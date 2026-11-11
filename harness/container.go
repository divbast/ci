// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// Confinement is how tightly a container runs. The zero Confinement is
// none at all: the engine's defaults.
type Confinement struct {
	// User is --user, as uid:gid. Empty leaves the image's own.
	User string
	// TmpfsSize sizes a tmpfs at /tmp, as --tmpfs /tmp:size=<TmpfsSize>.
	// Empty mounts none.
	TmpfsSize string
	// ReadOnly is --read-only, and CapDropAll is --cap-drop ALL.
	ReadOnly, CapDropAll bool
}

// Contract returns the confinement every divbast image's contract claims
// it runs under: uid and gid 65532, a read-only root, no capabilities, and
// a tmpfs at /tmp of tmpfsSize, which is the only writable place it has.
func Contract(tmpfsSize string) Confinement {
	return Confinement{User: "65532:65532", TmpfsSize: tmpfsSize, ReadOnly: true, CapDropAll: true}
}

// flags returns c as run flags, always in the same order.
func (c Confinement) flags() []string {
	var f []string
	if c.CapDropAll {
		f = append(f, "--cap-drop", "ALL")
	}
	if c.ReadOnly {
		f = append(f, "--read-only")
	}
	if c.User != "" {
		f = append(f, "--user", c.User)
	}
	if c.TmpfsSize != "" {
		f = append(f, "--tmpfs", "/tmp:size="+c.TmpfsSize)
	}
	return f
}

// Mount is one -v, as a user would write it.
type Mount struct {
	// Source is a volume's name when Volume is set, and otherwise a host
	// directory's absolute path. Target is the absolute path inside.
	Source, Target   string
	Volume, ReadOnly bool
}

// RunSpec is one container to run: the image and every flag it runs with.
type RunSpec struct {
	Image string
	// Name is the container's name. [Engine.Start] gives it a unique one
	// when it is empty.
	Name string
	// Network is a network's name, as [Engine.Network] returns it, and IP a
	// fixed address on it. Empty leaves the engine's default for each.
	Network, IP string
	Confine     Confinement
	// Env is set with -e, which carries only UTF-8: Docker sends it as
	// JSON, and puts U+FFFD in place of any other byte.
	Env    map[string]string
	Mounts []Mount
	// Publish holds -p values, such as 127.0.0.1:18080:8080.
	Publish []string
	// HealthCmd is the exec-form health command a Podman user passes as
	// --health-cmd, since Podman never reads a HEALTHCHECK from an image
	// published as an OCI index. It goes to Podman only: Docker runs the
	// image's own HEALTHCHECK, which is what is under test there.
	HealthCmd []string
	// Entrypoint replaces the image's, and Args its command.
	Entrypoint, Args []string
	// Extra holds raw flags, placed just before the image, for a negative
	// test to loosen what the fields above set.
	Extra []string
}

// validate refuses a spec the engine would read differently from what it
// says.
func (s *RunSpec) validate() error {
	if s.Image == "" {
		return errors.New("the run spec names no image")
	}
	for _, m := range s.Mounts {
		v := m.Source + ":" + m.Target
		switch {
		case strings.Contains(m.Source, ":") || strings.Contains(m.Target, ":"):
			return fmt.Errorf("mount %s: -v cannot carry a colon inside either path", v)
		case !path.IsAbs(m.Target):
			return fmt.Errorf("mount %s: the target inside the container must be an absolute path", v)
		case m.Volume && (m.Source == "" || strings.Contains(m.Source, "/")):
			return fmt.Errorf("mount %s: a volume is named, and -v would bind a directory at a path", v)
		case !m.Volume && !filepath.IsAbs(m.Source):
			return fmt.Errorf("mount %s: a host directory needs an absolute path, or -v makes a volume of that name", v)
		}
	}
	return nil
}

// Argv returns the arguments [Engine.Start] gives the engine for spec,
// from "run" on, so a test can assert the exact flags a container gets.
func (e Engine) Argv(spec *RunSpec) []string {
	argv := []string{"run", "-d", "--label", e.label}
	if spec.Name != "" {
		argv = append(argv, "--name", spec.Name)
	}
	argv = append(argv, spec.Confine.flags()...)
	if spec.Network != "" {
		argv = append(argv, "--network", spec.Network)
	}
	if spec.IP != "" {
		argv = append(argv, "--ip", spec.IP)
	}
	for _, k := range slices.Sorted(maps.Keys(spec.Env)) {
		argv = append(argv, "-e", k+"="+spec.Env[k])
	}
	for _, m := range spec.Mounts {
		v := m.Source + ":" + m.Target
		if m.ReadOnly {
			v += ":ro"
		}
		argv = append(argv, "-v", v)
	}
	for _, p := range spec.Publish {
		argv = append(argv, "-p", p)
	}
	// No leading "CMD": before 5.8.0, Podman re-splits an array that starts
	// with it on white space, and never runs the probe at all.
	if e.name == "podman" && len(spec.HealthCmd) > 0 {
		argv = append(argv, "--health-cmd", jsonArray(spec.HealthCmd))
	}
	// Docker's --entrypoint takes a single word. The rest of an exec-form
	// entrypoint goes first among the arguments, where the engine would
	// have put it.
	args := spec.Args
	if len(spec.Entrypoint) > 0 {
		argv = append(argv, "--entrypoint", spec.Entrypoint[0])
		args = slices.Concat(spec.Entrypoint[1:], spec.Args)
	}
	argv = append(argv, spec.Extra...)
	argv = append(argv, spec.Image)
	return append(argv, args...)
}

// jsonArray returns words as a JSON array.
func jsonArray(words []string) string {
	b, err := json.Marshal(words)
	if err != nil {
		// Unreachable: JSON holds any list of strings.
		panic(err)
	}
	return string(b)
}

// ErrNeverStarted means a container's process never ran: the engine
// refused to run it, or its entrypoint could not be executed, as a binary
// carrying a file capability cannot be under --cap-drop ALL. It is what
// tells a container that never started from one that started and exited.
var ErrNeverStarted = errors.New("never started")

// Start runs spec detached, labelled, and has tb's cleanup remove the
// container, dumping its log first if tb failed. It returns once the
// engine has started the process, not once the server in it is serving.
//
// A run the engine refuses, or whose process cannot start, is an error
// wrapping [ErrNeverStarted], with the engine's own words.
func (e Engine) Start(ctx context.Context, tb testing.TB, spec *RunSpec) (*Container, error) {
	tb.Helper()
	s := *spec
	if s.Name == "" {
		s.Name = uniqueName()
	}
	if err := s.validate(); err != nil {
		return nil, err
	}

	c := &Container{Name: s.Name, engine: e, network: s.Network}
	// Registered before the run: a container can be created and then fail
	// to start, and it is removed all the same.
	tb.Cleanup(func() {
		rmCtx, cancel := cleanupContext(ctx)
		defer cancel()
		if tb.Failed() && c.ID != "" {
			if logs, err := c.Logs(rmCtx); err != nil {
				tb.Logf("the log of container %s: %v", c, err)
			} else {
				tb.Logf("the log of container %s, running %s:\n%s", c, s.Image, logs)
			}
		}
		e.remove(rmCtx, tb, "rm", "-f", "-v", s.Name)
	})

	res, err := e.run.RunStdin(ctx, nil, e.name, e.Argv(&s)...)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("container %s %w: %s run: exit status %d: %s", s.Name, ErrNeverStarted, e.name, res.Code, bytes.TrimSpace(res.Stderr))
	}
	// The ID is the last thing printed; Podman may print a pull first.
	fields := strings.Fields(string(res.Stdout))
	if len(fields) == 0 {
		return nil, fmt.Errorf("container %s: %s run printed no container ID", s.Name, e.name)
	}
	c.ID = fields[len(fields)-1]
	c.started = time.Now()
	return c, nil
}

// Result is what a command left behind: its stdout, stderr and exit
// status. A command that ran and exited non-zero is a Result, not an
// error.
type Result = execx.Result

// Container is a container [Engine.Start] started.
type Container struct {
	ID, Name string

	engine  Engine
	network string
	started time.Time
}

// String returns the container's name, or its ID if it has none.
func (c *Container) String() string { return cmp.Or(c.Name, c.ID) }

// Exec runs argv in the container, as the container's own user, feeding it
// stdin when that is not nil. A non-zero exit status is in the Result;
// the error is for an exec the engine could not run at all.
func (c *Container) Exec(ctx context.Context, stdin io.Reader, argv ...string) (Result, error) {
	args := []string{"exec"}
	if stdin != nil {
		args = append(args, "-i")
	}
	args = append(args, c.ID)
	return c.engine.run.RunStdin(ctx, stdin, c.engine.name, append(args, argv...)...)
}

// Logs returns what the container has written: its stdout, then its
// stderr. The engine hands the two over separately, so how their lines
// interleaved is lost.
func (c *Container) Logs(ctx context.Context) (string, error) {
	res, err := c.engine.run.RunStdin(ctx, nil, c.engine.name, "logs", c.ID)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("%s logs %s: exit status %d: %s", c.engine.name, c, res.Code, bytes.TrimSpace(res.Stderr))
	}
	return string(res.Stdout) + string(res.Stderr), nil
}

// Inspect is the part of what the engine reports about a container that
// checks read.
type Inspect struct {
	State  State
	Config Config
	// IP is the container's address on the network it was started on, or
	// on its one network if it named none. Empty when it has none, as on
	// rootless Podman's default network.
	IP string
}

// State is the container's process, as the engine last saw it.
type State struct {
	// Status is the engine's word for it: created, running, exited.
	Status   string
	Running  bool
	ExitCode int
	// Error is why the engine could not start the process, if it could not.
	Error string
	// StartedAt is zero for a process that never started.
	StartedAt time.Time
	// Health is nil when the container has no health check.
	Health *Health
}

// Health is the engine's view of a container's health check.
type Health struct {
	// Status is starting, healthy or unhealthy.
	Status        string
	FailingStreak int
	Log           []HealthLog
}

// HealthLog is one run of the health check. Start and End are kept as the
// engine wrote them.
type HealthLog struct {
	Start, End string
	ExitCode   int
	Output     string
}

// Config is the configuration the container runs with.
type Config struct {
	// User is the uid:gid it runs as: --user, or else the image's own.
	User string
	// Healthcheck is the health check the engine runs, nil for none.
	Healthcheck *Healthcheck
}

// Healthcheck is a health check's command and timings.
type Healthcheck struct {
	// Test is the command, starting "CMD" for the exec form and
	// "CMD-SHELL" for one run through /bin/sh.
	Test                           []string
	Interval, Timeout, StartPeriod time.Duration
	Retries                        int
}

// Inspect returns what the engine reports about the container now.
func (c *Container) Inspect(ctx context.Context) (Inspect, error) {
	out, err := c.engine.output(ctx, "container", "inspect", c.ID)
	if err != nil {
		return Inspect{}, err
	}
	var all []struct {
		State struct {
			State
			// Podman's name for Health before it took Docker's.
			Healthcheck *Health
		}
		Config          Config
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if err := json.Unmarshal(out, &all); err != nil {
		return Inspect{}, fmt.Errorf("%s container inspect %s printed what is not an inspection: %w", c.engine.name, c, err)
	}
	if len(all) != 1 {
		return Inspect{}, fmt.Errorf("%s container inspect %s described %d containers, want 1", c.engine.name, c, len(all))
	}
	got := all[0]

	ins := Inspect{State: got.State.State, Config: got.Config}
	if ins.State.Health == nil {
		ins.State.Health = got.State.Healthcheck
	}
	if ins.State.Health != nil && ins.State.Health.Status == "" {
		ins.State.Health = nil
	}
	if n, ok := got.NetworkSettings.Networks[c.network]; ok {
		ins.IP = n.IPAddress
	} else if c.network == "" && len(got.NetworkSettings.Networks) == 1 {
		for _, n := range got.NetworkSettings.Networks {
			ins.IP = n.IPAddress
		}
	}
	return ins, nil
}

// pollInterval is how often WaitExit and EngineHealthy ask again.
const pollInterval = 500 * time.Millisecond

// WaitExit waits up to within for the container to stop, and returns its
// exit status. A container still running then is an error, as is one
// whose process never started, which wraps [ErrNeverStarted]: a refusal to
// start is an exit status, and a container that could not even try is not.
// The status is -1 with any error.
func (c *Container) WaitExit(ctx context.Context, within time.Duration) (int, error) {
	deadline := time.Now().Add(within)
	for {
		ins, err := c.Inspect(ctx)
		if err != nil {
			return -1, err
		}
		if !ins.State.Running {
			if ins.State.StartedAt.IsZero() {
				return -1, fmt.Errorf("container %s %w (%s, exit status %d): %s",
					c, ErrNeverStarted, ins.State.Status, ins.State.ExitCode, ins.State.Error)
			}
			return ins.State.ExitCode, nil
		}
		if !time.Now().Before(deadline) {
			return -1, fmt.Errorf("container %s is still running after %s", c, within)
		}
		if err := sleep(ctx, pollInterval); err != nil {
			return -1, err
		}
	}
}

// EngineHealthy returns nil once the engine's own health machinery says
// the container is healthy, which is what proves an exec-form health check
// runs in an image with no shell: a shell-form one fails every time.
//
// Podman is asked to run its check once, with podman healthcheck run, so
// the container must already be serving. Docker is watched until its
// health check settles, for up to startPeriod from when the container
// started: pass the image's own start period. Anything but healthy is an
// error, with Docker's log of the checks it ran.
func (c *Container) EngineHealthy(ctx context.Context, startPeriod time.Duration) error {
	if c.engine.name == "podman" {
		res, err := c.engine.run.RunStdin(ctx, nil, c.engine.name, "healthcheck", "run", c.ID)
		if err != nil {
			return err
		}
		if res.Code != 0 {
			return fmt.Errorf("podman healthcheck run %s: exit status %d: %s", c, res.Code, bytes.TrimSpace(append(res.Stdout, res.Stderr...)))
		}
		return nil
	}

	deadline := c.started.Add(startPeriod)
	for {
		ins, err := c.Inspect(ctx)
		if err != nil {
			return err
		}
		h := ins.State.Health
		switch {
		case h == nil:
			return fmt.Errorf("%s reports no health check for container %s: its image declares no HEALTHCHECK, or it was turned off", c.engine.name, c)
		case h.Status == "healthy":
			return nil
		case h.Status == "unhealthy":
			return fmt.Errorf("%s reports container %s unhealthy%s", c.engine.name, c, h.logText())
		case !time.Now().Before(deadline):
			return fmt.Errorf("container %s is still %s after the %s start period%s", c, h.Status, startPeriod, h.logText())
		}
		if err := sleep(ctx, pollInterval); err != nil {
			return err
		}
	}
}

// logText returns the health checks' log, one run to a line, for an error.
func (h *Health) logText() string {
	if len(h.Log) == 0 {
		return "; no check has run"
	}
	var b strings.Builder
	b.WriteString("; its checks:")
	for _, l := range h.Log {
		fmt.Fprintf(&b, "\n  exit %d: %s", l.ExitCode, strings.TrimSpace(l.Output))
	}
	return b.String()
}

// sleep waits for d, or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
