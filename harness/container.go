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
	"net"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// Confinement is how tightly a container runs. [Engine.Start] and
// [Engine.Run] refuse the zero Confinement, which would leave the engine's
// defaults in place, so that a spec which forgot to set one cannot run as
// root, on a writable root, with the default capabilities, and pass every
// check for the wrong reason. [Contract] is the confinement divbast's
// images claim, and [Unconfined] is none, asked for on purpose.
type Confinement struct {
	// User is --user, as uid:gid. Empty leaves the image's own.
	User string
	// TmpfsSize sizes a tmpfs at /tmp, as --tmpfs /tmp:size=<TmpfsSize>.
	// Empty mounts none.
	TmpfsSize string
	// ReadOnly is --read-only, and CapDropAll is --cap-drop ALL.
	ReadOnly, CapDropAll bool

	// none marks what Unconfined returns: no confinement on purpose, which
	// the zero Confinement is only by omission.
	none bool
}

// Contract returns the confinement every divbast image's contract claims
// it runs under: uid and gid 65532, a read-only root, no capabilities, and
// a tmpfs at /tmp of tmpfsSize, which is the only writable place it has.
func Contract(tmpfsSize string) Confinement {
	return Confinement{User: "65532:65532", TmpfsSize: tmpfsSize, ReadOnly: true, CapDropAll: true}
}

// Unconfined returns the Confinement that adds no flag at all, and leaves
// the engine's defaults: what the zero Confinement would, which Start and
// Run refuse, since a spec holding it may only have forgotten to set one.
func Unconfined() Confinement {
	return Confinement{none: true}
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
// says, and one that sets no confinement at all.
func (s *RunSpec) validate() error {
	if s.Image == "" {
		return errors.New("the run spec names no image")
	}
	if s.Confine == (Confinement{}) {
		return errors.New("the run spec sets no Confine, and would run under the engine's defaults: " +
			"give it harness.Contract's confinement, or harness.Unconfined() to run with none on purpose")
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
// [Engine.Run] gives the same, with --rm in place of -d.
func (e Engine) Argv(spec *RunSpec) []string {
	return e.argv(spec, "-d")
}

// argv is [Engine.Argv] with mode, -d or --rm, after "run".
func (e Engine) argv(spec *RunSpec, mode string) []string {
	argv := []string{"run", mode, "--label", e.label}
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

// ErrNeverStarted means a container's process never ran: the engine made
// the container and could not start it, as when its entrypoint could not
// be executed, as a binary carrying a file capability cannot be under
// --cap-drop ALL. It is what tells a container that never started from one
// that started and exited. A run the engine refused before it made a
// container at all is [ErrRefused] instead.
var ErrNeverStarted = errors.New("never started")

// ErrRefused means the engine refused a run before it made a container: a
// flag it does not take, an image it could not pull, or a name another
// container already has. The error carries the engine's own words, which
// say which.
var ErrRefused = errors.New("refused by the engine")

// Start runs spec detached, labelled, and has tb's cleanup remove the
// container, dumping its log first if tb failed. It returns once the
// engine has started the process, not once the server in it is serving.
//
// A run the engine refuses outright is an error wrapping [ErrRefused], and
// one whose container it made but could not start an error wrapping
// [ErrNeverStarted], each with the engine's own words.
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
	// to start, and it is removed all the same. One whose name was already
	// another container's made nothing, and that other is not its to remove.
	othersName := false
	tb.Cleanup(func() {
		if othersName {
			return
		}
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
		othersName = nameInUse(res.Stderr, s.Name)
		return nil, e.notStarted(ctx, s.Name, res)
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

// notStarted returns why the run of container name, which exited as res
// says, started nothing: [ErrNeverStarted] when the engine made the
// container, and [ErrRefused] when it made none. The engine is asked
// which, since Podman, unlike Docker, prints nothing of a container it
// made and could not start. A name in use is the one refusal settled by
// the engine's words alone, since a container of that name, another's,
// does exist.
func (e Engine) notStarted(ctx context.Context, name string, res Result) error {
	words := fmt.Sprintf("%s run: exit status %d: %s", e.name, res.Code, bytes.TrimSpace(res.Stderr))
	if nameInUse(res.Stderr, name) {
		return fmt.Errorf("container %s was %w: another container has its name: %s", name, ErrRefused, words)
	}
	made, err := e.made(ctx, name)
	switch {
	case err != nil:
		return fmt.Errorf("container %s: %s; and whether the engine made it is unknown: %w", name, words, err)
	case made:
		return fmt.Errorf("container %s %w: %s", name, ErrNeverStarted, words)
	default:
		return fmt.Errorf("container %s was %w: %s", name, ErrRefused, words)
	}
}

// nameInUse reports whether a run's stderr says another container already
// has the name the run asked for. Docker names the container with a
// leading slash, and Podman without.
func nameInUse(stderr []byte, name string) bool {
	return bytes.Contains(stderr, []byte(`name "/`+name+`" is already in use`)) ||
		bytes.Contains(stderr, []byte(`name "`+name+`" is already in use`))
}

// made reports whether the engine holds a container called name.
func (e Engine) made(ctx context.Context, name string) (bool, error) {
	args := []string{"container", "inspect", "--format", "{{.Id}}", name}
	res, err := e.run.RunStdin(ctx, nil, e.name, args...)
	switch {
	case err != nil:
		return false, err
	case res.Code == 0:
		return true, nil
	case gone(res.Stderr):
		return false, nil
	default:
		return false, fmt.Errorf("%s %s: exit status %d: %s", e.name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
	}
}

// Run runs spec in the foreground, as run --rm, and returns what it
// printed and its exit status once it exits. Some failures reach nothing
// but the foreground's stderr: crun reports an exec the kernel refused
// there, and leaves the log of a detached container empty.
//
// A status of the engine's own, 125 and up, is in the Result too, as is a
// run the engine refused: the error is for an engine that could not be run
// at all, or a spec it would misread.
func (e Engine) Run(ctx context.Context, tb testing.TB, spec *RunSpec) (Result, error) {
	tb.Helper()
	s := *spec
	if s.Name == "" {
		s.Name = uniqueName()
	}
	if err := s.validate(); err != nil {
		return Result{}, err
	}
	// --rm removes it once it exits. This removes one a cancelled run
	// left behind, unless the name was already another container's: the
	// engine then made nothing, and that other is not this run's to
	// remove, as Start leaves it too.
	othersName := false
	tb.Cleanup(func() {
		if othersName {
			return
		}
		rmCtx, cancel := cleanupContext(ctx)
		defer cancel()
		e.remove(rmCtx, tb, "rm", "-f", "-v", s.Name)
	})
	res, err := e.run.RunStdin(ctx, nil, e.name, e.argv(&s, "--rm")...)
	if err == nil && res.Code != 0 {
		othersName = nameInUse(res.Stderr, s.Name)
	}
	return res, err
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
//
// An exec the engine failed, rather than the command it ran, is run
// again, up to three times in all, a second apart, for as long as ctx
// allows: an engine can refuse an exec into a container that is starting
// or has just restarted, and its runtime can fail one into a container
// that runs. Exec tells the two apart by exit status alone. Any exit of
// 125 to 128 is taken for the engine's, as is Podman's 255 with stderr
// opening "Error: OCI runtime error:", so a command that itself exits 125
// to 128 is run again too, side effects and all: a command run through
// Exec should not exit that way. Each attempt is fed the whole of stdin,
// which Exec reads to its end before the first. When the third attempt
// fails in the engine too, the error names it, with the engine's words,
// and the Result is the third's. A command the runtime could not execute
// or find, exit status 126 or 127, is the one exception: it stays a
// Result, since a check that an image has no /bin/sh asserts exactly
// that. Any other non-zero exit, a PHP fatal error's 255 among them, is
// the command's own, and is never run again.
func (c *Container) Exec(ctx context.Context, stdin io.Reader, argv ...string) (Result, error) {
	args := []string{"exec"}
	var in []byte
	if stdin != nil {
		args = append(args, "-i")
		var err error
		if in, err = io.ReadAll(stdin); err != nil {
			return Result{}, fmt.Errorf("reading what to feed an exec in container %s: %w", c, err)
		}
	}
	args = slices.Concat(args, []string{c.ID}, argv)
	for attempt := 1; ; attempt++ {
		var fed io.Reader
		if stdin != nil {
			fed = bytes.NewReader(in)
		}
		res, err := c.engine.run.RunStdin(ctx, fed, c.engine.name, args...)
		if err != nil || !engineFailed(res) {
			return res, err
		}
		if attempt == execAttempts {
			if res.Code == 126 || res.Code == 127 {
				return res, nil
			}
			return res, fmt.Errorf("%s exec in container %s: attempt %d of %d failed in the engine, as each before it did: exit status %d: %s",
				c.engine.name, c, attempt, execAttempts, res.Code, combined(res))
		}
		if err := Pause(ctx, execRetry); err != nil {
			return res, fmt.Errorf("%s exec in container %s: waiting to try again after attempt %d failed in the engine, exit status %d: %s: %w",
				c.engine.name, c, attempt, res.Code, combined(res), err)
		}
	}
}

// An engine can refuse an exec while a container is starting: Docker once
// answered "cannot exec in a stopped container" here, with exit status
// 128, to one whose server was still coming up. So [Container.Exec] runs
// an exec the engine itself failed again, up to execAttempts times in
// all, execRetry apart.
const (
	execAttempts = 3
	execRetry    = time.Second
)

// engineFailed reports whether an exec that exited as res did failed in
// the engine rather than in the command it ran: 125 for the engine, 126
// and 127 for a command it could not run, and 128 where Docker's runtime
// refused. Podman also exits 255 when its runtime fails the exec, as crun
// once did with "setns `mnt`: Bad file descriptor" into a running
// container, and then opens stderr with podmanRuntimeError, which no PHP
// prints. Any other exit is the command's own, as PHP exits 255 for a
// fatal error, and would only do the same again.
func engineFailed(res Result) bool {
	return res.Code >= 125 && res.Code <= 128 ||
		res.Code == 255 && bytes.HasPrefix(res.Stderr, []byte(podmanRuntimeError))
}

// podmanRuntimeError opens what Podman prints when its OCI runtime fails.
const podmanRuntimeError = "Error: OCI runtime error:"

// Restart restarts the container in place, as <engine> restart does: the
// engine stops its process, as a stop would, and starts it again in the
// same container, with the same ID, name, run flags and volumes. It
// returns once the engine reports that container running again, not once
// the server in it is serving. [Container.EngineHealthy] counts its wait
// from the restart.
//
// What a restart keeps, as measured on Docker 29 and Podman 5.7, and as
// ci's TestRestartSameContainer asserts on each:
//
//   - A volume keeps what was written to it.
//   - The tmpfs at /tmp is a new, empty one on both engines. A probe
//     [InstallProbe] put there is gone: install it again.
//   - A host port the engine picked, as -p 127.0.0.1::8080 asks it to, is
//     picked again by Docker, which binds another port, and kept by
//     Podman, which picked it once, when it made the container. Read
//     [Container.Inspect] again for where a published port is now.
func (c *Container) Restart(ctx context.Context) error {
	if _, err := c.engine.output(ctx, "restart", c.String()); err != nil {
		return err
	}
	c.started = time.Now()
	ins, err := c.Inspect(ctx)
	if err != nil {
		return err
	}
	if !ins.State.Running {
		return fmt.Errorf("container %s is %s after %s restart, exit status %d, not running: %s",
			c, ins.State.Status, c.engine.name, ins.State.ExitCode, ins.State.Error)
	}
	return nil
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
	State      State
	Config     Config
	HostConfig HostConfig
	// Mounts holds the volumes and binds the engine mounted in the
	// container: a --tmpfs is in HostConfig.Tmpfs instead, on both
	// engines. Docker lists a --mount of type tmpfs here too.
	Mounts []MountPoint
	// HostConfigJSON is HostConfig as the engine printed it, for a check
	// that must tell a field the engine left out from one it printed with
	// its zero value, which HostConfig reads alike.
	HostConfigJSON json.RawMessage
	// IP is the container's address on the network it was started on, or
	// on its one network if it named none. Empty when it has none, as on
	// rootless Podman's default network.
	IP string
	// Ports holds where each port the run published is bound on the host,
	// as ip:port, keyed by the container's port as the engine names it,
	// such as 8080/tcp: how a suite that let the engine pick the host port,
	// with -p 127.0.0.1::8080, finds it. A port bound on several addresses
	// is given at the first the engine lists. A port published on every
	// address, as -p 8080 publishes it, is 0.0.0.0:<port> on both engines:
	// Docker lists 0.0.0.0 first and then ::, Podman from 5.0 on writes
	// 0.0.0.0, and Podman before 5.0 an empty address, read as 0.0.0.0. A
	// port the image exposes and the run did not publish is not in it.
	Ports map[string]string
}

// MountPoint is one mount in a container, as the engine reports it.
type MountPoint struct {
	// Type is volume or bind on both engines, tmpfs for Docker's --mount
	// type=tmpfs, and image for Podman's --mount type=image.
	Type string
	// Name is a volume's: the name it was given, or for one the engine
	// made itself, as for an image's VOLUME, one it chose.
	Name string
	// Source is where it comes from on the host, and Destination where it
	// is in the container.
	Source, Destination string
	// RW is whether the container may write to it.
	RW bool
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

// Config is the configuration a container runs with, or the one an image
// declares, as [Engine.ImageConfig] reads it.
type Config struct {
	// User is the uid:gid it runs as: --user, or else the image's own.
	User string
	// Healthcheck is the health check the engine runs, or the image's
	// HEALTHCHECK, nil for none.
	Healthcheck *Healthcheck
	// Volumes holds the image's VOLUME paths, as keys, each with an empty
	// value, as both engines write it. Nil for none.
	Volumes map[string]struct{}
}

// Healthcheck is a health check's command and timings. A timing left
// unset is zero, and the engine's default applies.
type Healthcheck struct {
	// Test is the command, starting "CMD" for the exec form and
	// "CMD-SHELL" for one run through /bin/sh.
	Test                                          []string
	Interval, Timeout, StartPeriod, StartInterval time.Duration
	Retries                                       int
}

// HostConfig is how the engine set a container up, which a probe inside
// it cannot see. Docker and Podman print the same field names here, with
// values of their own, given with each field.
type HostConfig struct {
	// CapAdd is what --cap-add granted: null on Docker when nothing was,
	// an empty list on Podman. Both name a capability CAP_<NAME>.
	CapAdd []string
	// Privileged is --privileged, and ReadonlyRootfs --read-only.
	Privileged, ReadonlyRootfs bool
	// SecurityOpt holds the --security-opt values. Docker keeps each as it
	// was given, with = or : between key and value, and null for none.
	// Podman rebuilds them, always with =, from what it records of the
	// options given, and adds unmask=all when no path is masked.
	SecurityOpt []string
	// Init is whether the engine put an init in front of the entrypoint:
	// null on Docker unless --init was given, a bool on Podman.
	Init *bool
	// NetworkMode is the network the container joined. Docker names it;
	// Podman says bridge for any named network, or slirp4netns or pasta
	// for its rootless default. Both say none, host for the host's, and
	// container:<id> for another container's; Podman alone says
	// ns:<path> for a namespace joined by its path.
	NetworkMode string
	// Tmpfs holds each --tmpfs: its path in the container, and its
	// options, which each engine writes its own way. Docker leaves the
	// field out when there is none. Podman lists only those the run asked
	// for, and not the ones --read-only adds itself.
	Tmpfs map[string]string
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
		HostConfig      json.RawMessage
		Mounts          []MountPoint
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
			// null for a port exposed and not published
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string
			}
		}
	}
	if err := json.Unmarshal(out, &all); err != nil {
		return Inspect{}, fmt.Errorf("%s container inspect %s printed what is not an inspection: %w", c.engine.name, c, err)
	}
	if len(all) != 1 {
		return Inspect{}, fmt.Errorf("%s container inspect %s described %d containers, want 1", c.engine.name, c, len(all))
	}
	got := all[0]

	ins := Inspect{State: got.State.State, Config: got.Config, Mounts: got.Mounts, HostConfigJSON: got.HostConfig}
	if len(got.HostConfig) > 0 {
		if err := json.Unmarshal(got.HostConfig, &ins.HostConfig); err != nil {
			return Inspect{}, fmt.Errorf("%s container inspect %s printed a HostConfig that is not one: %w", c.engine.name, c, err)
		}
	}
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
	ins.Ports = make(map[string]string, len(got.NetworkSettings.Ports))
	for port, bindings := range got.NetworkSettings.Ports {
		if len(bindings) > 0 {
			ins.Ports[port] = net.JoinHostPort(cmp.Or(bindings[0].HostIP, "0.0.0.0"), bindings[0].HostPort)
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
		if err := Pause(ctx, pollInterval); err != nil {
			return -1, err
		}
	}
}

// EngineHealthy returns nil once the engine's own health machinery says
// the container is healthy, which is what proves an exec-form health check
// runs in an image with no shell: a shell-form one fails every time.
//
// It only watches: the engine runs the check on its own schedule, as it
// would for a user. Docker runs the image's HEALTHCHECK. Podman runs the
// --health-cmd it was given, as [RunSpec.HealthCmd] gives it, from the
// transient systemd timer it sets up for the container, which needs a
// systemd user session: without one, Podman schedules nothing. The wait
// lasts startPeriod from when the container started, or was last
// restarted, and then three of the intervals the engine runs the check
// at, as it reports them, or 30 s, both engines' default: pass the
// image's own start period. A check that kept failing past the start
// period has by then failed as often as either engine's default retries,
// so the engine has called the container unhealthy, which is an error at
// once, as is a container that stopped. Every error but the engine's own
// carries the engine's log of the checks it ran.
func (c *Container) EngineHealthy(ctx context.Context, startPeriod time.Duration) error {
	var interval time.Duration
	for {
		ins, err := c.Inspect(ctx)
		if err != nil {
			return err
		}
		if interval == 0 {
			interval = defaultHealthInterval
			if hc := ins.Config.Healthcheck; hc != nil && hc.Interval > 0 {
				interval = hc.Interval
			}
		}
		h := ins.State.Health
		switch {
		case h == nil:
			return fmt.Errorf("%s reports no health check for container %s: %s", c.engine.name, c, c.noHealthCheck())
		case h.Status == "healthy":
			return nil
		case h.Status == "unhealthy":
			return fmt.Errorf("%s reports container %s unhealthy%s", c.engine.name, c, h.logText())
		case !ins.State.Running:
			return fmt.Errorf("container %s %s, exit status %d, before %s reported it healthy%s",
				c, ins.State.Status, ins.State.ExitCode, c.engine.name, h.logText())
		case !time.Now().Before(c.started.Add(startPeriod + healthIntervals*interval)):
			return fmt.Errorf("%s reports container %s still %s %s after it started: its start period of %s and three intervals of %s%s",
				c.engine.name, c, h.Status, time.Since(c.started).Round(time.Second), startPeriod, interval, h.logText())
		}
		if err := Pause(ctx, pollInterval); err != nil {
			return err
		}
	}
}

// EngineHealthy waits for the start period it is given and then
// healthIntervals of the engine's interval, or of defaultHealthInterval
// when the engine reports none.
const (
	healthIntervals       = 3
	defaultHealthInterval = 30 * time.Second
)

// noHealthCheck says why the engine may report no health check for c.
func (c *Container) noHealthCheck() string {
	if c.engine.name == "podman" {
		return "it was started with no --health-cmd, which Podman needs for an image published as an OCI index, " +
			"or Podman had no systemd user session to run its timer in"
	}
	return "its image declares no HEALTHCHECK, or it was turned off"
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
