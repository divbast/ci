// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// contractFlags is what every container run under the contract carries, in
// this order, and exactly once.
var contractFlags = []string{"--cap-drop", "ALL", "--read-only", "--user", "65532:65532", "--tmpfs", "/tmp:size=16m"}

// healthProbe is an exec-form health command, as both apps' images declare
// theirs.
var healthProbe = []string{"/usr/local/bin/frankenphp", "php-cli", "/x"}

// count returns how many times sub appears in s as a contiguous run.
func count(s, sub []string) int {
	n := 0
	for i := range s {
		if i+len(sub) <= len(s) && slices.Equal(s[i:i+len(sub)], sub) {
			n++
		}
	}
	return n
}

func TestEngineFromEnv(t *testing.T) {
	tests := []struct {
		env     string
		want    string
		wantErr bool
	}{
		{env: "", want: "docker"},
		{env: "docker", want: "docker"},
		{env: "podman", want: "podman"},
		{env: "nerdctl", wantErr: true},
	}

	for _, tt := range tests {
		t.Run("ENGINE="+tt.env, func(t *testing.T) {
			t.Setenv("ENGINE", tt.env)

			e, err := EngineFromEnv()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("EngineFromEnv() = %q, nil; want an error", e.Name())
				}
				return
			}
			if err != nil {
				t.Fatalf("EngineFromEnv() error = %v", err)
			}
			if e.Name() != tt.want {
				t.Errorf("EngineFromEnv().Name() = %q, want %q", e.Name(), tt.want)
			}
		})
	}
}

func TestArgvContract(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"docker", "podman"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEngine(name, nil)
			got := e.Argv(&RunSpec{Image: "img", Confine: Contract("16m")})
			if n := count(got, contractFlags); n != 1 {
				t.Errorf("Argv(Contract(16m)) = %q\nholds %q %d times, want exactly once", got, contractFlags, n)
			}

			// A spec that asks for no confinement gets none of it.
			loose := e.Argv(&RunSpec{Image: "img"})
			for _, flag := range []string{"--cap-drop", "--read-only", "--user", "--tmpfs"} {
				if slices.Contains(loose, flag) {
					t.Errorf("Argv(no confinement) = %q, holds %s", loose, flag)
				}
			}
		})
	}
}

func TestArgvPodmanHealthCmd(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{Image: "img", HealthCmd: healthProbe}

	podman := newEngine("podman", nil).Argv(spec)
	want := []string{"--health-cmd", `["/usr/local/bin/frankenphp","php-cli","/x"]`}
	if count(podman, want) != 1 {
		t.Errorf("podman Argv = %q, want it to hold %q once", podman, want)
	}
	if slices.ContainsFunc(podman, func(a string) bool { return strings.Contains(a, `"CMD"`) }) {
		t.Errorf("podman Argv = %q holds \"CMD\", which Podman before 5.8.0 re-splits on white space", podman)
	}

	// Docker runs the image's own HEALTHCHECK, which is what is under test.
	if docker := newEngine("docker", nil).Argv(spec); slices.Contains(docker, "--health-cmd") {
		t.Errorf("docker Argv = %q, holds --health-cmd, which would stand in for the image's HEALTHCHECK", docker)
	}
}

func TestArgv(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{
		Image:   "img",
		Name:    "ctr",
		Network: "net",
		IP:      "10.89.66.200",
		Confine: Contract("16m"),
		Env:     map[string]string{"B": "2", "A": "1 2"},
		Mounts: []Mount{
			{Source: "vol", Target: "/data", Volume: true},
			{Source: "/host/dir", Target: "/x", ReadOnly: true},
		},
		Publish:    []string{"18080:8080"},
		HealthCmd:  healthProbe,
		Entrypoint: []string{"/bin/e", "first"},
		Args:       []string{"a1"},
		Extra:      []string{"--init"},
	}
	head := []string{
		"run", "-d", "--label", "divbast.harness=1", "--name", "ctr",
		"--cap-drop", "ALL", "--read-only", "--user", "65532:65532", "--tmpfs", "/tmp:size=16m",
		"--network", "net", "--ip", "10.89.66.200",
		"-e", "A=1 2", "-e", "B=2",
		"-v", "vol:/data", "-v", "/host/dir:/x:ro",
		"-p", "18080:8080",
	}
	// Docker's --entrypoint takes one word, so the rest goes before Args.
	tail := []string{"--entrypoint", "/bin/e", "--init", "img", "first", "a1"}

	tests := []struct {
		engine string
		want   []string
	}{
		{engine: "docker", want: slices.Concat(head, tail)},
		{engine: "podman", want: slices.Concat(head, []string{"--health-cmd", `["/usr/local/bin/frankenphp","php-cli","/x"]`}, tail)},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			t.Parallel()

			if got := newEngine(tt.engine, nil).Argv(spec); !slices.Equal(got, tt.want) {
				t.Errorf("Argv() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestStart(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{Image: "img", Name: "ctr", Network: "net", Confine: Contract("16m")}
	e := newEngine("docker", nil)
	fake := execx.NewFake(t,
		execx.Call{Argv: slices.Concat([]string{"docker"}, e.Argv(spec)), Result: execx.Result{Stdout: []byte("abc123\n")}},
		execx.Call{Argv: []string{"docker", "rm", "-f", "-v", "ctr"}},
	)
	e.run = fake

	c, err := e.Start(t.Context(), t, spec)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if c.ID != "abc123" || c.Name != "ctr" {
		t.Errorf("Start() = ID %q, Name %q; want abc123, ctr", c.ID, c.Name)
	}
}

func TestStartNamesTheContainer(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{Image: "img"}
	var ran []string
	e := newEngine("docker", runFunc(func(argv []string) execx.Result {
		ran = append(ran, strings.Join(argv, " "))
		return execx.Result{Stdout: []byte("id\n")}
	}))

	c, err := e.Start(t.Context(), t, spec)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !strings.HasPrefix(c.Name, "divbast-") || len(c.Name) <= len("divbast-") {
		t.Errorf("Start() named the container %q, want divbast- and something unique", c.Name)
	}
	if spec.Name != "" {
		t.Errorf("Start() wrote the name %q into the caller's spec", spec.Name)
	}
	if len(ran) != 1 || !strings.Contains(ran[0], "--name "+c.Name+" ") {
		t.Errorf("ran %q, want one run with --name %s", ran, c.Name)
	}
}

func TestStartNeverStarted(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{Image: "img", Name: "ctr", Entrypoint: []string{"/nonexistent"}}
	e := newEngine("podman", nil)
	fake := execx.NewFake(t,
		execx.Call{Argv: slices.Concat([]string{"podman"}, e.Argv(spec)), Result: execx.Result{
			Code:   127,
			Stderr: []byte(`Error: crun: executable file "/nonexistent" not found in $PATH`),
		}},
		// The container may have been created before its process failed,
		// so it is removed all the same, and a missing one is no failure.
		execx.Call{Argv: []string{"podman", "rm", "-f", "-v", "ctr"}, Result: execx.Result{
			Code:   1,
			Stderr: []byte(`Error: no container with name or ID "ctr" found: no such container`),
		}},
	)
	e.run = fake

	_, err := e.Start(t.Context(), t, spec)
	if !errors.Is(err, ErrNeverStarted) {
		t.Fatalf("Start() error = %v, want ErrNeverStarted", err)
	}
	if !strings.Contains(err.Error(), "/nonexistent") {
		t.Errorf("Start() error = %q, want the engine's own words", err)
	}
}

func TestStartRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec RunSpec
	}{
		{name: "no-image", spec: RunSpec{}},
		{name: "volume-named-like-a-path", spec: RunSpec{Image: "img", Mounts: []Mount{{Source: "/srv", Target: "/data", Volume: true}}}},
		{name: "bind-not-absolute", spec: RunSpec{Image: "img", Mounts: []Mount{{Source: "data", Target: "/data"}}}},
		{name: "colon-in-source", spec: RunSpec{Image: "img", Mounts: []Mount{{Source: "a:b", Target: "/data", Volume: true}}}},
		{name: "target-not-absolute", spec: RunSpec{Image: "img", Mounts: []Mount{{Source: "vol", Target: "data", Volume: true}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A Fake with no calls: nothing may run.
			e := newEngine("docker", execx.NewFake(t))
			if _, err := e.Start(t.Context(), t, &tt.spec); err == nil {
				t.Errorf("Start(%+v) error = nil, want a refusal", tt.spec)
			}
		})
	}
}

func TestNetwork(t *testing.T) {
	t.Parallel()

	create := []string{"docker", "network", "create", "--label", "divbast.harness=1", "--subnet", "10.89.66.0/24", "--internal", "net"}
	inspect := []string{"docker", "network", "inspect", "--format", "{{.Internal}}", "net"}
	remove := []string{"docker", "network", "rm", "net"}

	tests := []struct {
		name    string
		calls   []execx.Call
		wantErr string
	}{
		{
			name: "created",
			calls: []execx.Call{
				{Argv: create, Result: execx.Result{Stdout: []byte("f00\n")}},
				{Argv: inspect, Result: execx.Result{Stdout: []byte("true\n")}},
				{Argv: remove},
			},
		},
		{
			name: "create-fails",
			calls: []execx.Call{
				{Argv: create, Result: execx.Result{Code: 1, Stderr: []byte("Error response from daemon: Pool overlaps with other one on this address space")}},
			},
			wantErr: "Pool overlaps",
		},
		{
			name: "not-internal-after-all",
			calls: []execx.Call{
				{Argv: create, Result: execx.Result{Stdout: []byte("f00\n")}},
				{Argv: inspect, Result: execx.Result{Stdout: []byte("false\n")}},
				{Argv: remove},
			},
			wantErr: "internal",
		},
		{
			name: "inspect-fails",
			calls: []execx.Call{
				{Argv: create, Result: execx.Result{Stdout: []byte("f00\n")}},
				{Argv: inspect, Result: execx.Result{Code: 1, Stderr: []byte("Error: network net not found")}},
				{Argv: remove},
			},
			wantErr: "not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newEngine("docker", execx.NewFake(t, tt.calls...))
			got, err := e.Network(t.Context(), t, "net", "10.89.66.0/24", true)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Network() = %q, %v; want an error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != "net" {
				t.Errorf("Network() = %q, %v; want net, nil", got, err)
			}
		})
	}
}

func TestVolume(t *testing.T) {
	t.Parallel()

	e := newEngine("podman", execx.NewFake(t,
		execx.Call{Argv: []string{"podman", "volume", "create", "--label", "divbast.harness=1", "vol"}, Result: execx.Result{Stdout: []byte("vol\n")}},
		execx.Call{Argv: []string{"podman", "volume", "rm", "vol"}},
	))
	if got, err := e.Volume(t.Context(), t, "vol"); err != nil || got != "vol" {
		t.Errorf("Volume() = %q, %v; want vol, nil", got, err)
	}
}

func TestSweepCommands(t *testing.T) {
	t.Parallel()

	filter := []string{"--filter", "label=divbast.harness=1"}
	ps := slices.Concat([]string{"docker", "ps", "-a", "-q"}, filter)
	nets := slices.Concat([]string{"docker", "network", "ls", "-q"}, filter)
	vols := slices.Concat([]string{"docker", "volume", "ls", "-q"}, filter)

	tests := []struct {
		name    string
		calls   []execx.Call
		wantErr []string
	}{
		{
			name: "removes-containers-then-networks-and-volumes",
			calls: []execx.Call{
				{Argv: ps, Result: execx.Result{Stdout: []byte("c1\nc2\n")}},
				{Argv: []string{"docker", "rm", "-f", "-v", "c1", "c2"}},
				{Argv: nets, Result: execx.Result{Stdout: []byte("n1\n")}},
				{Argv: []string{"docker", "network", "rm", "n1"}},
				{Argv: vols, Result: execx.Result{Stdout: []byte("v1\nv2\n")}},
				{Argv: []string{"docker", "volume", "rm", "v1", "v2"}},
			},
		},
		{
			name: "nothing-left-behind",
			calls: []execx.Call{
				{Argv: ps},
				{Argv: nets},
				{Argv: vols},
			},
		},
		{
			// Every failure is reported, and one does not stop the rest.
			name: "errors-surface",
			calls: []execx.Call{
				{Argv: ps, Result: execx.Result{Code: 1, Stderr: []byte("Cannot connect to the Docker daemon")}},
				{Argv: nets, Result: execx.Result{Stdout: []byte("n1\n")}},
				{Argv: []string{"docker", "network", "rm", "n1"}, Result: execx.Result{Code: 1, Stderr: []byte("network n1 has active endpoints")}},
				{Argv: vols, Result: execx.Result{Stdout: []byte("v1\n")}},
				{Argv: []string{"docker", "volume", "rm", "v1"}},
			},
			wantErr: []string{"Cannot connect", "active endpoints"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := newEngine("docker", execx.NewFake(t, tt.calls...)).Sweep(t.Context())
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Errorf("Sweep() error = %v, want nil", err)
				}
				return
			}
			for _, want := range tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("Sweep() error = %v, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestExec(t *testing.T) {
	t.Parallel()

	c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t,
		execx.Call{Argv: []string{"docker", "exec", "abc", "id", "-u"}, Result: execx.Result{Stdout: []byte("65532\n")}},
		execx.Call{Argv: []string{"docker", "exec", "-i", "abc", "cat"}, Stdin: []byte("in"), Result: execx.Result{Stdout: []byte("in")}},
		execx.Call{Argv: []string{"docker", "exec", "abc", "false"}, Result: execx.Result{Code: 1}},
	))}

	if res, err := c.Exec(t.Context(), nil, "id", "-u"); err != nil || string(res.Stdout) != "65532\n" {
		t.Errorf("Exec(id -u) = %+v, %v", res, err)
	}
	if res, err := c.Exec(t.Context(), strings.NewReader("in"), "cat"); err != nil || string(res.Stdout) != "in" {
		t.Errorf("Exec(cat) = %+v, %v", res, err)
	}
	// A command that ran and failed is a Result, not an error.
	if res, err := c.Exec(t.Context(), nil, "false"); err != nil || res.Code != 1 {
		t.Errorf("Exec(false) = %+v, %v; want code 1, nil", res, err)
	}
}

func TestLogs(t *testing.T) {
	t.Parallel()

	c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t,
		execx.Call{Argv: []string{"docker", "logs", "abc"}, Result: execx.Result{Stdout: []byte("out\n"), Stderr: []byte("refusing: reason\n")}},
	))}
	got, err := c.Logs(t.Context())
	if err != nil || !strings.Contains(got, "out\n") || !strings.Contains(got, "refusing: reason\n") {
		t.Errorf("Logs() = %q, %v; want both streams", got, err)
	}
}

// inspectJSON is `container inspect` output for one container, in the
// shape both engines print, with the fields the harness reads.
const inspectJSON = `[{
	"Id": "abc",
	"State": {
		"Status": "running", "Running": true, "ExitCode": 0, "Error": "",
		"StartedAt": "2026-11-11T04:06:16.053161074Z",
		"Health": {"Status": "healthy", "FailingStreak": 0, "Log": [
			{"Start": "2026-11-11T04:06:21Z", "End": "2026-11-11T04:06:22Z", "ExitCode": 0, "Output": ""}
		]}
	},
	"Config": {
		"User": "65532:65532",
		"Healthcheck": {"Test": ["CMD", "/usr/local/bin/frankenphp", "php-cli", "/x"],
			"Interval": 30000000000, "Timeout": 10000000000, "StartPeriod": 60000000000, "Retries": 3}
	},
	"HostConfig": {
		"CapAdd": null, "CapDrop": ["ALL"], "Privileged": false, "ReadonlyRootfs": true,
		"SecurityOpt": null, "Init": null, "NetworkMode": "net"
	},
	"NetworkSettings": {"Networks": {"net": {"IPAddress": "10.89.66.3"}, "other": {"IPAddress": "10.0.0.9"}}}
}]`

// podmanHostConfig is the HostConfig of Podman's `container inspect`, as
// rootless Podman 6.1 printed it for a container run under the contract
// with --cap-add NET_RAW, --init and two security options on a named
// network: the same field names as Docker's, but its own values.
const podmanHostConfig = `[{
	"Id": "abc",
	"HostConfig": {
		"CapAdd": ["CAP_NET_RAW"],
		"CapDrop": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL"],
		"Privileged": false, "ReadonlyRootfs": true,
		"SecurityOpt": ["no-new-privileges", "apparmor=unconfined"], "Init": true, "NetworkMode": "bridge"
	}
}]`

func TestInspect(t *testing.T) {
	t.Parallel()

	c := &Container{ID: "abc", network: "net", engine: newEngine("docker", execx.NewFake(t,
		execx.Call{Argv: []string{"docker", "container", "inspect", "abc"}, Result: execx.Result{Stdout: []byte(inspectJSON)}},
	))}
	got, err := c.Inspect(t.Context())
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !got.State.Running || got.State.Status != "running" || got.State.StartedAt.IsZero() {
		t.Errorf("Inspect().State = %+v", got.State)
	}
	if got.State.Health == nil || got.State.Health.Status != "healthy" || len(got.State.Health.Log) != 1 {
		t.Errorf("Inspect().State.Health = %+v", got.State.Health)
	}
	if got.Config.User != "65532:65532" {
		t.Errorf("Inspect().Config.User = %q", got.Config.User)
	}
	if hc := got.Config.Healthcheck; hc == nil || hc.StartPeriod != time.Minute || hc.Retries != 3 || len(hc.Test) != 4 {
		t.Errorf("Inspect().Config.Healthcheck = %+v", hc)
	}
	// The address on the container's own network, not on any other.
	if got.IP != "10.89.66.3" {
		t.Errorf("Inspect().IP = %q, want 10.89.66.3", got.IP)
	}
	if h := got.HostConfig; len(h.CapAdd) != 0 || h.Privileged || !h.ReadonlyRootfs || len(h.SecurityOpt) != 0 ||
		h.Init != nil || h.NetworkMode != "net" {
		t.Errorf("Inspect().HostConfig = %+v, want Docker's null CapAdd, SecurityOpt and Init, read-only, on net", h)
	}
}

func TestInspectPodmanHostConfig(t *testing.T) {
	t.Parallel()

	c := &Container{ID: "abc", engine: newEngine("podman", execx.NewFake(t,
		execx.Call{Argv: []string{"podman", "container", "inspect", "abc"}, Result: execx.Result{Stdout: []byte(podmanHostConfig)}},
	))}
	got, err := c.Inspect(t.Context())
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	h := got.HostConfig
	if !slices.Equal(h.CapAdd, []string{"CAP_NET_RAW"}) || h.Privileged || !h.ReadonlyRootfs ||
		!slices.Equal(h.SecurityOpt, []string{"no-new-privileges", "apparmor=unconfined"}) ||
		h.Init == nil || !*h.Init || h.NetworkMode != "bridge" {
		t.Errorf("Inspect().HostConfig = %+v (Init %v), want what Podman printed", h, h.Init)
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{
		Image:      "img",
		Name:       "ctr",
		Network:    "none",
		Confine:    Contract("16m"),
		Entrypoint: []string{FrankenPHP},
		Args:       []string{"version"},
	}
	// What Docker 29 printed for a binary carrying a file capability: the
	// runtime execs it after the container has started, and exits 255.
	refused := execx.Result{Code: 255, Stderr: []byte("exec /usr/local/bin/frankenphp: operation not permitted\n")}
	e := newEngine("docker", nil)
	e.run = execx.NewFake(t,
		execx.Call{
			Argv: []string{
				"docker", "run", "--rm", "--label", "divbast.harness=1", "--name", "ctr",
				"--cap-drop", "ALL", "--read-only", "--user", "65532:65532", "--tmpfs", "/tmp:size=16m",
				"--network", "none", "--entrypoint", FrankenPHP, "img", "version",
			},
			Result: refused,
		},
		// --rm removed it already, and a missing one is no failure.
		execx.Call{Argv: []string{"docker", "rm", "-f", "-v", "ctr"}, Result: execx.Result{
			Code: 1, Stderr: []byte("Error response from daemon: No such container: ctr"),
		}},
	)

	got, err := e.Run(t.Context(), t, spec)
	if err != nil {
		t.Fatalf("Run() error = %v; an exit status is a Result, not an error", err)
	}
	if got.Code != 255 || !bytes.Equal(got.Stderr, refused.Stderr) {
		t.Errorf("Run() = %+v, want exit status 255 and the runtime's words", got)
	}
}

func TestRunRejects(t *testing.T) {
	t.Parallel()

	// A Fake with no calls: nothing may run.
	e := newEngine("docker", execx.NewFake(t))
	if _, err := e.Run(t.Context(), t, &RunSpec{}); err == nil {
		t.Error("Run(no image) error = nil, want a refusal")
	}
}

// state is `container inspect` output with only the fields WaitExit and
// EngineHealthy read.
func state(status string, running bool, code int, started, health string) []byte {
	h := ""
	if health != "" {
		h = `, "Health": {"Status": "` + health + `", "Log": [{"ExitCode": 1, "Output": "probe said no"}]}`
	}
	return []byte(`[{"State": {"Status": "` + status + `", "Running": ` + strconv.FormatBool(running) +
		`, "ExitCode": ` + strconv.Itoa(code) + `, "StartedAt": "` + started + `"` + h + `}}]`)
}

const (
	startedAt = "2000-01-01T00:00:01Z"
	never     = "0001-01-01T00:00:00Z"
)

func TestWaitExitStates(t *testing.T) {
	t.Parallel()

	inspect := []string{"docker", "container", "inspect", "abc"}
	tests := []struct {
		name     string
		states   [][]byte
		within   time.Duration
		wantCode int
		wantErr  error
		wantText string
	}{
		{
			name:     "refuses-with-1",
			states:   [][]byte{state("running", true, 0, startedAt, ""), state("exited", false, 1, startedAt, "")},
			within:   30 * time.Second,
			wantCode: 1,
		},
		{
			name:     "never-started",
			states:   [][]byte{state("created", false, 127, never, "")},
			within:   30 * time.Second,
			wantErr:  ErrNeverStarted,
			wantText: "never started",
		},
		{
			name:     "still-running",
			states:   slices.Repeat([][]byte{state("running", true, 0, startedAt, "")}, 3),
			within:   time.Second,
			wantText: "still running after 1s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				calls := make([]execx.Call, 0, len(tt.states))
				for _, s := range tt.states {
					calls = append(calls, execx.Call{Argv: inspect, Result: execx.Result{Stdout: s}})
				}
				c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, calls...))}

				code, err := c.WaitExit(t.Context(), tt.within)
				if tt.wantText == "" {
					if err != nil || code != tt.wantCode {
						t.Errorf("WaitExit() = %d, %v; want %d, nil", code, err, tt.wantCode)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Fatalf("WaitExit() = %d, %v; want an error containing %q", code, err, tt.wantText)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("WaitExit() error = %v, want %v", err, tt.wantErr)
				}
			})
		})
	}
}

func TestEngineHealthy(t *testing.T) {
	t.Parallel()

	inspect := []string{"docker", "container", "inspect", "abc"}
	healthcheck := []string{"podman", "healthcheck", "run", "abc"}
	tests := []struct {
		name     string
		engine   string
		calls    []execx.Call
		wantText string
	}{
		{
			name:   "podman-runs-the-check",
			engine: "podman",
			calls:  []execx.Call{{Argv: healthcheck}},
		},
		{
			name:     "podman-check-fails",
			engine:   "podman",
			calls:    []execx.Call{{Argv: healthcheck, Result: execx.Result{Code: 1, Stdout: []byte("unhealthy\n")}}},
			wantText: "unhealthy",
		},
		{
			name:   "docker-healthy-once-started",
			engine: "docker",
			calls: []execx.Call{
				{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "starting")}},
				{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "healthy")}},
			},
		},
		{
			name:     "docker-unhealthy-dumps-the-log",
			engine:   "docker",
			calls:    []execx.Call{{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "unhealthy")}}},
			wantText: "probe said no",
		},
		{
			name:   "docker-still-starting-past-the-start-period",
			engine: "docker",
			calls: slices.Repeat([]execx.Call{
				{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "starting")}},
			}, 3),
			wantText: "still starting",
		},
		{
			name:     "docker-no-health-check",
			engine:   "docker",
			calls:    []execx.Call{{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}}},
			wantText: "no health check",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c := &Container{ID: "abc", started: time.Now(), engine: newEngine(tt.engine, execx.NewFake(t, tt.calls...))}

				err := c.EngineHealthy(t.Context(), time.Second)
				if tt.wantText == "" {
					if err != nil {
						t.Errorf("EngineHealthy() error = %v, want nil", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Errorf("EngineHealthy() error = %v, want it to contain %q", err, tt.wantText)
				}
			})
		})
	}
}

// runFunc is an execx.StdinRunner that answers every command from a
// function, for tests that cannot know an argv in advance.
type runFunc func(argv []string) execx.Result

func (f runFunc) RunStdin(_ context.Context, _ io.Reader, name string, args ...string) (execx.Result, error) {
	return f(append([]string{name}, args...)), nil
}

func TestParseRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		out     string
		want    []Record
		wantErr bool
	}{
		{
			name: "records",
			out:  "ok\tCapEff, every capability bit clear\t0000000000000000\t0000000000000000\nFAIL\tPID 1 comm\tfrankenphp\tdocker-init\n",
			want: []Record{
				{OK: true, What: "CapEff, every capability bit clear", Expected: "0000000000000000", Found: "0000000000000000"},
				{OK: false, What: "PID 1 comm", Expected: "frankenphp", Found: "docker-init"},
			},
		},
		{name: "empty-found", out: "ok\tUDP ports\tnone\t\n", want: []Record{{OK: true, What: "UDP ports", Expected: "none"}}},
		{name: "nothing", out: "", want: nil},
		{name: "unknown-verdict", out: "pass\twhat\texpected\tfound\n", wantErr: true},
		{name: "too-few-fields", out: "ok\twhat\texpected\n", wantErr: true},
		{name: "too-many-fields", out: "ok\twhat\texpected\tfound\textra\n", wantErr: true},
		{name: "not-a-record", out: "ok\tfine\ta\ta\nPHP Warning:  something\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseRecords([]byte(tt.out))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRecords(%q) = %+v, nil; want an error", tt.out, got)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Errorf("parseRecords(%q) = %+v, %v; want %+v, nil", tt.out, got, err, tt.want)
			}
		})
	}
}

// fakeTB is a testing.TB that keeps what checks report instead of failing
// the test running them. Only the methods Checks calls are implemented.
type fakeTB struct {
	testing.TB

	mu         sync.Mutex
	logs, errs []string
}

func (*fakeTB) Helper() {}

func (f *fakeTB) Logf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

func (f *fakeTB) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, fmt.Sprintf(format, args...))
}

func TestChecks(t *testing.T) {
	t.Parallel()

	tb := &fakeTB{}
	c := newChecks(tb, "")
	c.Records([]Record{
		{OK: true, What: "CapEff, every capability bit clear", Expected: "0", Found: "0"},
		{OK: false, What: "PID 1 comm", Expected: "frankenphp", Found: "docker-init"},
	})
	Equal(c, "status", 401, 401)
	Equal(c, "body", "ok\n", "fail\n")
	c.True("healthy", true, "")
	c.True("internal", false, "network inspect says false")
	c.Records(nil)

	wantLogs := []string{"ok   CapEff, every capability bit clear (0)", "ok   status (401)", "ok   healthy ()"}
	wantErrs := []string{
		`FAIL PID 1 comm: got "docker-init", want "frankenphp"`,
		`FAIL body: got "fail\n", want "ok\n"`,
		"FAIL internal: network inspect says false",
		"FAIL no records",
	}
	if !slices.Equal(tb.logs, wantLogs) {
		t.Errorf("logged %q, want %q", tb.logs, wantLogs)
	}
	if len(tb.errs) != len(wantErrs) {
		t.Fatalf("reported %q, want %q", tb.errs, wantErrs)
	}
	for i, want := range wantErrs {
		if !strings.HasPrefix(tb.errs[i], want) {
			t.Errorf("report %d = %q, want it to start %q", i, tb.errs[i], want)
		}
	}
}

func TestChecksLog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tb := &fakeTB{}
	c := newChecks(tb, filepath.Join(dir, "checks.log"))

	// Checks from parallel subtests share one log, and every name must land
	// whole, on a line of its own.
	want := make([]string, 0, 66)
	var wg sync.WaitGroup
	for i := range 64 {
		name := fmt.Sprintf("check %02d x%s", i, strings.Repeat("x", i*16))
		want = append(want, name)
		wg.Go(func() { c.True(name, true, "") })
	}
	wg.Wait()
	// Failed checks are named too, and a name never spans two lines.
	c.Records([]Record{{OK: false, What: "a record\twith a tab", Expected: "a", Found: "b"}})
	Equal(c, "equal\nthat fails", 1, 2)
	want = append(want, "a record with a tab", "equal that fails")

	b := readLog(t, dir)
	got := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the log holds\n%q\nwant\n%q", got, want)
	}
}

func TestChecksLogFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DIVBAST_CHECK_LOG", filepath.Join(dir, "checks.log"))

	c := NewChecks(&fakeTB{})
	c.True("named from the environment", true, "")

	if b := readLog(t, dir); string(b) != "named from the environment\n" {
		t.Errorf("the log holds %q, want the one name", b)
	}
}

// readLog returns checks.log from dir.
func readLog(t *testing.T, dir string) []byte {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Error(cerr)
		}
	})
	b, err := root.ReadFile("checks.log")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChecksLogUnwritable(t *testing.T) {
	t.Parallel()

	tb := &fakeTB{}
	c := newChecks(tb, filepath.Join(t.TempDir(), "no-such-dir", "checks.log"))
	c.True("named", true, "")
	if len(tb.errs) != 1 || !strings.Contains(tb.errs[0], "DIVBAST_CHECK_LOG") {
		t.Errorf("reported %q, want the log's failure surfaced once", tb.errs)
	}
}

// probeArgv is how the harness runs one probe subcommand in container abc.
func probeArgv(args ...string) []string {
	return slices.Concat([]string{"docker", "exec", "abc", "/usr/local/bin/frankenphp", "php-cli", "/tmp/divbast-probe/core.php"}, args)
}

func TestInstallProbe(t *testing.T) {
	t.Parallel()

	install := func(file string) []string {
		return []string{"docker", "exec", "-i", "abc", "/usr/local/bin/frankenphp", "php-cli", "-r", installCode(file)}
	}
	app := []byte("<?php return [];\n")
	tests := []struct {
		name    string
		app     []byte
		calls   []execx.Call
		wantErr string
	}{
		{
			name:  "core-only",
			calls: []execx.Call{{Argv: install("/tmp/divbast-probe/core.php"), Stdin: coreProbe}},
		},
		{
			name: "core-and-app",
			app:  app,
			calls: []execx.Call{
				{Argv: install("/tmp/divbast-probe/core.php"), Stdin: coreProbe},
				{Argv: install("/tmp/divbast-probe/app.php"), Stdin: app},
			},
		},
		{
			name: "write-fails",
			calls: []execx.Call{{Argv: install("/tmp/divbast-probe/core.php"), Stdin: coreProbe, Result: execx.Result{
				Code: 1, Stderr: []byte("cannot write /tmp/divbast-probe/core.php: No space left on device\n"),
			}}},
			wantErr: "No space left on device",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, tt.calls...))}
			p, err := InstallProbe(t.Context(), c, tt.app)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("InstallProbe() = %v, %v; want an error containing %q", p, err, tt.wantErr)
				}
				return
			}
			if err != nil || p == nil {
				t.Errorf("InstallProbe() = %v, %v; want a probe", p, err)
			}
		})
	}
}

func TestInstallProbeRetries(t *testing.T) {
	t.Parallel()

	install := []string{"docker", "exec", "-i", "abc", "/usr/local/bin/frankenphp", "php-cli", "-r", installCode("/tmp/divbast-probe/core.php")}
	inspect := []string{"docker", "container", "inspect", "abc"}
	// What Docker said, once, to an exec into a container still starting
	refused := execx.Result{Code: 128, Stderr: []byte("OCI runtime exec failed: exec failed: cannot exec in a stopped container")}
	tests := []struct {
		name     string
		calls    []execx.Call
		wantText string
	}{
		{
			name: "engine-refused-while-running",
			calls: []execx.Call{
				{Argv: install, Stdin: coreProbe, Result: refused},
				{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}},
				{Argv: install, Stdin: coreProbe},
			},
		},
		{
			name: "engine-refused-and-stopped",
			calls: []execx.Call{
				{Argv: install, Stdin: coreProbe, Result: refused},
				{Argv: inspect, Result: execx.Result{Stdout: state("exited", false, 1, startedAt, "")}},
			},
			wantText: "cannot exec in a stopped container",
		},
		{
			name: "engine-refuses-every-time",
			calls: slices.Concat(
				slices.Repeat([]execx.Call{
					{Argv: install, Stdin: coreProbe, Result: refused},
					{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}},
				}, installAttempts-1),
				[]execx.Call{{Argv: install, Stdin: coreProbe, Result: refused}},
			),
			wantText: "cannot exec in a stopped container",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, tt.calls...))}
				p, err := InstallProbe(t.Context(), c, nil)
				if tt.wantText == "" {
					if err != nil || p == nil {
						t.Errorf("InstallProbe() = %v, %v; want a probe", p, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Errorf("InstallProbe() = %v, %v; want an error containing %q", p, err, tt.wantText)
				}
			})
		})
	}
}

func TestProbeRun(t *testing.T) {
	t.Parallel()

	okRecord := "ok\tCapEff, every capability bit clear\t0\t0\n"
	failRecord := "FAIL\tCapBnd, every capability bit clear\t0\t2000\n"
	tests := []struct {
		name     string
		res      execx.Result
		want     int
		wantText string
	}{
		{name: "all-ok", res: execx.Result{Stdout: []byte(okRecord + okRecord)}, want: 2},
		// A FAIL is the caller's to report, not an error.
		{name: "a-fail", res: execx.Result{Code: 1, Stdout: []byte(okRecord + failRecord)}, want: 2},
		{name: "fail-but-exit-0", res: execx.Result{Stdout: []byte(failRecord)}, wantText: "disagrees"},
		{name: "exit-1-but-all-ok", res: execx.Result{Code: 1, Stdout: []byte(okRecord)}, wantText: "disagrees"},
		{name: "usage", res: execx.Result{Code: 2, Stderr: []byte("unknown subcommand 'assert-caps'\n")}, wantText: "unknown subcommand"},
		{name: "no-records", res: execx.Result{Code: 1, Stderr: []byte("Error response from daemon: container abc is not running\n")}, wantText: "not running"},
		{name: "not-records", res: execx.Result{Stdout: []byte(okRecord + "Warning: something\n")}, wantText: "not a record"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := &Probe{c: &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t,
				execx.Call{Argv: probeArgv("assert-caps"), Result: tt.res},
			))}}
			got, err := p.Run(t.Context(), "assert-caps")
			if tt.wantText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Errorf("Run() = %+v, %v; want an error containing %q", got, err, tt.wantText)
				}
				return
			}
			if err != nil || len(got) != tt.want {
				t.Errorf("Run() = %+v, %v; want %d records", got, err, tt.want)
			}
		})
	}
}

func TestParseHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		out     string
		want    HTTPResponse
		wantErr bool
	}{
		{out: "200\n{\"processedString\":\"127.0.0.1\"}", want: HTTPResponse{Status: 200, Body: []byte(`{"processedString":"127.0.0.1"}`)}},
		{out: "404\n", want: HTTPResponse{Status: 404, Body: []byte{}}},
		{out: "200", wantErr: true},
		{out: "ok\nbody", wantErr: true},
		{out: "2000\nbody", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseHTTP([]byte(tt.out))
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseHTTP(%q) = %+v, nil; want an error", tt.out, got)
			}
			continue
		}
		if err != nil || got.Status != tt.want.Status || !bytes.Equal(got.Body, tt.want.Body) {
			t.Errorf("parseHTTP(%q) = %+v, %v; want %+v", tt.out, got, err, tt.want)
		}
	}
}

func TestWaitHTTP(t *testing.T) {
	t.Parallel()

	const url = "http://127.0.0.1:8080/"
	request := probeArgv("http-request", "GET", url, "", "")
	inspect := []string{"docker", "container", "inspect", "abc"}
	refused := execx.Result{Code: 1, Stdout: []byte("FAIL\thttp-request completed\tno exception\tRuntimeException: cannot connect to 127.0.0.1:8080 (errno 111: Connection refused)\n")}
	tests := []struct {
		name     string
		calls    []execx.Call
		wantText string
	}{
		{
			name: "serves-once-started",
			calls: []execx.Call{
				{Argv: request, Result: refused},
				{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}},
				{Argv: request, Result: execx.Result{Stdout: []byte("200\nhello")}},
			},
		},
		{
			name: "stops-instead",
			calls: []execx.Call{
				{Argv: request, Result: refused},
				{Argv: inspect, Result: execx.Result{Stdout: state("exited", false, 1, startedAt, "")}},
				{Argv: []string{"docker", "logs", "abc"}, Result: execx.Result{Stderr: []byte("refusing: TRUSTED_PROXIES holds '::/0'\n")}},
			},
			wantText: "TRUSTED_PROXIES",
		},
		{
			name: "never-serves",
			calls: slices.Concat(
				slices.Repeat([]execx.Call{
					{Argv: request, Result: refused},
					{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}},
				}, 2),
				[]execx.Call{{Argv: []string{"docker", "logs", "abc"}, Result: execx.Result{Stdout: []byte("starting\n")}}},
			),
			wantText: "Connection refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				p := &Probe{c: &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, tt.calls...))}}
				got, err := p.WaitHTTP(t.Context(), url, time.Second)
				if tt.wantText == "" {
					if err != nil || got.Status != 200 || string(got.Body) != "hello" {
						t.Errorf("WaitHTTP() = %+v, %v; want 200 hello", got, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Errorf("WaitHTTP() error = %v, want it to contain %q", err, tt.wantText)
				}
			})
		})
	}
}

func TestHostClient(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin/install/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := HostClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	// The redirect is the answer: following it would turn a 302 into a 200.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("GET / status = %d, want 302, unfollowed", resp.StatusCode)
	}
}

// php returns the host's php, skipping t without one: the probe runs as
// the container's PHP in the integration tests, and here as the host's.
func php(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("php")
	switch {
	case err == nil:
	case os.Getenv("GITHUB_ACTIONS") == "true":
		// CI sets PHP up, and a skip there would leave the probe untested.
		t.Fatalf("no php on PATH, which CI provides: %v", err)
	default:
		t.Skip("no php on PATH to run the probe with")
	}
	return bin
}

// runPHP runs the probe script with php and arguments.
func runPHP(t *testing.T, script string, args ...string) execx.Result {
	t.Helper()
	res, err := execx.OS{}.Run(t.Context(), php(t), append([]string{script}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestListenersParser runs the probe's own socket parsing over tables
// taken from the LibreSpeed fixture under Docker, on an internal network,
// where Docker's resolver keeps a TCP listener and a UDP socket at
// 127.0.0.11 that no process in the container holds. proc-net-udp adds,
// by hand, a UDP socket that one does hold, at port 5353.
func TestListenersParser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tcp, udp string
		wantCode int
		want     string
	}{
		{name: "held-udp-reported-resolver-ignored", tcp: "proc-net-tcp", udp: "proc-net-udp", want: "udp 5353\n"},
		{name: "held-tcp-listeners", tcp: "proc-net-tcp6", udp: "proc-net-udp6", want: "tcp 8080\ntcp 8081\n"},
		{name: "malformed-table", tcp: "proc-net-malformed", udp: "proc-net-udp6", wantCode: 1, want: "FAIL\tparse-listeners completed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := runPHP(t, "probe/core.php", "parse-listeners",
				filepath.Join("testdata", tt.tcp), filepath.Join("testdata", tt.udp), filepath.Join("testdata", "proc-net-fds"))
			if res.Code != tt.wantCode || !strings.HasPrefix(string(res.Stdout), tt.want) {
				t.Errorf("parse-listeners = exit %d, stdout %q, stderr %q; want exit %d, stdout starting %q",
					res.Code, res.Stdout, res.Stderr, tt.wantCode, tt.want)
			}
		})
	}
}

func TestProbeDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		app      string // app.php beside core.php; none when empty
		args     []string
		wantCode int
		want     string // the start of stdout, or of stderr when wantCode is 2
	}{
		{name: "no-subcommand", wantCode: 2, want: "no subcommand given"},
		{name: "unknown", args: []string{"assert-everything"}, wantCode: 2, want: "unknown subcommand 'assert-everything'"},
		{name: "variadic-needs-one", args: []string{"assert-pid1"}, wantCode: 2, want: "assert-pid1 takes <argv>..., got 0"},
		{name: "fixed-arity", args: []string{"probe-egress", "extra"}, wantCode: 2, want: "probe-egress takes no arguments, got 1"},
		{
			name:     "a-port-that-is-not",
			args:     []string{"assert-listeners", "80a"},
			wantCode: 1,
			want:     "FAIL\tassert-listeners completed\tno exception\tInvalidArgumentException: '80a' is not a TCP port",
		},
		{
			name: "app-subcommand",
			app:  `<?php return ['app-echo' => static function (array $operands): void { Assertions::equals('app operands', 'a b', implode(' ', $operands)); }];`,
			args: []string{"app-echo", "a", "b"},
			want: "ok\tapp operands\ta b\ta b\n",
		},
		{
			name:     "app-clashes-with-core",
			app:      `<?php return ['assert-caps' => static function (array $operands): void {}];`,
			args:     []string{"assert-caps"},
			wantCode: 2,
			want:     "cannot load the subcommands",
		},
		{
			name:     "app-returns-no-commands",
			app:      `<?php return 'nothing';`,
			args:     []string{"assert-caps"},
			wantCode: 2,
			want:     "cannot load the subcommands",
		},
		{
			name:     "app-does-not-parse",
			app:      `<?php return [`,
			args:     []string{"assert-caps"},
			wantCode: 2,
			want:     "cannot load the subcommands",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "core.php"), coreProbe, 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.app != "" {
				if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(tt.app), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			res := runPHP(t, filepath.Join(dir, "core.php"), tt.args...)
			got := res.Stdout
			if tt.wantCode == 2 {
				got = res.Stderr
			}
			if res.Code != tt.wantCode || !strings.HasPrefix(string(got), tt.want) {
				t.Errorf("core.php %q = exit %d, stdout %q, stderr %q; want exit %d, starting %q",
					tt.args, res.Code, res.Stdout, res.Stderr, tt.wantCode, tt.want)
			}
		})
	}
}
