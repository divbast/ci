// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
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
	"NetworkSettings": {"Networks": {"net": {"IPAddress": "10.89.66.3"}, "other": {"IPAddress": "10.0.0.9"}}}
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
