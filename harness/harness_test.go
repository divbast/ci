// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// ownLabel is the label the harness gives everything it makes in ci's own
// tests, whose binaries are built in ci's module.
const ownLabel = "divbast.harness=github.com/divbast/ci"

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
			loose := e.Argv(&RunSpec{Image: "img", Confine: Unconfined()})
			for _, flag := range []string{"--cap-drop", "--read-only", "--user", "--tmpfs"} {
				if slices.Contains(loose, flag) {
					t.Errorf("Argv(Unconfined()) = %q, holds %s", loose, flag)
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
		"run", "-d", "--label", ownLabel, "--name", "ctr",
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

	spec := &RunSpec{Image: "img", Confine: Contract("16m")}
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

// TestNeverStartedOnlyForNeverStarted runs Start into each way a run can
// fail, in the words Docker 29 and Podman print. ErrNeverStarted is for a
// container the engine made and could not start; a run it refused before
// making one, for a flag, an image it could not pull or a name already in
// use, is ErrRefused instead. A container Start did not make is not its
// to remove: on a name in use, its cleanup issues no rm, which the Fake,
// having none scripted, would fail.
func TestNeverStartedOnlyForNeverStarted(t *testing.T) {
	t.Parallel()

	spec := &RunSpec{Image: "img", Name: "ctr", Confine: Contract("16m")}
	// whether the engine made ctr, as its container inspect says
	made := func(engine string) execx.Call {
		return execx.Call{Argv: []string{engine, "container", "inspect", "--format", "{{.Id}}", "ctr"}, Result: execx.Result{Stdout: []byte("abc123\n")}}
	}
	notMade := func(engine string, code int, stderr string) execx.Call {
		return execx.Call{Argv: []string{engine, "container", "inspect", "--format", "{{.Id}}", "ctr"}, Result: execx.Result{Code: code, Stderr: []byte(stderr)}}
	}
	tests := []struct {
		name, engine string
		run          execx.Result
		inspect      []execx.Call // none for a refusal the engine's words already settle
		othersName   bool         // the name is another container's, which no cleanup may remove
		want         error        // nil for neither
		wantText     string
	}{
		{
			// Docker prints the ID of the container it made, then fails
			name:   "docker-entrypoint-missing",
			engine: "docker",
			run: execx.Result{Code: 127, Stdout: []byte("64ca16a5b644\n"), Stderr: []byte(`docker: Error response from daemon: failed to create task for container: ` +
				`failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: ` +
				`error during container init: exec: "/nonexistent": stat /nonexistent: no such file or directory`)},
			inspect:  []execx.Call{made("docker")},
			want:     ErrNeverStarted,
			wantText: "/nonexistent",
		},
		{
			name:     "podman-entrypoint-missing",
			engine:   "podman",
			run:      execx.Result{Code: 127, Stderr: []byte("Error: crun: executable file `/nonexistent` not found in $PATH: No such file or directory: OCI runtime attempted to invoke a command that was not found")},
			inspect:  []execx.Call{made("podman")},
			want:     ErrNeverStarted,
			wantText: "/nonexistent",
		},
		{
			// A mount the runtime refused as it started the container,
			// which Docker made first: the process never ran either.
			name:   "docker-mount-refused-at-start",
			engine: "docker",
			run: execx.Result{Code: 125, Stdout: []byte("186a882cf7c6\n"), Stderr: []byte(`docker: Error response from daemon: failed to create task for container: ` +
				`error mounting "tmpfs" to rootfs at "/tmp": invalid argument`)},
			inspect:  []execx.Call{made("docker")},
			want:     ErrNeverStarted,
			wantText: "invalid argument",
		},
		{
			// Made, then refused a port another holds: "already in use",
			// but of an address, not a name, and the container exists.
			name:     "podman-port-in-use-at-start",
			engine:   "podman",
			run:      execx.Result{Code: 126, Stderr: []byte("Error: rootlessport listen tcp 127.0.0.1:18290: bind: address already in use")},
			inspect:  []execx.Call{made("podman")},
			want:     ErrNeverStarted,
			wantText: "address already in use",
		},
		{
			name:     "docker-bad-flag",
			engine:   "docker",
			run:      execx.Result{Code: 125, Stderr: []byte("unknown flag: --bogus\n\nUsage:  docker run [OPTIONS] IMAGE [COMMAND] [ARG...]")},
			inspect:  []execx.Call{notMade("docker", 1, "Error response from daemon: No such container: ctr")},
			want:     ErrRefused,
			wantText: "unknown flag: --bogus",
		},
		{
			name:     "podman-bad-flag",
			engine:   "podman",
			run:      execx.Result{Code: 125, Stderr: []byte("Error: unknown flag: --bogus\nSee 'podman run --help'")},
			inspect:  []execx.Call{notMade("podman", 125, "Error: no such container ctr")},
			want:     ErrRefused,
			wantText: "unknown flag: --bogus",
		},
		{
			name:   "docker-pull-fails",
			engine: "docker",
			run: execx.Result{Code: 125, Stderr: []byte("Unable to find image 'localhost:1/none:missing' locally\n" +
				`docker: Error response from daemon: failed to resolve reference "localhost:1/none:missing": connect: connection refused`)},
			inspect:  []execx.Call{notMade("docker", 1, "Error response from daemon: No such container: ctr")},
			want:     ErrRefused,
			wantText: "connection refused",
		},
		{
			name:   "podman-pull-fails",
			engine: "podman",
			run: execx.Result{Code: 125, Stderr: []byte("Trying to pull localhost:1/none:missing...\n" +
				`Error: initializing source docker://localhost:1/none:missing: pinging container registry localhost:1: connect: connection refused`)},
			inspect:  []execx.Call{notMade("podman", 125, "Error: no such container ctr")},
			want:     ErrRefused,
			wantText: "connection refused",
		},
		{
			// The container of that name is another's, so its state says
			// nothing of this run: it is never asked about, nor removed.
			name:       "docker-name-in-use",
			engine:     "docker",
			othersName: true,
			run: execx.Result{Code: 125, Stderr: []byte(`docker: Error response from daemon: Conflict. The container name "/ctr" is already in use by container "3f82dc47df74". ` +
				`You have to remove (or rename) that container to be able to reuse that name.`)},
			want:     ErrRefused,
			wantText: "already in use",
		},
		{
			name:       "podman-name-in-use",
			engine:     "podman",
			othersName: true,
			run: execx.Result{Code: 125, Stderr: []byte(`Error: creating container storage: the container name "ctr" is already in use by 3f82dc47df74. ` +
				`You have to remove that container to be able to reuse that name: that name is already in use`)},
			want:     ErrRefused,
			wantText: "already in use",
		},
		{
			// An engine that cannot say whether it made the container gets
			// neither error, and both of its failures are in the one given.
			name:     "engine-gone",
			engine:   "docker",
			run:      execx.Result{Code: 125, Stderr: []byte("docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock.")},
			inspect:  []execx.Call{notMade("docker", 1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")},
			wantText: "Is the docker daemon running?",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newEngine(tt.engine, nil)
			calls := slices.Concat(
				[]execx.Call{{Argv: slices.Concat([]string{tt.engine}, e.Argv(spec)), Result: tt.run}},
				tt.inspect,
			)
			if !tt.othersName {
				// Removed all the same, and a missing one is no failure
				calls = append(calls, execx.Call{Argv: []string{tt.engine, "rm", "-f", "-v", "ctr"}, Result: execx.Result{
					Code: 1, Stderr: []byte("Error: no such container ctr"),
				}})
			}
			e.run = execx.NewFake(t, calls...)

			_, err := e.Start(t.Context(), t, spec)
			if err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("Start() error = %v, want one with the engine's own words, %q", err, tt.wantText)
			}
			for _, sentinel := range []error{ErrNeverStarted, ErrRefused} {
				if got, want := errors.Is(err, sentinel), errors.Is(tt.want, sentinel); got != want {
					t.Errorf("Start() error = %v; errors.Is(err, %q) = %t, want %t", err, sentinel, got, want)
				}
			}
		})
	}
}

func TestStartRejects(t *testing.T) {
	t.Parallel()

	confine := Contract("16m")
	tests := []struct {
		name string
		spec RunSpec
	}{
		{name: "no-image", spec: RunSpec{Confine: confine}},
		{name: "volume-named-like-a-path", spec: RunSpec{Image: "img", Confine: confine, Mounts: []Mount{{Source: "/srv", Target: "/data", Volume: true}}}},
		{name: "bind-not-absolute", spec: RunSpec{Image: "img", Confine: confine, Mounts: []Mount{{Source: "data", Target: "/data"}}}},
		{name: "colon-in-source", spec: RunSpec{Image: "img", Confine: confine, Mounts: []Mount{{Source: "a:b", Target: "/data", Volume: true}}}},
		{name: "target-not-absolute", spec: RunSpec{Image: "img", Confine: confine, Mounts: []Mount{{Source: "vol", Target: "data", Volume: true}}}},
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

// TestZeroConfinementRefused shows Start and Run refusing a spec that
// leaves Confine unset, which would run under the engine's defaults: as
// root, writable, with the default capabilities. Unconfined is how a test
// asks for that on purpose.
func TestZeroConfinementRefused(t *testing.T) {
	t.Parallel()

	if Unconfined() == (Confinement{}) {
		t.Fatal("Unconfined() is the zero Confinement, which Start and Run refuse")
	}
	if f := Unconfined().flags(); len(f) != 0 {
		t.Errorf("Unconfined() runs with %q, want no confinement flags at all", f)
	}

	t.Run("zero-refused", func(t *testing.T) {
		t.Parallel()

		// A Fake with no calls: nothing may run.
		e := newEngine("docker", execx.NewFake(t))
		spec := &RunSpec{Image: "img"}
		if _, err := e.Start(t.Context(), t, spec); err == nil || !strings.Contains(err.Error(), "Unconfined") {
			t.Errorf("Start(zero Confine) error = %v, want a refusal naming Unconfined", err)
		}
		if _, err := e.Run(t.Context(), t, spec); err == nil || !strings.Contains(err.Error(), "Unconfined") {
			t.Errorf("Run(zero Confine) error = %v, want a refusal naming Unconfined", err)
		}
	})

	t.Run("unconfined-runs", func(t *testing.T) {
		t.Parallel()

		spec := &RunSpec{Image: "img", Name: "ctr", Confine: Unconfined()}
		e := newEngine("docker", execx.NewFake(t,
			execx.Call{Argv: []string{"docker", "run", "-d", "--label", ownLabel, "--name", "ctr", "img"}, Result: execx.Result{Stdout: []byte("abc123\n")}},
			execx.Call{Argv: []string{"docker", "run", "--rm", "--label", ownLabel, "--name", "ctr", "img"}},
			execx.Call{Argv: []string{"docker", "rm", "-f", "-v", "ctr"}},
			execx.Call{Argv: []string{"docker", "rm", "-f", "-v", "ctr"}},
		))
		if _, err := e.Start(t.Context(), t, spec); err != nil {
			t.Errorf("Start(Unconfined()) error = %v", err)
		}
		if _, err := e.Run(t.Context(), t, spec); err != nil {
			t.Errorf("Run(Unconfined()) error = %v", err)
		}
	})
}

func TestNetwork(t *testing.T) {
	t.Parallel()

	create := []string{"docker", "network", "create", "--label", ownLabel, "--subnet", "10.89.66.0/24", "--internal", "net"}
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
		execx.Call{Argv: []string{"podman", "volume", "create", "--label", ownLabel, "vol"}, Result: execx.Result{Stdout: []byte("vol\n")}},
		execx.Call{Argv: []string{"podman", "volume", "rm", "vol"}},
	))
	if got, err := e.Volume(t.Context(), t, "vol"); err != nil || got != "vol" {
		t.Errorf("Volume() = %q, %v; want vol, nil", got, err)
	}
}

func TestSweepCommands(t *testing.T) {
	t.Parallel()

	// The module's label only: the key alone would match every module's.
	filter := []string{"--filter", "label=" + ownLabel}
	ps := slices.Concat([]string{"docker", "ps", "-a", "-q"}, filter)
	images := slices.Concat([]string{"docker", "image", "ls", "-q"}, filter)
	nets := slices.Concat([]string{"docker", "network", "ls", "-q"}, filter)
	vols := slices.Concat([]string{"docker", "volume", "ls", "-q"}, filter)

	tests := []struct {
		name    string
		calls   []execx.Call
		wantErr []string
	}{
		{
			// An image is listed once for each of its tags, and removed
			// once, after the containers that may run it.
			name: "removes-containers-then-images-networks-and-volumes",
			calls: []execx.Call{
				{Argv: ps, Result: execx.Result{Stdout: []byte("c1\nc2\n")}},
				{Argv: []string{"docker", "rm", "-f", "-v", "c1", "c2"}},
				{Argv: images, Result: execx.Result{Stdout: []byte("i1\ni2\ni1\n")}},
				{Argv: []string{"docker", "image", "rm", "-f", "i1", "i2"}},
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
				{Argv: images},
				{Argv: nets},
				{Argv: vols},
			},
		},
		{
			// Every failure is reported, and one does not stop the rest.
			name: "errors-surface",
			calls: []execx.Call{
				{Argv: ps, Result: execx.Result{Code: 1, Stderr: []byte("Cannot connect to the Docker daemon")}},
				{Argv: images},
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

// TestLabelIsTheMainModules reads the label in ci's own test binary, whose
// main module go test makes ci's.
func TestLabelIsTheMainModules(t *testing.T) {
	t.Parallel()

	if got := newEngine("docker", nil).Label(); got != ownLabel {
		t.Errorf("Label() = %q, want %q", got, ownLabel)
	}
	e, err := EngineFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Label(); got != ownLabel {
		t.Errorf("EngineFromEnv().Label() = %q, want %q", got, ownLabel)
	}
}

// TestLabelInAnotherModule is the case the label is for. An app's
// acceptance suite is a test binary of the app's own module, which reaches
// the harness through a replace, and its label must be the app's: were it
// the harness's own module, every app's would be the same, and two suites
// on one host would sweep each other's containers. It builds such a test
// in a module of its own, laid out as LibreSpeed's is, and has it print
// its label.
func TestLabelInAnotherModule(t *testing.T) {
	t.Parallel()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("no go on PATH to build another module's test with: %v", err)
	}
	ci, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.27.0\n\n" +
			"require github.com/divbast/ci v0.0.0-00010101000000-000000000000\n\n" +
			"replace github.com/divbast/ci => " + ci + "\n",
		"label_test.go": "package app\n\nimport (\n\t\"fmt\"\n\t\"testing\"\n\n\t\"github.com/divbast/ci/harness\"\n)\n\n" +
			"func TestLabel(t *testing.T) {\n\te, err := harness.EngineFromEnv()\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n" +
			"\tfmt.Println(\"label:\", e.Label())\n}\n",
	} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.CommandContext(t.Context(), goBin, "test", "-count=1", "-v", "-run", "^TestLabel$", ".") //nolint:gosec // G204: the go on PATH, with this test's own arguments
	cmd.Dir = dir
	// Nothing to download, no workspace of the caller's, and no flags of
	// the run around this one
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOFLAGS=", "ENGINE=docker")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test in example.com/app: %v\n%s", err, out)
	}
	if want := "label: divbast.harness=example.com/app\n"; !strings.Contains(string(out), want) {
		t.Errorf("go test in example.com/app printed\n%s\nwant the line %q", out, want)
	}
}

// TestLabelWithoutAModule covers a binary that records no main module, as
// a test of files named on go test's command line does. Its label is its
// own process's, so its Sweep could never remove another's.
func TestLabelWithoutAModule(t *testing.T) {
	t.Parallel()

	if got := labelFor(&debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}}, true); got != "divbast.harness=example.com/app" {
		t.Errorf("labelFor(example.com/app) = %q, want divbast.harness=example.com/app", got)
	}
	noPath := labelFor(&debug.BuildInfo{}, true)
	noInfo := labelFor(nil, false)
	for _, got := range []string{noPath, noInfo} {
		if !strings.HasPrefix(got, "divbast.harness=divbast-") || len(got) <= len("divbast.harness=divbast-") {
			t.Errorf("labelFor(no main module) = %q, want divbast.harness= and a unique name", got)
		}
	}
	if noPath == noInfo {
		t.Errorf("labelFor(no main module) gave %q twice, want each its own", noPath)
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

// What engines and their runtimes print when they, and not the command,
// fail an exec, and what a command that ran prints when it fails.
var (
	// Podman, when crun failed an exec into a running container on an
	// arm64 runner.
	runtimeError = execx.Result{Code: 255, Stderr: []byte("Error: OCI runtime error: crun: setns `mnt`: Bad file descriptor\nfail startup\n")}
	// Docker, once, to an exec into a container still starting.
	stoppedRefusal = execx.Result{Code: 128, Stderr: []byte("OCI runtime exec failed: exec failed: cannot exec in a stopped container")}
	// Podman's own error, as for an exec into a container not running.
	engineError = execx.Result{Code: 125, Stderr: []byte("Error: can only create exec sessions on running containers: container state improper\n")}
	// Docker 29, for /bin/sh in an image without one.
	notFound = execx.Result{Code: 127, Stderr: []byte(`OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin/sh": stat /bin/sh: no such file or directory` + "\n")}
	// FrankenPHP's PHP, for a fatal error, which exits 255 too.
	phpFatal = execx.Result{Code: 255, Stderr: []byte("PHP Fatal error:  Uncaught Error: Call to undefined function f() in Command line code:1\n")}
)

// TestExecRetriesEngineFailure runs Exec into each way an exec can fail.
// One the engine failed, rather than the command it ran, is run again, a
// second apart, three times in all, each fed the whole of stdin; one whose
// command ran and failed is not. Three engine failures in a row are an
// error naming the last attempt, except for a command the runtime could
// not execute or find, 126 or 127, which stays a Result: a check that an
// image has no /bin/sh asserts exactly that.
func TestExecRetriesEngineFailure(t *testing.T) {
	t.Parallel()

	argv := []string{FrankenPHP, "php-cli", "-r", "echo 1;"}
	tests := []struct {
		name   string
		engine string
		stdin  []byte
		// what each attempt returns, in order: the test fails on an
		// attempt more or fewer
		attempts []execx.Result
		wantCode int
		// wantErr is in the error; empty for none
		wantErr  string
		wantWait time.Duration
	}{
		{
			name:     "runtime-error-then-0",
			engine:   "podman",
			attempts: []execx.Result{runtimeError, {Stdout: []byte("1")}},
			wantWait: time.Second,
		},
		{
			name:     "255-without-the-prefix",
			engine:   "podman",
			attempts: []execx.Result{phpFatal},
			wantCode: 255,
		},
		{
			// The prefix must open stderr: PHP may print the words
			// anywhere else in what it was given to say.
			name:     "the-prefix-later",
			engine:   "podman",
			attempts: []execx.Result{{Code: 255, Stderr: []byte("PHP Fatal error:  Error: OCI runtime error: in Command line code:1\n")}},
			wantCode: 255,
		},
		{
			name:     "exit-1",
			engine:   "docker",
			attempts: []execx.Result{{Code: 1, Stderr: []byte("no\n")}},
			wantCode: 1,
		},
		{
			name:     "125-three-times",
			engine:   "podman",
			attempts: []execx.Result{engineError, engineError, engineError},
			wantCode: 125,
			wantErr:  "attempt 3 of 3",
			wantWait: 2 * time.Second,
		},
		{
			name:     "128-then-0-fed-again",
			engine:   "docker",
			stdin:    []byte("<?php return [];\n"),
			attempts: []execx.Result{stoppedRefusal, {}},
			wantWait: time.Second,
		},
		{
			name:     "128-three-times",
			engine:   "docker",
			attempts: []execx.Result{stoppedRefusal, stoppedRefusal, stoppedRefusal},
			wantCode: 128,
			wantErr:  "cannot exec in a stopped container",
			wantWait: 2 * time.Second,
		},
		{
			name:     "127-three-times-is-a-result",
			engine:   "docker",
			attempts: []execx.Result{notFound, notFound, notFound},
			wantCode: 127,
			wantWait: 2 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				run := slices.Concat([]string{tt.engine, "exec", "abc"}, argv)
				var stdin io.Reader
				if tt.stdin != nil {
					run = slices.Concat([]string{tt.engine, "exec", "-i", "abc"}, argv)
					stdin = bytes.NewReader(tt.stdin)
				}
				calls := make([]execx.Call, 0, len(tt.attempts))
				for _, res := range tt.attempts {
					calls = append(calls, execx.Call{Argv: run, Stdin: tt.stdin, Result: res})
				}
				c := &Container{ID: "abc", engine: newEngine(tt.engine, execx.NewFake(t, calls...))}

				start := time.Now()
				res, err := c.Exec(t.Context(), stdin, argv...)
				switch {
				case tt.wantErr == "" && err != nil:
					t.Errorf("Exec() error = %v, want nil", err)
				case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
					t.Errorf("Exec() error = %v, want one containing %q", err, tt.wantErr)
				}
				if res.Code != tt.wantCode {
					t.Errorf("Exec() exit status = %d, want %d", res.Code, tt.wantCode)
				}
				if waited := time.Since(start); waited != tt.wantWait {
					t.Errorf("Exec() took %s, want %s between its attempts", waited, tt.wantWait)
				}
			})
		})
	}
}

// TestExecRetryCodes runs Exec into each exit status once, then 0. Only
// the engine's own, 125 to 128, are tried again: any other is the
// command's, which another try would only repeat.
func TestExecRetryCodes(t *testing.T) {
	t.Parallel()

	run := []string{"docker", "exec", "abc", "true"}
	for _, code := range []int{1, 2, 124, 125, 126, 127, 128, 129, 137, 255} {
		retried := code >= 125 && code <= 128
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				calls := []execx.Call{{Argv: run, Result: execx.Result{Code: code, Stderr: []byte("exit " + strconv.Itoa(code))}}}
				if retried {
					calls = append(calls, execx.Call{Argv: run})
				}
				c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, calls...))}

				res, err := c.Exec(t.Context(), nil, "true")
				switch {
				case err != nil:
					t.Errorf("Exec() after exit status %d: error = %v, want nil", code, err)
				case retried && res.Code != 0:
					t.Errorf("Exec() after exit status %d, then 0 = exit status %d, want it tried again and 0", code, res.Code)
				case !retried && res.Code != code:
					t.Errorf("Exec() after exit status %d = exit status %d, want that status, not tried again", code, res.Code)
				}
			})
		})
	}
}

// TestExecRetryHonoursContext ends the context while Exec waits to try an
// exec the engine failed again: it stops waiting, runs nothing more, and
// says why.
func TestExecRetryHonoursContext(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		run := []string{"docker", "exec", "abc", "true"}
		c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, execx.Call{Argv: run, Result: stoppedRefusal}))}
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := c.Exec(ctx, nil, "true")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Exec() error = %v, want the context's deadline", err)
		}
		if waited := time.Since(start); waited != 300*time.Millisecond {
			t.Errorf("Exec() returned after %s, want at the deadline, 300ms", waited)
		}
	})
}

// TestRestart restarts a container by its name, and reads back from the
// engine that it runs again. A restart the engine refuses is an error in
// its words, and so is a container that is not running once it is done.
// Docker's health check counts its start period from the restart, so
// EngineHealthy's does too.
func TestRestart(t *testing.T) {
	t.Parallel()

	restart := []string{"docker", "restart", "ctr"}
	inspect := []string{"docker", "container", "inspect", "abc"}
	tests := []struct {
		name    string
		calls   []execx.Call
		wantErr string
	}{
		{
			name: "running-again",
			calls: []execx.Call{
				{Argv: restart, Result: execx.Result{Stdout: []byte("ctr\n")}},
				{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}},
			},
		},
		{
			name: "refused",
			calls: []execx.Call{{Argv: restart, Result: execx.Result{
				Code: 1, Stderr: []byte("Error response from daemon: Cannot restart container ctr: tried to kill container, but did not receive an exit event\n"),
			}}},
			wantErr: "did not receive an exit event",
		},
		{
			name: "exited-again",
			calls: []execx.Call{
				{Argv: restart, Result: execx.Result{Stdout: []byte("ctr\n")}},
				{Argv: inspect, Result: execx.Result{Stdout: state("exited", false, 3, startedAt, "")}},
			},
			wantErr: "exit status 3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c := &Container{ID: "abc", Name: "ctr", engine: newEngine("docker", execx.NewFake(t, tt.calls...)), started: time.Now()}
				time.Sleep(time.Hour)

				err := c.Restart(t.Context())
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("Restart() error = %v, want one containing %q", err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("Restart() error = %v", err)
				}
				if !c.started.Equal(time.Now()) {
					t.Errorf("after Restart(), the container started at %s, want the restart's time, %s", c.started, time.Now())
				}
			})
		})
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
		"SecurityOpt": null, "Init": null, "NetworkMode": "net", "Tmpfs": {"/tmp": "size=16m"}
	},
	"Mounts": [{"Type": "volume", "Name": "divbast-abc", "Source": "/var/lib/docker/volumes/divbast-abc/_data",
		"Destination": "/data", "Driver": "local", "Mode": "z", "RW": true, "Propagation": ""}],
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
	// As printed, with what HostConfig does not read, so a check can see
	// which fields the engine left out
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(got.HostConfigJSON, &raw); err != nil || string(raw["CapDrop"]) != `["ALL"]` || len(raw) != 8 {
		t.Errorf("Inspect().HostConfigJSON = %s (%v), want the HostConfig inspect printed", got.HostConfigJSON, err)
	}
	if !maps.Equal(got.HostConfig.Tmpfs, map[string]string{"/tmp": "size=16m"}) {
		t.Errorf("Inspect().HostConfig.Tmpfs = %q", got.HostConfig.Tmpfs)
	}
	want := []MountPoint{{Type: "volume", Name: "divbast-abc", Source: "/var/lib/docker/volumes/divbast-abc/_data", Destination: "/data", RW: true}}
	if !slices.Equal(got.Mounts, want) {
		t.Errorf("Inspect().Mounts = %+v, want %+v", got.Mounts, want)
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

// TestInspectPorts reads the host address each published port is bound
// to. Docker 29 printed NetworkSettings.Ports as the docker case has it,
// for a container run with -p 127.0.0.1::8080 -p 8081 whose image exposes
// 8080 and 8081: one binding for an address given, one per address family
// for none, and null for a port exposed but not published.
//
// The podman case is the shape of Podman's define.InspectHostPort
// (libpod/define/container_inspect.go, v6.2.0), whose HostIp is "" for a
// port bound on every address. Podman 4.9 printed it so, since its
// makeInspectPorts (libpod/util.go) copied the address as given; from 5.0
// on Podman writes 0.0.0.0 there, as Docker does. An exposed port gets a
// nil binding (addInspectPortsExpose). Podman is not installed where this
// was written, so the shape is from the source, not a run.
func TestInspectPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, engine, ports string
		want                map[string]string
	}{
		{
			name:   "docker",
			engine: "docker",
			ports: `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"32768"}],` +
				`"8081/tcp":[{"HostIp":"0.0.0.0","HostPort":"32769"},{"HostIp":"::","HostPort":"32769"}]}`,
			want: map[string]string{"8080/tcp": "127.0.0.1:32768", "8081/tcp": "0.0.0.0:32769"},
		},
		{
			name:   "podman",
			engine: "podman",
			ports:  `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18290"}],"8081/tcp":[{"HostIp":"","HostPort":"18291"}],"9000/tcp":null}`,
			want:   map[string]string{"8080/tcp": "127.0.0.1:18290", "8081/tcp": "0.0.0.0:18291"},
		},
		{name: "exposed-not-published", engine: "docker", ports: `{"8080/tcp":null,"8081/tcp":[]}`, want: map[string]string{}},
		{name: "none-exposed", engine: "podman", ports: `{}`, want: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := `[{"State": {"Status": "running", "Running": true}, "NetworkSettings": {"Ports": ` + tt.ports + `}}]`
			c := &Container{ID: "abc", engine: newEngine(tt.engine, execx.NewFake(t,
				execx.Call{Argv: []string{tt.engine, "container", "inspect", "abc"}, Result: execx.Result{Stdout: []byte(out)}},
			))}
			got, err := c.Inspect(t.Context())
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			if !maps.Equal(got.Ports, tt.want) {
				t.Errorf("Inspect().Ports = %q, want %q", got.Ports, tt.want)
			}
		})
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
				"docker", "run", "--rm", "--label", ownLabel, "--name", "ctr",
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

// TestEngineHealthy shows EngineHealthy reading the engine's own verdict,
// on Podman as on Docker: it only ever inspects the container, and never
// runs the check itself, as podman healthcheck run would, so a Podman
// container is healthy only once the systemd timer that --health-cmd sets
// up has run the check on its own schedule.
func TestEngineHealthy(t *testing.T) {
	t.Parallel()

	for _, engine := range []string{"docker", "podman"} {
		inspect := []string{engine, "container", "inspect", "abc"}
		tests := []struct {
			name     string
			states   [][]byte
			wantText string
		}{
			{
				name: "healthy-once-the-engine-says-so",
				states: [][]byte{
					state("running", true, 0, startedAt, "starting"),
					state("running", true, 0, startedAt, "starting"),
					state("running", true, 0, startedAt, "healthy"),
				},
			},
			{
				// At once, with the checks the engine ran, rather than waiting
				// out the rest of the window.
				name:     "unhealthy-dumps-the-log",
				states:   [][]byte{state("running", true, 0, startedAt, "unhealthy")},
				wantText: engine + " reports container abc unhealthy; its checks:\n  exit 1: probe said no",
			},
			{
				name:     "no-health-check",
				states:   [][]byte{state("running", true, 0, startedAt, "")},
				wantText: engine + " reports no health check for container abc",
			},
			{
				// A container that stopped can never turn healthy.
				name:     "stopped",
				states:   [][]byte{state("exited", false, 3, startedAt, "starting")},
				wantText: "exited, exit status 3, before " + engine + " reported it healthy",
			},
		}
		for _, tt := range tests {
			t.Run(engine+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					calls := make([]execx.Call, 0, len(tt.states))
					for _, s := range tt.states {
						calls = append(calls, execx.Call{Argv: inspect, Result: execx.Result{Stdout: s}})
					}
					c := &Container{ID: "abc", started: time.Now(), engine: newEngine(engine, execx.NewFake(t, calls...))}

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
}

// healthState is `container inspect` output for a running container whose
// health check is status, run every interval as the engine says, or at
// the engine's default when interval is zero and the field is left out.
func healthState(status string, interval time.Duration) []byte {
	hc := ""
	if interval > 0 {
		hc = `, "Config": {"Healthcheck": {"Test": ["CMD", "/x"], "Interval": ` + strconv.FormatInt(int64(interval), 10) + `}}`
	}
	return []byte(`[{"State": {"Status": "running", "Running": true, "StartedAt": "` + startedAt +
		`", "Health": {"Status": "` + status + `", "Log": []}}` + hc + `}]`)
}

// TestEngineHealthyWindow shows how long EngineHealthy waits for a
// container the engine still calls starting: the start period it is
// given, counted from when the container started, and then three of the
// intervals the engine runs the check at, as the container's inspection
// gives them, or 30 s, both engines' default, when it gives none. By then
// a check that had passed would have been seen, and one that kept failing
// would have been retried as often as Docker's default and Podman's.
func TestEngineHealthyWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		engine      string
		startPeriod time.Duration
		interval    time.Duration // as inspect gives it; zero for none
		want        time.Duration
	}{
		{engine: "docker", startPeriod: time.Minute, interval: 30 * time.Second, want: 150 * time.Second},
		{engine: "docker", startPeriod: 10 * time.Second, interval: 2 * time.Second, want: 16 * time.Second},
		{engine: "podman", startPeriod: time.Minute, interval: 30 * time.Second, want: 150 * time.Second},
		{engine: "podman", startPeriod: 0, interval: 5 * time.Second, want: 15 * time.Second},
		{engine: "podman", startPeriod: 0, want: 90 * time.Second},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s+3x%s", tt.engine, tt.startPeriod, tt.interval), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				inspect := []string{tt.engine, "container", "inspect", "abc"}
				var others []string
				e := newEngine(tt.engine, runFunc(func(argv []string) execx.Result {
					if !slices.Equal(argv, inspect) {
						others = append(others, strings.Join(argv, " "))
						return execx.Result{Code: 125, Stderr: []byte("not scripted")}
					}
					return execx.Result{Stdout: healthState("starting", tt.interval)}
				}))
				// Started a little before EngineHealthy is called, as a container
				// is, and the window is counted from then.
				c := &Container{ID: "abc", started: time.Now(), engine: e}
				time.Sleep(3 * time.Second)

				err := c.EngineHealthy(t.Context(), tt.startPeriod)
				if waited := time.Since(c.started); waited != tt.want {
					t.Errorf("EngineHealthy() gave up %s after the container started, want %s", waited, tt.want)
				}
				if err == nil || !strings.Contains(err.Error(), "still starting") {
					t.Errorf("EngineHealthy() error = %v, want one saying it is still starting", err)
				}
				if len(others) > 0 {
					t.Errorf("EngineHealthy() ran %q, want nothing but %q", others, inspect)
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

// TestInstallProbeRetries installs the probe through an engine that
// refuses the exec, as Docker once did to a container still starting: the
// install rides on Exec's retry, which feeds the file again, and once the
// third attempt is refused too, the error says what was being installed.
func TestInstallProbeRetries(t *testing.T) {
	t.Parallel()

	install := execx.Call{
		Argv:  []string{"docker", "exec", "-i", "abc", "/usr/local/bin/frankenphp", "php-cli", "-r", installCode("/tmp/divbast-probe/core.php")},
		Stdin: coreProbe,
	}
	refused := install
	refused.Result = stoppedRefusal
	tests := []struct {
		name     string
		calls    []execx.Call
		wantText []string
	}{
		{
			name:  "engine-refused-then-installed",
			calls: []execx.Call{refused, install},
		},
		{
			name:     "engine-refuses-every-time",
			calls:    []execx.Call{refused, refused, refused},
			wantText: []string{"installing /tmp/divbast-probe/core.php", "attempt 3 of 3", "cannot exec in a stopped container"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, tt.calls...))}
				p, err := InstallProbe(t.Context(), c, nil)
				if len(tt.wantText) == 0 {
					if err != nil || p == nil {
						t.Errorf("InstallProbe() = %v, %v; want a probe", p, err)
					}
					return
				}
				for _, want := range tt.wantText {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Errorf("InstallProbe() = %v, %v; want an error containing %q", p, err, want)
					}
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
// by hand, a UDP socket that one does hold, at port 5353. The resolver's
// UDP port, 60327, sorts after it, so only the whole of what the parser
// printed shows it was left out.
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
		{
			name: "malformed-table", tcp: "proc-net-malformed", udp: "proc-net-udp6", wantCode: 1,
			want: "FAIL\tparse-listeners completed\tno exception\t" +
				"RuntimeException: testdata/proc-net-malformed has a line that is not a socket: this is not a socket\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := runPHP(t, "probe/core.php", "parse-listeners",
				filepath.Join("testdata", tt.tcp), filepath.Join("testdata", tt.udp), filepath.Join("testdata", "proc-net-fds"))
			if res.Code != tt.wantCode || string(res.Stdout) != tt.want {
				t.Errorf("parse-listeners = exit %d, stdout %q, stderr %q; want exit %d, stdout %q",
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
		{name: "user-takes-nothing", args: []string{"user", "65532"}, wantCode: 2, want: "user takes no arguments, got 1"},
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
