// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// probed has e mount volume as the probe volume for the image img, as an
// arm64 image, with the app probe app, as if it had made it already, so
// that Start makes nothing.
func probed(e Engine, app, volume string) {
	e.probes.mu.Lock()
	defer e.probes.mu.Unlock()
	e.probes.arches["img"] = "arm64"
	v := &probeVolume{done: make(chan struct{}), name: volume}
	close(v.done)
	e.probes.volumes[probeKey{engine: e.name, arch: "arm64", app: app}] = v
}

// volumeMaker answers what making a probe volume runs, as each command
// would succeed, with fill as the fill run's result, and counts each kind.
type volumeMaker struct {
	t    *testing.T
	fill execx.Result

	mu     sync.Mutex
	counts map[string]int
	builds [][]string // each go build's argv
}

func newVolumeMaker(t *testing.T, fill execx.Result) *volumeMaker {
	t.Helper()
	return &volumeMaker{t: t, fill: fill, counts: make(map[string]int)}
}

func (m *volumeMaker) count(kind string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[kind]
}

func (m *volumeMaker) run(argv []string) execx.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case slices.Equal(argv, []string{"go", "env", "GOMOD"}):
		m.counts["go env"]++
		return execx.Result{Stdout: []byte("/mod/go.mod\n")}
	case argv[0] == "env":
		m.counts["go build"]++
		m.builds = append(m.builds, argv)
		return execx.Result{}
	case argv[0] == "docker" && argv[1] == "build":
		m.counts["build"]++
		return execx.Result{}
	case argv[0] == "docker" && argv[1] == "volume" && argv[2] == "create":
		m.counts["volume create"]++
		if argv[3] != "--label" || argv[4] != ownLabel {
			m.t.Errorf("volume create %q carries no label of the module's", argv)
		}
		return execx.Result{}
	case argv[0] == "docker" && argv[1] == "run":
		m.counts["fill"]++
		return m.fill
	case argv[0] == "docker" && (argv[1] == "rm" || argv[1] == "image"):
		// A cleanup's
		return execx.Result{}
	default:
		m.t.Errorf("unexpected command %q", argv)
		return execx.Result{Code: 125}
	}
}

// TestProbeVolumeOnce asks for the probe volume from eight tests at
// once, as parallel tests do on first use: one build and one volume serve
// them all. Another app probe is another volume.
func TestProbeVolumeOnce(t *testing.T) {
	t.Parallel()

	m := newVolumeMaker(t, execx.Result{Stdout: []byte("present\n")})
	e := newEngine("docker", runFunc(m.run))

	var wg sync.WaitGroup
	names := make([]string, 8)
	for i := range names {
		wg.Go(func() {
			name, err := e.probeVolume(t.Context(), t, "arm64", "")
			if err != nil {
				t.Errorf("probeVolume() error = %v", err)
			}
			names[i] = name
		})
	}
	wg.Wait()
	for kind, want := range map[string]int{"go build": 1, "build": 1, "volume create": 1, "fill": 1} {
		if got := m.count(kind); got != want {
			t.Errorf("%d parallel first uses ran %s %d times, want %d", len(names), kind, got, want)
		}
	}
	if names[0] == "" || slices.ContainsFunc(names, func(n string) bool { return n != names[0] }) {
		t.Errorf("probeVolume() gave %q, want one volume for every caller", names)
	}
	if b := m.builds[0]; !slices.Equal(b[:6], []string{"env", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "go", "-C"}) ||
		b[6] != "/mod" || b[len(b)-1] != "github.com/divbast/ci/harness/probe/core" || !slices.Contains(b, "-trimpath") {
		t.Errorf("the core probe was built with %q, want a static linux/arm64 build of harness/probe/core in the module", b)
	}

	app, err := e.probeVolume(t.Context(), t, "arm64", "./test/probe")
	if err != nil {
		t.Fatal(err)
	}
	if app == names[0] {
		t.Errorf("an app probe got the core probe's volume, %s", app)
	}
	for kind, want := range map[string]int{"go build": 3, "build": 2, "volume create": 2, "fill": 2} {
		if got := m.count(kind); got != want {
			t.Errorf("after a second key, %s ran %d times, want %d", kind, got, want)
		}
	}
	if b := m.builds[2]; b[len(b)-1] != "./test/probe" || !strings.HasSuffix(b[len(b)-2], "/app") {
		t.Errorf("the app probe was built with %q, want ./test/probe built to app", b)
	}
}

func TestProbeVolumeEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fill execx.Result
		want []string
	}{
		{name: "absent", fill: execx.Result{Stdout: []byte("absent\n")}, want: []string{"the probe volume", "is empty"}},
		{
			name: "engine-refused",
			fill: execx.Result{Code: 125, Stderr: []byte("docker: Error response from daemon: volume copy-up is not supported\n")},
			want: []string{"the probe volume", "is empty", "volume copy-up is not supported"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := newVolumeMaker(t, tt.fill)
			e := newEngine("docker", runFunc(m.run))
			_, err := e.probeVolume(t.Context(), t, "amd64", "")
			for _, want := range tt.want {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("probeVolume() error = %v, want one saying %q", err, want)
				}
			}
			// Asked again, it is the same failure, not a second try
			if _, again := e.probeVolume(t.Context(), t, "amd64", ""); again == nil || m.count("fill") != 1 {
				t.Errorf("probeVolume() again = %v after %d fills; want the first failure, and no second fill", again, m.count("fill"))
			}
		})
	}
}

func TestProbeVolumeNoModule(t *testing.T) {
	t.Parallel()

	e := newEngine("docker", execx.NewFake(t, execx.Call{Argv: []string{"go", "env", "GOMOD"}, Result: execx.Result{Stdout: []byte("/dev/null\n")}}))
	if _, err := e.probeVolume(t.Context(), t, "arm64", ""); err == nil || !strings.Contains(err.Error(), "module") {
		t.Errorf("probeVolume() outside a module = %v; want an error saying it needs one", err)
	}
}

// TestRemoveProbeVolumes removes the probe volumes the process made, all
// in one command, and nothing for one that failed to be made. Removed,
// they are made again on next use.
func TestRemoveProbeVolumes(t *testing.T) {
	t.Parallel()

	e := newEngine("docker", execx.NewFake(t,
		execx.Call{Argv: []string{"docker", "volume", "rm", "probe-a", "probe-b"}},
	))
	probed(e, "", "probe-b")
	probed(e, "./test/probe", "probe-a")
	failed := &probeVolume{done: make(chan struct{}), err: errors.New("never made")}
	close(failed.done)
	e.probes.volumes[probeKey{engine: "docker", arch: "amd64"}] = failed

	if err := e.RemoveProbeVolumes(t.Context()); err != nil {
		t.Fatalf("RemoveProbeVolumes() error = %v", err)
	}
	if n := len(e.probes.volumes); n != 0 {
		t.Errorf("after RemoveProbeVolumes(), %d volumes are still known, want none", n)
	}
	if err := e.RemoveProbeVolumes(t.Context()); err != nil {
		t.Errorf("RemoveProbeVolumes() with none made = %v, want nothing to do", err)
	}
}

func TestRemoveProbeVolumesFails(t *testing.T) {
	t.Parallel()

	e := newEngine("docker", execx.NewFake(t, execx.Call{
		Argv:   []string{"docker", "volume", "rm", "probe-a"},
		Result: execx.Result{Code: 1, Stderr: []byte("Error response from daemon: remove probe-a: volume is in use\n")},
	}))
	probed(e, "", "probe-a")
	if err := e.RemoveProbeVolumes(t.Context()); err == nil || !strings.Contains(err.Error(), "volume is in use") {
		t.Errorf("RemoveProbeVolumes() = %v, want the engine's refusal", err)
	}
}
