// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/divbast/ci/internal/testfixture"
)

// These tests run real containers from the LibreSpeed fixture, and the
// Serving tests from the contract suite's minimal one, under the engine
// $ENGINE names. CI runs them on both engines and both arches.

// pid1 is the fixture's server as its bootstrap hands over to it, with
// pcntl_exec(SERVER_BIN, ['run', '--config', CADDYFILE]), and as
// /proc/1/cmdline reads under the contract.
var pid1 = []string{"/usr/local/bin/frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"}

// healthCmd is the fixture's HEALTHCHECK, as a Podman user passes it.
var healthCmd = []string{"/usr/local/bin/frankenphp", "php-cli", "/usr/local/bin/librespeed-health"}

// integration returns the engine $ENGINE names, and skips t when it is
// unset.
func integration(t *testing.T) Engine {
	t.Helper()
	if os.Getenv("ENGINE") == "" {
		t.Skip("ENGINE is unset: set it to docker or podman to run containers")
	}
	e, err := EngineFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestSweepOnlyOwnLabel leaves behind, as three runs that died would, what
// each made under its module's label, then sweeps one of them: everything
// that one made goes, and nothing either of the others made does. One of
// the others is a module whose path starts with the swept one's, which a
// sweep matching a prefix, or the key alone, would take too.
//
// The modules are this test's own, under the harness's key: sweeping by
// the label of ci's own module would remove the containers of every test
// running beside it, in this package or the contract suite's.
func TestSweepOnlyOwnLabel(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	module := "example.com/sweep-" + strings.TrimPrefix(uniqueName(), "divbast-")
	swept, longer, other := e, e, e
	swept.label = labelFor(&debug.BuildInfo{Main: debug.Module{Path: module}}, true)
	longer.label = labelFor(&debug.BuildInfo{Main: debug.Module{Path: module + "/more"}}, true)
	other.label = labelFor(&debug.BuildInfo{Main: debug.Module{Path: "example.com/other-" + strings.TrimPrefix(uniqueName(), "divbast-")}}, true)
	engines := []Engine{swept, longer, other}

	// Each an image, and a running container of it that holds a network
	// and a volume, none of which can go before it does. Only the images
	// have cleanups of their own; the sweeps below are the rest's.
	containerfile := filepath.Join(t.TempDir(), "Containerfile")
	if err := os.WriteFile(containerfile, []byte("FROM "+testfixture.LibreSpeed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	images := make([]string, len(engines))
	for i, eng := range engines {
		image, err := eng.Build(ctx, t, containerfile, nil)
		if err != nil {
			t.Fatal(err)
		}
		images[i] = image
	}
	t.Cleanup(func() {
		sweepCtx, cancel := cleanupContext(ctx)
		defer cancel()
		for _, eng := range engines {
			if err := eng.Sweep(sweepCtx); err != nil {
				t.Errorf("sweeping up after the test: %v", err)
			}
		}
	})
	for i, eng := range engines {
		network, volume := uniqueName(), uniqueName()
		for _, args := range [][]string{
			{"network", "create", "--label", eng.label, network},
			{"volume", "create", "--label", eng.label, volume},
			eng.Argv(&RunSpec{
				Image:   images[i],
				Network: network,
				Confine: Contract("16m"),
				Mounts:  []Mount{{Source: volume, Target: "/data", Volume: true}},
			}),
		} {
			if _, err := eng.output(ctx, args...); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := swept.Sweep(ctx); err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}

	for _, eng := range engines {
		for _, list := range [][]string{{"ps", "-a", "-q"}, {"image", "ls", "-q"}, {"network", "ls", "-q"}, {"volume", "ls", "-q"}} {
			out, err := eng.output(ctx, append(list, "--filter", "label="+eng.label)...)
			if err != nil {
				t.Fatal(err)
			}
			left := strings.Fields(string(out))
			switch {
			case eng.label == swept.label && len(left) != 0:
				t.Errorf("after Sweep(), %s %s for %s lists %q, want nothing", e.name, strings.Join(list, " "), eng.label, left)
			case eng.label != swept.label && len(left) != 1:
				t.Errorf("after the sweep of %s, %s %s for %s lists %q, want the one it made", swept.label, e.name, strings.Join(list, " "), eng.label, left)
			}
		}
	}
}

// TestBuildBesideImageRemoval builds one image beside the removal of
// another, on Podman, as the parallel tests of a suite do (backlog
// CI-S3-1). store-race/second takes its first step from store-race/
// first's cache, then sleeps in its second, and store-race/first's image
// is removed meanwhile, by the cleanup Build gave it.
//
// Podman's image rm -f also removes each parent image it leaves dangling,
// and with -f, every container still using one: Buildah's build
// containers among them, so the second build lost its container and
// failed, as ci's own CI saw it fail. The harness keeps an image's
// removal from overlapping any build, so the second build ends as it
// would alone.
//
// Docker's builder keeps what a build uses out of reach of image rm, so
// the race is Podman's alone, and the test runs only there.
func TestBuildBesideImageRemoval(t *testing.T) {
	t.Parallel()
	e := integration(t)
	if e.name != "podman" {
		t.Skip("only Podman's image rm reaches into a build that is running")
	}
	ctx := t.Context()

	// The first build's cleanups run when this says, and not when the
	// test ends
	first := &cleanups{TB: t}
	t.Cleanup(first.run)
	if _, err := e.Build(ctx, first, filepath.Join("testdata", "store-race", "first", "Containerfile"), nil); err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() {
		_, err := e.Build(ctx, t, filepath.Join("testdata", "store-race", "second", "Containerfile"), nil)
		second <- err
	}()
	// Long enough for the second build to take its first step from the
	// cache and start the slow one, which takes 20 s
	if err := Pause(ctx, 8*time.Second); err != nil {
		t.Fatal(err)
	}
	first.run()
	if err := <-second; err != nil {
		t.Fatalf("the second build, while the first's image was removed: %v", err)
	}
}

// cleanups is a testing.TB whose cleanups run when the test calls run,
// rather than when the test ends.
type cleanups struct {
	testing.TB

	mu  sync.Mutex
	fns []func()
}

// Cleanup implements testing.TB.
func (c *cleanups) Cleanup(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fns = append(c.fns, f)
}

// run runs the cleanups registered so far, last first, each once.
func (c *cleanups) run() {
	c.mu.Lock()
	fns := c.fns
	c.fns = nil
	c.mu.Unlock()
	for _, f := range slices.Backward(fns) {
		f()
	}
}

func TestWaitExitOnFixture(t *testing.T) {
	t.Parallel()
	e := integration(t)

	t.Run("refuses-to-start", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		c, err := e.Start(ctx, t, &RunSpec{
			Image:   testfixture.LibreSpeed,
			Confine: Contract("16m"),
			Env:     map[string]string{"TRUSTED_PROXIES": "::/0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if code, err := c.WaitExit(ctx, 30*time.Second); err != nil || code != 1 {
			t.Errorf("WaitExit() = %d, %v; want 1, nil", code, err)
		}
		const reason = "TRUSTED_PROXIES holds '::/0'"
		if logs, err := c.Logs(ctx); err != nil || !strings.Contains(logs, reason) {
			t.Errorf("Logs() = %q, %v; want it to name the reason, %q", logs, err, reason)
		}
	})

	t.Run("still-running", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		c, err := e.Start(ctx, t, &RunSpec{Image: testfixture.LibreSpeed, Confine: Contract("16m")})
		if err != nil {
			t.Fatal(err)
		}
		if code, err := c.WaitExit(ctx, 2*time.Second); err == nil || !strings.Contains(err.Error(), "still running") {
			t.Errorf("WaitExit() = %d, %v; want an error saying it is still running", code, err)
		}
	})

	t.Run("never-started", func(t *testing.T) {
		t.Parallel()

		_, err := e.Start(t.Context(), t, &RunSpec{
			Image:      testfixture.LibreSpeed,
			Confine:    Contract("16m"),
			Entrypoint: []string{"/nonexistent"},
		})
		if !errors.Is(err, ErrNeverStarted) || errors.Is(err, ErrRefused) {
			t.Errorf("Start(entrypoint /nonexistent) error = %v, want ErrNeverStarted alone", err)
		}
	})

	// Runs the engine refuses before it makes a container at all, which
	// are not containers that never started.
	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		taken, err := e.Start(ctx, t, &RunSpec{Image: testfixture.LibreSpeed, Confine: Contract("16m")})
		if err != nil {
			t.Fatal(err)
		}
		// The container whose name a-name-in-use asks for is another's,
		// which that run never made, so its cleanup must leave it be. This
		// runs once every case below has ended and run its cleanups, and
		// before taken's own cleanup removes it.
		t.Cleanup(func() {
			inspectCtx, cancel := cleanupContext(ctx)
			defer cancel()
			if ins, ierr := taken.Inspect(inspectCtx); ierr != nil || !ins.State.Running {
				t.Errorf("container %s, whose name a refused run asked for: %+v, %v; want it still running", taken, ins.State, ierr)
			}
		})
		for _, tt := range []struct {
			name string
			spec RunSpec
		}{
			{name: "a-flag", spec: RunSpec{Image: testfixture.LibreSpeed, Extra: []string{"--no-such-flag"}}},
			// Nothing listens on port 1, so the pull fails at once.
			{name: "an-image-it-cannot-pull", spec: RunSpec{Image: "localhost:1/divbast/none:missing"}},
			{name: "a-name-in-use", spec: RunSpec{Image: testfixture.LibreSpeed, Name: taken.Name}},
		} {
			// Each a test of its own, whose cleanups run when it ends
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				tt.spec.Confine = Contract("16m")
				_, err := e.Start(t.Context(), t, &tt.spec)
				if !errors.Is(err, ErrRefused) || errors.Is(err, ErrNeverStarted) {
					t.Errorf("Start() error = %v, want ErrRefused alone", err)
				}
			})
		}
	})
}

// TestInspectPortsOnFixture publishes the app port to a host port the
// engine picks, and reads back where: the fixed host ports a suite would
// otherwise choose collide with any other suite on the host using them.
func TestInspectPortsOnFixture(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	c, _ := startServed(t, e, &RunSpec{
		Image:   testfixture.LibreSpeed,
		Confine: Contract("16m"),
		Publish: []string{"127.0.0.1::8080"},
	})
	ins, err := c.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	addr := ins.Ports["8080/tcp"]
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" || port == "" || port == "0" {
		t.Fatalf("Inspect().Ports = %q, want 8080/tcp at 127.0.0.1 and the port the engine picked", ins.Ports)
	}
	if got, published := ins.Ports["8081/tcp"]; published {
		t.Errorf("Inspect().Ports[8081/tcp] = %q, for a port the image exposes and the run did not publish", got)
	}

	// That address reaches the app from the host.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := HostClient().Do(req)
	if err != nil {
		t.Fatalf("GET / at %s, from the host: %v", addr, err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Error(cerr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / at %s, from the host: status %d, want 200", addr, resp.StatusCode)
	}

	// A port published on every address reads as 0.0.0.0 on either engine,
	// whatever address the engine itself wrote for it.
	all, err := e.Start(ctx, t, &RunSpec{Image: testfixture.LibreSpeed, Confine: Contract("16m"), Publish: []string{"8080"}})
	if err != nil {
		t.Fatal(err)
	}
	ins, err = all.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err = net.SplitHostPort(ins.Ports["8080/tcp"])
	if err != nil || host != "0.0.0.0" || port == "" || port == "0" {
		t.Errorf("Inspect().Ports = %q after -p 8080, want 8080/tcp at 0.0.0.0 and the port the engine picked", ins.Ports)
	}
}

// TestRestartSameContainer restarts a serving container in place, as a
// suite does to see an app come back up on the state it left: the same
// container, running again, with what it wrote to its volume. What the
// restart does to the tmpfs at /tmp and to a host port the engine picked
// is asserted exactly for each engine, as Restart's doc comment states it.
func TestRestartSameContainer(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	// The fixture's home directory is 65532's, and a new volume mounted on
	// it takes that owner, so the contract's user can write to it.
	volume, err := e.Volume(ctx, t, "")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := startServed(t, e, &RunSpec{
		Image:   testfixture.LibreSpeed,
		Confine: Contract("16m"),
		Mounts:  []Mount{{Source: volume, Target: "/home/nonroot", Volume: true}},
		Publish: []string{"127.0.0.1::8080"},
	})
	php := func(code string) string {
		t.Helper()
		res, execErr := c.Exec(ctx, nil, FrankenPHP, "php-cli", "-r", code)
		if execErr != nil {
			t.Fatal(execErr)
		}
		if res.Code != 0 {
			t.Fatalf("php-cli -r %q in container %s: exit status %d: %s", code, c, res.Code, combined(res))
		}
		return string(res.Stdout)
	}
	php(`foreach (["/home/nonroot/kept" => "volume", "/tmp/kept" => "tmpfs"] as $f => $s) {
    if (file_put_contents($f, $s) !== strlen($s)) { fwrite(STDERR, "cannot write $f\n"); exit(1); }
}`)
	before, err := c.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := c.ID

	if err = c.Restart(ctx); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}

	out, err := e.output(ctx, "container", "inspect", "--format", "{{.Id}}", c.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != id || c.ID != id {
		t.Errorf("after Restart(), %s names container %s and the harness %s; want the one restarted, %s", c.Name, got, c.ID, id)
	}
	after, err := c.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !after.State.Running {
		t.Fatalf("after Restart(), container %s is %s, exit status %d, want it running", c, after.State.Status, after.State.ExitCode)
	}
	if got := php(`echo file_get_contents("/home/nonroot/kept");`); got != "volume" {
		t.Errorf("after Restart(), the volume holds %q, want what was written to it, volume", got)
	}
	// A new, empty tmpfs on both engines: what was on /tmp, the probe
	// among it, is gone.
	if got := php(`var_export(file_exists("/tmp/kept"));`); got != "false" {
		t.Errorf("after Restart() on %s, /tmp/kept exists: %s; want false, the tmpfs a new one", e.Name(), got)
	}

	// Docker picks the host port again, and binds another; Podman picked
	// it once, when it made the container, and keeps it.
	was, now := before.Ports["8080/tcp"], after.Ports["8080/tcp"]
	host, port, err := net.SplitHostPort(now)
	if err != nil || host != "127.0.0.1" || port == "" || port == "0" {
		t.Fatalf("after Restart(), Inspect().Ports = %q, want 8080/tcp at 127.0.0.1 and a port the engine picked", after.Ports)
	}
	switch e.Name() {
	case "docker":
		if now == was {
			t.Errorf("after Restart() on docker, 8080/tcp is still at %s, want another port: Docker picks one again", was)
		}
	case "podman":
		if now != was {
			t.Errorf("after Restart() on podman, 8080/tcp moved from %s to %s, want it kept: Podman picked it when it made the container", was, now)
		}
	}

	// As a caller does after a restart: the probe installed again answers
	// on both ports, and the address Inspect now gives reaches the app.
	p, err := InstallProbe(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://127.0.0.1:8080/", "http://127.0.0.1:8081/healthz"} {
		if _, err = p.WaitHTTP(ctx, url, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+now+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := HostClient().Do(req)
	if err != nil {
		t.Fatalf("GET / at %s, from the host, after Restart(): %v", now, err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Error(cerr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / at %s, from the host, after Restart(): status %d, want 200", now, resp.StatusCode)
	}
}

// startServed starts spec, installs the probe, and waits until both of the
// contract's ports answer from inside the container.
func startServed(t *testing.T, e Engine, spec *RunSpec) (*Container, *Probe) {
	t.Helper()
	ctx := t.Context()
	c, err := e.Start(ctx, t, spec)
	if err != nil {
		t.Fatal(err)
	}
	p, err := InstallProbe(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://127.0.0.1:8080/", "http://127.0.0.1:8081/healthz"} {
		if _, err := p.WaitHTTP(ctx, url, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	return c, p
}

func TestProbeOnFixture(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	network, err := e.Network(ctx, t, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	c, p := startServed(t, e, &RunSpec{
		Image:     testfixture.LibreSpeed,
		Network:   network,
		Confine:   Contract("16m"),
		HealthCmd: healthCmd,
	})

	checks := NewChecks(t)
	for _, sub := range [][]string{
		{"assert-caps"},
		{"assert-no-shell"},
		{"assert-read-only"},
		slices.Concat([]string{"assert-pid1"}, pid1),
		{"assert-listeners", "8080", "8081"},
		{"probe-egress"},
	} {
		records, runErr := p.Run(ctx, sub[0], sub[1:]...)
		if runErr != nil {
			t.Error(runErr)
			continue
		}
		checks.Records(records)
	}

	ins, err := c.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	Equal(checks, "the container runs as uid/gid 65532", "65532:65532", ins.Config.User)
	checks.True("the container has an address on its internal network", ins.IP != "", ins.IP)

	// Inside an internal network too: the health check is the newest thing
	// in an image that could want a route out.
	var startPeriod time.Duration
	if hc := ins.Config.Healthcheck; hc != nil {
		startPeriod = hc.StartPeriod
	}
	detail := "healthy"
	if err := c.EngineHealthy(ctx, startPeriod); err != nil {
		detail = err.Error()
	}
	checks.True(e.Name()+" reports the container healthy, on an internal network", detail == "healthy", detail)
}

// TestProbeCapsArePID1s runs assert-caps in an exec the engine grants
// every capability, beside a server run under the contract with none: its
// records must be the server's, PID 1's, and so all ok. A probe that read
// its own process would find the exec's full bounding set.
func TestProbeCapsArePID1s(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	c, _ := startServed(t, e, &RunSpec{Image: testfixture.LibreSpeed, Confine: Contract("16m")})
	privileged := func(argv ...string) Result {
		t.Helper()
		res, err := e.run.RunStdin(ctx, nil, e.name, slices.Concat([]string{"exec", "--privileged", c.ID}, argv)...)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// That the exec holds a capability at all, or this shows nothing
	self := privileged(FrankenPHP, "php-cli", "-r", `echo file_get_contents('/proc/self/status');`)
	if !regexp.MustCompile(`(?m)^CapBnd:\s*0*[1-9a-f]`).Match(self.Stdout) {
		t.Fatalf("exec --privileged holds no capability, so it cannot tell PID 1's from its own: exit %d: %s",
			self.Code, combined(self))
	}

	res := privileged(FrankenPHP, "php-cli", path.Join(ProbeDir, "core.php"), "assert-caps")
	records, err := parseRecords(res.Stdout)
	if err != nil {
		t.Fatalf("assert-caps: %v: %s", err, combined(res))
	}
	if len(records) != 5 {
		t.Errorf("assert-caps made %d records, want one for each of the five sets: %+v", len(records), records)
	}
	for _, r := range records {
		if !r.OK {
			t.Errorf("%s: found %q, want PID 1's, %q", r.What, r.Found, r.Expected)
		}
	}
	if res.Code != 0 {
		t.Errorf("assert-caps exited %d, want 0: %s", res.Code, combined(res))
	}
}

// TestProbeNegative loosens one thing at a time, and the probe must catch
// each: a check never seen failing proves nothing. Each case names the
// record that must FAIL, and any that must stay ok, so a check that fails
// for some other reason, or a subcommand that crashed, does not count.
func TestProbeNegative(t *testing.T) {
	t.Parallel()
	e := integration(t)

	writable := Contract("16m")
	writable.ReadOnly = false

	tests := []struct {
		name string
		spec *RunSpec
		sub  []string
		fail string   // the record that must FAIL
		ok   []string // records that must stay ok
		// tries is how many runs of sub may be needed to see fail FAIL,
		// for a check whose one try can be inconclusive. Zero is one.
		tries int
		// asRoot is a command run beside the server, detached, as root.
		asRoot []string
	}{
		{
			// It reaches CapBnd alone: exec clears CapEff and CapPrm for
			// uid 65532 whatever the engine grants.
			name: "a-capability-added",
			spec: &RunSpec{Confine: Contract("16m"), Extra: []string{"--cap-add", "NET_RAW"}},
			sub:  []string{"assert-caps"},
			fail: "CapBnd, every capability bit clear",
		},
		{
			name: "an-init-as-pid-1",
			spec: &RunSpec{Confine: Contract("16m"), Extra: []string{"--init"}},
			sub:  slices.Concat([]string{"assert-pid1"}, pid1),
			fail: "PID 1 argv",
		},
		{
			// The right binary as PID 1, run with other arguments, as a
			// bootstrap that never handed over would leave it: only the
			// whole argv tells the two apart.
			name: "the-server-binary-with-another-argv",
			spec: &RunSpec{Confine: Contract("16m")},
			sub:  []string{"assert-pid1", "/usr/local/bin/frankenphp", "run", "--config", "/etc/frankenphp/Other"},
			fail: "PID 1 argv",
			ok:   []string{"PID 1 comm"},
		},
		{
			name: "a-writable-root",
			spec: &RunSpec{Confine: writable},
			sub:  []string{"assert-read-only"},
			fail: "writing /.divbast-write-probe fails because / is read-only",
		},
		{
			name: "a-listener-not-named",
			spec: &RunSpec{Confine: Contract("16m")},
			sub:  []string{"assert-listeners", "8080"},
			fail: "TCP ports a process in the container listens on",
			ok:   []string{"UDP ports a process in the container holds a socket on"},
		},
		{
			// A process of another user, which the probe, as the
			// container's own and with no capabilities, may not look into:
			// any socket it held would go uncounted.
			name:   "a-process-the-probe-cannot-look-into",
			spec:   &RunSpec{Confine: Contract("16m")},
			asRoot: []string{FrankenPHP, "php-cli", "-r", "sleep(600);"},
			sub:    []string{"assert-listeners", "8080", "8081"},
			fail:   "processes in the container whose descriptors the probe cannot read",
			ok:     []string{"TCP ports a process in the container listens on", "UDP ports a process in the container holds a socket on"},
		},
		{
			// The engine's default network, which has a route out. One
			// connect there can time out, through rootless slirp4netns
			// under load, which shows nothing either way: the case passes
			// once a try connects, and fails only if none of five does.
			// TestProbeOnFixture's check stays one try, since a refusal
			// and a timeout are both the success there.
			name:  "a-network-with-a-route-out",
			spec:  &RunSpec{Confine: Contract("16m")},
			sub:   []string{"probe-egress"},
			fail:  "outbound TCP to 9.9.9.9:443 is refused",
			tries: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.sub[0] == "probe-egress" {
				needEgress(t)
			}

			spec := *tt.spec
			spec.Image = testfixture.LibreSpeed
			c, p := startServed(t, e, &spec)
			if tt.asRoot != nil {
				if _, err := e.output(t.Context(), slices.Concat([]string{"exec", "-d", "-u", "0", c.ID}, tt.asRoot)...); err != nil {
					t.Fatal(err)
				}
			}
			tries := max(tt.tries, 1)
			var records []Record
			for try := 1; ; try++ {
				var err error
				records, err = p.Run(t.Context(), tt.sub[0], tt.sub[1:]...)
				if err != nil {
					t.Fatal(err)
				}
				if failed(records, tt.fail) || try == tries {
					break
				}
				t.Logf("try %d of %d: %s recorded %+v, which shows nothing; trying again", try, tries, tt.sub[0], records)
				if err := Pause(t.Context(), time.Second); err != nil {
					t.Fatal(err)
				}
			}

			byWhat := make(map[string]Record, len(records))
			for _, r := range records {
				// What main records for a subcommand that threw
				if strings.HasSuffix(r.What, " completed") {
					t.Errorf("%s crashed rather than checked: %+v", tt.sub[0], r)
				}
				byWhat[r.What] = r
			}
			if r, found := byWhat[tt.fail]; !found || r.OK {
				t.Errorf("%s recorded %+v, want %q among them, FAIL", tt.sub[0], records, tt.fail)
			}
			for _, what := range tt.ok {
				if r, found := byWhat[what]; !found || !r.OK {
					t.Errorf("%s recorded %+v, want %q among them, ok", tt.sub[0], records, what)
				}
			}
		})
	}
}

// failed reports whether records hold what, and it FAILed.
func failed(records []Record, what string) bool {
	return slices.ContainsFunc(records, func(r Record) bool { return r.What == what && !r.OK })
}

// needEgress skips t on a runner that cannot reach the egress probe's
// address itself, where no container could either. It dials once, for at
// most 3 seconds, before the positive control: that control shows the
// probe sees a route out, which a container has only where its host does,
// so a host without one skips it rather than failing it for the runner.
func needEgress(t *testing.T) {
	t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", "9.9.9.9:443")
	if err != nil {
		t.Skipf("this runner cannot reach 9.9.9.9:443 (%v), so no container on it could", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEngineUnhealthy(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	// A shell-form health check, which the engine runs as /bin/sh -c, and
	// which no image without /bin/sh can pass. It runs every 2 s, and one
	// failure past the start period is enough: Podman's start period is
	// none, so it reports the container unhealthy in seconds. Docker keeps
	// the image's minute, so it is still starting when the wait, 15 s and
	// three intervals, ends, with the checks it ran in its log.
	c, _ := startServed(t, e, &RunSpec{
		Image:   testfixture.LibreSpeed,
		Confine: Contract("16m"),
		Extra:   []string{"--health-cmd", "exit 0", "--health-interval", "2s", "--health-retries", "1"},
	})
	unhealthy := c.EngineHealthy(ctx, 15*time.Second)
	if unhealthy == nil {
		t.Fatal("EngineHealthy() = nil, want an error for a shell-form health check in an image with no shell")
	}
	t.Logf("EngineHealthy() error, as it should be: %v", unhealthy)

	// Unhealthy for want of the shell, and for nothing else, or this shows
	// nothing: the check the engine ran is the shell form, and the shell it
	// runs that with cannot be executed.
	ins, err := c.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hc := ins.Config.Healthcheck; hc == nil || len(hc.Test) == 0 || hc.Test[0] != "CMD-SHELL" {
		t.Fatalf("the container's health check is %+v, want the shell form, CMD-SHELL", hc)
	}
	// Run by hand, what the engine runs for it fails in the runtime's own
	// words. Podman's health log keeps only what a check printed, which is
	// nothing for one whose shell could not be executed.
	res, err := c.Exec(ctx, nil, "/bin/sh", "-c", "exit 0")
	if err != nil {
		t.Fatal(err)
	}
	if out := combined(res); (res.Code != 126 && res.Code != 127) || !strings.Contains(out, "/bin/sh") {
		t.Fatalf("/bin/sh -c 'exit 0' in the container: exit %d: %s; want 126 or 127, the runtime saying /bin/sh could not be executed", res.Code, out)
	}
	switch e.Name() {
	case "docker":
		// Docker's health log does keep the runtime's words, for each check.
		if !strings.Contains(unhealthy.Error(), "/bin/sh") {
			t.Fatalf("EngineHealthy() error = %v, want Docker's health log saying /bin/sh could not be run", unhealthy)
		}
	case "podman":
		// Its timer ran the check, which failed, and Podman called the
		// container unhealthy.
		if !strings.Contains(unhealthy.Error(), "podman reports container "+c.String()+" unhealthy") {
			t.Fatalf("EngineHealthy() error = %v, want Podman's own verdict, unhealthy", unhealthy)
		}
	}
}

// TestEngineHealthyWaitsForTimer has the engine judge two containers on
// its own schedule, as their users' engines would: Docker runs the image's
// HEALTHCHECK, and Podman the --health-cmd it was given, from the
// transient systemd timer it sets up for it, which runs only in a user
// session. Nothing here runs a check. The minimal fixture turns healthy
// within its start period and three intervals, and the engine's log shows
// the passing check it ran. The unhealthy mutant, whose probe exits 1 once
// its server is up, turns unhealthy within the same wait, past the start
// period in which no failure counts, and EngineHealthy says so as soon as
// the engine does.
func TestEngineHealthyWaitsForTimer(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	fixture := minimalFixture(t, e, false)
	unhealthy, err := e.Build(ctx, t, filepath.Join("..", "contract", "testdata", "mutants", "unhealthy", "Containerfile"),
		map[string]string{"FIXTURE": fixture})
	if err != nil {
		t.Fatal(err)
	}
	// The wait is bounded by the image's own start period, as the contract
	// bounds it.
	cfg, err := e.ImageConfig(ctx, t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Healthcheck == nil || cfg.Healthcheck.StartPeriod == 0 {
		t.Fatalf("the minimal fixture's HEALTHCHECK is %+v, want one with a start period", cfg.Healthcheck)
	}
	startPeriod := cfg.Healthcheck.StartPeriod

	for _, tt := range []struct {
		name, image string
		healthy     bool
	}{
		{name: "healthy", image: fixture, healthy: true},
		{name: "unhealthy", image: unhealthy},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			c, _ := startServed(t, e, &RunSpec{Image: tt.image, Confine: Contract("16m"), HealthCmd: minimalHealthCmd})
			waitErr := c.EngineHealthy(ctx, startPeriod)
			ins, err := c.Inspect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			h := ins.State.Health
			if h == nil {
				t.Fatalf("EngineHealthy() error = %v, and %s reports no health check for the container", waitErr, e.Name())
			}
			t.Logf("EngineHealthy() error = %v; %s reports it %s, failing streak %d%s", waitErr, e.Name(), h.Status, h.FailingStreak, h.logText())
			if tt.healthy {
				if waitErr != nil || h.Status != "healthy" {
					t.Fatalf("EngineHealthy() error = %v and the engine reports %s, want nil and healthy", waitErr, h.Status)
				}
				if !slices.ContainsFunc(h.Log, func(l HealthLog) bool { return l.ExitCode == 0 }) {
					t.Errorf("the engine logged no passing check: %+v", h.Log)
				}
				return
			}
			want := e.Name() + " reports container " + c.String() + " unhealthy"
			if waitErr == nil || !strings.Contains(waitErr.Error(), want) || h.Status != "unhealthy" {
				t.Fatalf("EngineHealthy() error = %v and the engine reports %s, want an error saying %q, and unhealthy", waitErr, h.Status, want)
			}
		})
	}
}

// minimalHealthCmd is the minimal fixture's health probe, as its
// HEALTHCHECK runs it and a Podman user passes it.
var minimalHealthCmd = []string{FrankenPHP, "php-cli", "/usr/local/bin/minimal-health"}

// minimalPage is exactly what the minimal fixture's GET / answers.
const minimalPage = "Hello from frankenphp\n"

// exitsSays is what the exits mutant writes to its log before it stops.
const exitsSays = "exits: stopping before it serves"

// minimalFixture builds the contract suite's minimal fixture for t, an
// image with nothing in it but a server and its health probe, and, when
// exits is set, the exits mutant FROM it, whose entrypoint stops before
// it ever serves, exit status 3, saying exitsSays.
func minimalFixture(t *testing.T, e Engine, exits bool) string {
	t.Helper()
	image, err := e.Build(t.Context(), t, filepath.Join("..", "contract", "testdata", "minimal", "Containerfile"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if exits {
		image, err = e.Build(t.Context(), t, filepath.Join("testdata", "exits", "Containerfile"), map[string]string{"FIXTURE": image})
		if err != nil {
			t.Fatal(err)
		}
	}
	return image
}

// minimalServe is image served as the minimal fixture is: under the
// contract, on both its ports.
func minimalServe(image string) ServeSpec {
	return ServeSpec{
		Run:        RunSpec{Image: image, Confine: Contract("16m"), HealthCmd: minimalHealthCmd},
		AppPort:    8080,
		HealthPort: 8081,
	}
}

// loopbackPort returns the port of base, failing t unless base is
// http://127.0.0.1:<port>, at a port the engine picked.
func loopbackPort(t *testing.T, what, base string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(base, "http://"))
	if err != nil || !strings.HasPrefix(base, "http://") || host != "127.0.0.1" || port == "" || port == "0" {
		t.Fatalf("%s = %q, want http://127.0.0.1:<the port the engine picked>", what, base)
	}
	return port
}

// TestServeEnginePickedPort serves the minimal fixture twice at once, on
// the same container ports, as two suites on one host would: each port
// is published on the host's loopback at a port the engine picked, so
// neither collides with the other, each container is on a network Serve
// made for it alone, and each answers from the host where Serve says, on
// its app port and its health port alike, with the probe installed. A
// spec with no HealthPort leaves the health port unpublished.
func TestServeEnginePickedPort(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()
	sp := minimalServe(minimalFixture(t, e, false))

	var served [2]*Serving
	for i := range served {
		s, err := e.Serve(ctx, t, &sp)
		if err != nil {
			t.Fatal(err)
		}
		served[i] = s
	}
	ports, networks := make(map[string]bool), make(map[string]bool)
	for _, s := range served {
		for _, base := range []string{s.Base, s.HealthBase} {
			port := loopbackPort(t, "Serve()'s Base or HealthBase", base)
			if ports[port] {
				t.Errorf("host port %s is published twice: two containers served at once collide", port)
			}
			ports[port] = true
		}

		out, err := e.output(ctx, "container", "inspect", "--format", "{{json .NetworkSettings.Networks}}", s.C.ID)
		if err != nil {
			t.Fatal(err)
		}
		var on map[string]json.RawMessage
		if err = json.Unmarshal(out, &on); err != nil {
			t.Fatalf("container %s's networks, %s: %v", s.C, out, err)
		}
		names := slices.Sorted(maps.Keys(on))
		if len(names) != 1 || !strings.HasPrefix(names[0], "divbast-") || networks[names[0]] {
			t.Errorf("container %s is on networks %q, want one network Serve made for it alone", s.C, names)
		}
		for _, n := range names {
			networks[n] = true
		}

		resp, err := s.Get(ctx, "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != http.StatusOK || string(resp.Body) != minimalPage {
			t.Errorf("GET / at %s, from the host = %d %q, want 200 %q", s.Base, resp.Status, resp.Body, minimalPage)
		}
		StatusIs(t, s.Health(), "GET /healthz on the health port, from the host", http.StatusOK, "/healthz")
		StatusIs(t, s, "GET /healthz on the app port, from the host", http.StatusNotFound, "/healthz")
		RunRecords(t, s.Probe, "assert-listeners", "8080", "8081")
	}

	// The container's own PHP, and a path PHP would read otherwise if it
	// interpolated: IsFile must look for the path exactly as written.
	c := served[0].C
	if out, err := PHPIn(ctx, c, `echo PHP_SAPI; file_put_contents("/tmp/it's \$HOME", "");`); err != nil || out != "cli" {
		t.Errorf("PHPIn() = %q, %v; want cli", out, err)
	}
	IsFile(t, c, "a path holding a quote and a dollar sign is present", "present", `/tmp/it's $HOME`)
	IsFile(t, c, "the image has no /bin/sh", "absent", "/bin/sh")

	unpublished := sp
	unpublished.HealthPort = 0
	s, err := e.Serve(ctx, t, &unpublished)
	if err != nil {
		t.Fatal(err)
	}
	loopbackPort(t, "Serve()'s Base", s.Base)
	ins, err := s.C.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, published := ins.Ports["8081/tcp"]; published || s.HealthBase != "" {
		t.Errorf("with HealthPort 0, HealthBase = %q and 8081/tcp is at %q; want it unpublished", s.HealthBase, got)
	}
	if resp, err := s.Health().Get(ctx, "/healthz", nil); err == nil || !strings.Contains(err.Error(), "the health port is unpublished") {
		t.Errorf("with HealthPort 0, Health().Get(/healthz) = %+v, %v; want an error saying the health port is unpublished", resp, err)
	}
}

// TestServeStoppedContainerCarriesLog serves the exits mutant, whose
// entrypoint stops before it serves: once at once, and once after three
// seconds, while Serve waits. Either way Serve fails as soon as it sees
// the container stopped, not after ServeWithin, with an error carrying
// the container's log, which says why. Which of Serve's checks sees the
// stop depends on how soon the engine does: on Docker, both cases have
// been seen to fail in Wait, the ports read while the container still
// ran. TestStartServingPortsMissing covers a container gone before its
// ports could be read.
func TestServeStoppedContainerCarriesLog(t *testing.T) {
	t.Parallel()
	e := integration(t)
	image := minimalFixture(t, e, true)

	for _, tt := range []struct{ name, afterMS string }{{"at-once", "0"}, {"while-waiting", "3000"}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sp := minimalServe(image)
			sp.Run.Env = map[string]string{"EXITS_AFTER_MS": tt.afterMS}

			start := time.Now()
			s, err := e.Serve(t.Context(), t, &sp)
			if err == nil {
				t.Fatalf("Serve() = %+v, nil; want an error, the container having stopped", s)
			}
			t.Logf("Serve() error, as it should be: %v", err)
			for _, want := range []string{"stopped, exit status 3", exitsSays} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Serve() error = %v, want it to hold %q", err, want)
				}
			}
			if waited := time.Since(start); waited >= ServeWithin {
				t.Errorf("Serve() took %s, want it to stop waiting once the container stopped", waited)
			}
		})
	}
}

// TestServingRestart restarts a serving container in place, as a suite
// does to see an app come back up on the state it left: the same
// container comes back, at the host ports the engine reports now, which
// Docker moves and Podman keeps, and serves there, with the probe, which
// went with the old tmpfs, installed again.
func TestServingRestart(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	sp := minimalServe(minimalFixture(t, e, false))
	s, err := e.Serve(ctx, t, &sp)
	if err != nil {
		t.Fatal(err)
	}
	id, base, probe := s.C.ID, s.Base, s.Probe
	before := s.Health()

	if err = s.Restart(ctx); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}
	if s.C.ID != id {
		t.Errorf("after Restart(), the container is %s, want the one restarted, %s", s.C.ID, id)
	}
	ins, err := s.C.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Base != "http://"+ins.Ports["8080/tcp"] || s.HealthBase != "http://"+ins.Ports["8081/tcp"] {
		t.Errorf("after Restart(), Base, HealthBase = %q, %q; want where the engine has the ports now, %q", s.Base, s.HealthBase, ins.Ports)
	}
	switch e.Name() {
	case "docker":
		if s.Base == base {
			t.Errorf("after Restart() on docker, Base is still %s, want another port: Docker picks one again", base)
		}
	case "podman":
		if s.Base != base {
			t.Errorf("after Restart() on podman, Base moved from %s to %s, want it kept", base, s.Base)
		}
	}
	StatusIs(t, s, "GET / after the restart, where the engine has the port now", http.StatusOK, "/")
	if s.Probe == nil || s.Probe == probe {
		t.Errorf("after Restart(), the probe is %p (was %p), want one installed again", s.Probe, probe)
	}
	RunRecords(t, s.Probe, "assert-read-only")

	// A health copy taken before the restart sends to the health port
	// where it is now, which Docker moved, and never to the app port:
	// / is the health port's 404, and the app port's 200.
	StatusIs(t, before, "GET /healthz through a health copy taken before the restart", http.StatusOK, "/healthz")
	StatusIs(t, before, "GET / through that copy is the health port's 404, not the app port's 200", http.StatusNotFound, "/")

	// Restarted through a health copy: the Serving it was taken from is
	// what restarts, and the copy still sends to the health port.
	h := s.Health()
	if err = h.Restart(ctx); err != nil {
		t.Fatalf("Health().Restart() error = %v", err)
	}
	StatusIs(t, h, "GET / through a health copy restarted through is the health port's 404", http.StatusNotFound, "/")
	StatusIs(t, h, "GET /healthz through that copy", http.StatusOK, "/healthz")
	StatusIs(t, s, "GET / on the app port, where it is after the restart through the copy", http.StatusOK, "/")
	RunRecords(t, s.Probe, "assert-read-only")
}

// TestRefuses runs the exits mutant, which stops before it serves, exit
// status 3, as a refusal: Refuses passes it when told to want 3, and
// fails a container that exits 0, one told to want another status, and
// one whose log does not say what it was asked for, each on the half it
// breaks, with why.
func TestRefuses(t *testing.T) {
	t.Parallel()
	e := integration(t)
	spec := RunSpec{Image: minimalFixture(t, e, true), Network: "none", Confine: Contract("16m")}
	logged := `its log: "` + exitsSays + `\n"`

	t.Run("refuses", func(t *testing.T) {
		t.Parallel()
		Refuses(t, e, &spec, 3, "the exits mutant", exitsSays)
	})
	t.Run("exits-0", func(t *testing.T) {
		t.Parallel()
		zero := spec
		zero.Entrypoint = []string{FrankenPHP, "php-cli", "-r", "fwrite(STDERR, '" + exitsSays + "' . PHP_EOL); exit(0);"}
		tb := &recTB{t: t}
		Refuses(tb, e, &zero, 3, "exits 0", exitsSays)
		recorded(t, tb,
			[]string{"ok   exits 0: the log says '" + exitsSays + `' (holds "` + exitsSays + `")`},
			[]string{"FAIL exits 0: the container exits: exit status 0, want 3; " + logged})
	})
	t.Run("another-exit", func(t *testing.T) {
		t.Parallel()
		tb := &recTB{t: t}
		Refuses(tb, e, &spec, 1, "wants 1", exitsSays)
		recorded(t, tb,
			[]string{"ok   wants 1: the log says '" + exitsSays + `' (holds "` + exitsSays + `")`},
			[]string{"FAIL wants 1: the container exits: exit status 3, want 1; " + logged})
	})
	t.Run("says-something-else", func(t *testing.T) {
		t.Parallel()
		tb := &recTB{t: t}
		Refuses(tb, e, &spec, 3, "something else", "TRUSTED_PROXIES")
		recorded(t, tb,
			[]string{"ok   something else: the container exits (exit status 3)"},
			[]string{`FAIL something else: the log says 'TRUSTED_PROXIES': "TRUSTED_PROXIES" is not in "` + exitsSays + `\n"`})
	})
}
