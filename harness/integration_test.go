// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/internal/testfixture"
)

// These tests run real containers from the LibreSpeed fixture, under the
// engine $ENGINE names. CI runs them on both engines and both arches.

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

func TestSweep(t *testing.T) {
	t.Parallel()
	e := integration(t)
	ctx := t.Context()

	// A label of this test's own: sweeping the harness's would remove the
	// containers of every test running beside it, in this package or any
	// other.
	e.label = "divbast.harness.sweep-test=" + strings.TrimPrefix(uniqueName(), "divbast-")
	t.Cleanup(func() {
		sweepCtx, cancel := cleanupContext(ctx)
		defer cancel()
		if err := e.Sweep(sweepCtx); err != nil {
			t.Errorf("sweeping up after the test: %v", err)
		}
	})

	// Left behind as a run that died would leave them, made with no cleanup
	// to remove them: a running container that holds a network and a
	// volume, which cannot go before it does.
	network, volume := uniqueName(), uniqueName()
	for _, args := range [][]string{
		{"network", "create", "--label", e.label, network},
		{"volume", "create", "--label", e.label, volume},
		e.Argv(&RunSpec{
			Image:   testfixture.LibreSpeed,
			Network: network,
			Confine: Contract("16m"),
			Mounts:  []Mount{{Source: volume, Target: "/data", Volume: true}},
		}),
	} {
		if _, err := e.output(ctx, args...); err != nil {
			t.Fatal(err)
		}
	}

	if err := e.Sweep(ctx); err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}

	for _, list := range [][]string{{"ps", "-a", "-q"}, {"network", "ls", "-q"}, {"volume", "ls", "-q"}} {
		out, err := e.output(ctx, append(list, "--filter", "label="+e.label)...)
		if err != nil {
			t.Fatal(err)
		}
		if left := strings.Fields(string(out)); len(left) != 0 {
			t.Errorf("after Sweep(), %s %s lists %q, want nothing", e.name, strings.Join(list, " "), left)
		}
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
		if !errors.Is(err, ErrNeverStarted) {
			t.Errorf("Start(entrypoint /nonexistent) error = %v, want ErrNeverStarted", err)
		}
	})
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
			_, p := startServed(t, e, &spec)
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
				if err := sleep(t.Context(), time.Second); err != nil {
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
// address itself, where no container could either.
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

	// A shell-form health check, which the engine runs as /bin/sh -c, and
	// which no image without /bin/sh can pass.
	c, _ := startServed(t, e, &RunSpec{
		Image:   testfixture.LibreSpeed,
		Confine: Contract("16m"),
		Extra:   []string{"--health-cmd", "exit 0"},
	})
	err := c.EngineHealthy(t.Context(), 15*time.Second)
	if err == nil {
		t.Fatal("EngineHealthy() = nil, want an error for a shell-form health check in an image with no shell")
	}
	t.Logf("EngineHealthy() error, as it should be: %v", err)
}
