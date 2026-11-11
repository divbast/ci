// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/internal/testfixture"
)

// These tests run real containers from the LibreSpeed fixture, under the
// engine $ENGINE names. CI runs them on both engines and both arches.

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
