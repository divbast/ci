// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/divbast/ci/internal/testfixture"
)

// TestMain pulls the fixture the tests run containers of before any of
// them runs, and removes the probe volumes they made once all are done.
// ci's own suites never sweep, since a sweep would remove what the tests
// of another package, running beside these under the same label, made.
// With ENGINE unset it pulls nothing, and with no test that ran a
// container it removes nothing.
func TestMain(m *testing.M) {
	// A CI runner starts with an empty store, where every test that runs
	// a container of the fixture, or builds FROM it, would pull it at the
	// same moment, a dozen and more pulls of one image, and a server error
	// the registry gives any one of them fails its test. No test guards
	// this call: only a cold store shows what it saves.
	testfixture.PullBeforeTests("harness", testfixture.LibreSpeed)
	code := m.Run()
	if err := removeProbeVolumes(); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		code = max(code, 1)
	}
	os.Exit(code)
}

func removeProbeVolumes() error {
	e, err := EngineFromEnv()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	return e.RemoveProbeVolumes(ctx)
}
