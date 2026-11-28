// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/divbast/ci/harness"
	"github.com/divbast/ci/internal/testfixture"
)

// TestMain pulls the fixtures the tests check before any of them runs,
// and removes the probe volumes they made once all are done. ci's own
// suites never sweep: each test removes what it made, and a CI runner
// starts empty. With ENGINE unset it pulls nothing, and with no test that
// ran a container it removes nothing.
func TestMain(m *testing.M) {
	// A CI runner starts with an empty store, where every test that checks
	// a fixture, or builds a mutant FROM it, would pull it at the same
	// moment, a dozen and more pulls of one image, and a server error the
	// registry gives any one of them fails its test. No test guards this
	// call: only a cold store shows what it saves.
	testfixture.PullBeforeTests("contract", testfixture.LibreSpeed, testfixture.Baikal)
	code := m.Run()
	if err := removeProbeVolumes(); err != nil {
		fmt.Fprintln(os.Stderr, "contract:", err)
		code = max(code, 1)
	}
	os.Exit(code)
}

func removeProbeVolumes() error {
	e, err := harness.EngineFromEnv()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return e.RemoveProbeVolumes(ctx)
}
