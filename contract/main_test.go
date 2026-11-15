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
)

// TestMain removes the probe volumes the tests made once they are done.
// ci's own suites never sweep, since a sweep would remove what the tests
// of another package, running beside these under the same label, made.
// With no test that ran a container, it runs nothing.
func TestMain(m *testing.M) {
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
