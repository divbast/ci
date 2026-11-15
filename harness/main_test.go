// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// TestMain removes the probe volumes the tests made once they are done.
// ci's own suites never sweep, since a sweep would remove what the tests
// of another package, running beside these under the same label, made.
// With no test that ran a container, it runs nothing.
func TestMain(m *testing.M) {
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
