// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/divbast/ci/harness"
)

// minimalGoHealthCmd is the Go fixture's health probe, as its HEALTHCHECK
// runs it and as a Podman user passes it.
var minimalGoHealthCmd = []string{"/usr/local/bin/minimal", "health"}

// minimalGo is the contract of the Go fixture, testdata/minimal-go, for
// image: a static Go server on static-debian13, with no PHP, no shell and
// no bootstrap, and a Go app probe of its own beside the core one.
func minimalGo(image string) Config {
	return Config{
		Image:      image,
		AppPort:    8080,
		HealthPort: 8081,
		TmpfsSize:  "16m",
		PID1:       []string{"/usr/local/bin/minimal", "serve"},
		Exec:       []string{"/usr/local/bin/minimal", "version"},
		HealthCmd:  minimalGoHealthCmd,
		Healthcheck: Healthcheck{
			Test:        slices.Concat([]string{"CMD"}, minimalGoHealthCmd),
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			StartPeriod: 60 * time.Second,
			Retries:     3,
		},
		HealthOnly404: []string{"/"},
		AppProbe:      "./contract/internal/minimalgoprobe",
		// The app's own check, through its Go probe, before any other
		ReadyProbe: func(ctx context.Context, _ *harness.Container, p *harness.Probe) error {
			records, err := p.RunApp(ctx, "assert-page")
			if err != nil {
				return err
			}
			if len(records) != 1 || !records[0].OK {
				return fmt.Errorf("assert-page recorded %+v, want one ok record", records)
			}
			return nil
		},
	}
}

// TestContractMinimalGo builds the Go fixture and checks it passes every
// check, with nothing in the image but a static binary: no check may lean
// on PHP, a shell or any tool in the image. Its own Go probe runs as the
// contract waits for it to be ready.
func TestContractMinimalGo(t *testing.T) {
	t.Parallel()
	e := integration(t)

	fixture, err := e.Build(t.Context(), t, filepath.Join("testdata", "minimal-go", "Containerfile"), nil)
	if err != nil {
		t.Fatal(err)
	}
	extra := func(c *Config) { c.Env = map[string]string{"MINIMAL_EXTRA_PORT": "7070"} }
	for _, m := range []mutant{
		{name: "fixture"},
		{
			// A configuration with a listener past the two ports, which
			// it names
			name: "extra-port",
			config: func(c *Config) {
				extra(c)
				c.ExtraTCPPorts = []int{7070}
			},
		},
		{
			// The same listener, which the configuration does not name
			name: "extra-port-undeclared", config: extra,
			fails: []failure{{checkListeners, "TCP ports a process in the container listens on", []string{"7070"}}},
		},
	} {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			runMutant(t, e, fixture, minimalGo, &m)
		})
	}
}
