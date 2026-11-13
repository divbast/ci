// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/divbast/ci/harness"
)

// minimalHealthCmd is the minimal fixture's health probe, as its
// HEALTHCHECK runs it and as a Podman user passes it.
var minimalHealthCmd = []string{harness.FrankenPHP, "php-cli", "/usr/local/bin/minimal-health"}

// minimal is the contract of the minimal fixture, testdata/minimal, for
// image: an app with no bootstrap, whose server is PID 1 straight from its
// ENTRYPOINT, and no volume, so /tmp is all it may write.
func minimal(image string) Config {
	return Config{
		Image:      image,
		AppPort:    8080,
		HealthPort: 8081,
		TmpfsSize:  "16m",
		PID1:       []string{harness.FrankenPHP, "run", "--config", "/etc/frankenphp/Caddyfile"},
		HealthCmd:  minimalHealthCmd,
		Healthcheck: Healthcheck{
			Test:        slices.Concat([]string{"CMD"}, minimalHealthCmd),
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			StartPeriod: 60 * time.Second,
			Retries:     3,
		},
		HealthOnly404: []string{"/", "/index.php"},
	}
}

// TestContractMinimal builds the minimal fixture, an image with nothing in
// it but what the contract needs, and checks it passes every check: a
// change to the contract that would fail an app with no bootstrap and no
// volume fails here, before any app sees it. Then it breaks the fixture
// one way at a time, as TestContractMutants breaks LibreSpeed, for the
// checks LibreSpeed has no mutant of.
func TestContractMinimal(t *testing.T) {
	t.Parallel()
	e := integration(t)

	fixture, err := e.Build(t.Context(), t, filepath.Join("testdata", "minimal", "Containerfile"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []mutant{
		{name: "fixture"},
		{
			// Docker and Podman both mount an anonymous volume where the
			// image declares one, writable, whatever the run asked for.
			name: "volume", dir: "volume",
			fails: []failure{
				{checkNoVolume, volumeRecord, []string{"/data"}},
				{checkNoVolume, mountsRecordWhat, []string{"volume /data"}},
			},
		},
		{
			// Not an image: a second tmpfs, writable, that the contract
			// does not grant
			name: "tmpfs", loosen: []string{"--tmpfs", "/run"},
			fails: []failure{{checkNoVolume, mountsRecordWhat, []string{"tmpfs /run"}}},
		},
		{
			// A capability the kernel lets run, which file-capability's
			// exec cannot see
			name: "filecap-permitted", dir: "filecap-permitted",
			fails: []failure{{checkNoFileCapabilityXattr, xattrRecord, []string{"/usr/local/bin/frankenphp"}}},
		},
	} {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			runMutant(t, e, fixture, minimal, &m)
		})
	}
}
