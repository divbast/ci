// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

// TestTrivyIgnoresCallerEnvironment runs the real trivy convert, which
// needs no database, through the runner divbast-scan uses, with a
// TRIVY_ setting in the environment that would hide the fixture's one
// finding from the SARIF: a caller's mise.toml [env] reaches every later
// step of the scan job. The SARIF must still carry it.
func TestTrivyIgnoresCallerEnvironment(t *testing.T) {
	// Not parallel: it sets the environment
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Fatalf("trivy is not on PATH: %v", err)
	}
	t.Setenv("TRIVY_SEVERITY", "LOW")
	dir := t.TempDir()
	report, sarif := filepath.Join(dir, "report.json"), filepath.Join(dir, "report.sarif")
	if err := os.WriteFile(report, recorded(t, "trivy-librespeed.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (scan.Trivy{Run: tokenOnlyForGH{}}).SARIF(t.Context(), report, sarif); err != nil {
		t.Fatalf("SARIF() error = %v", err)
	}
	data, err := os.ReadFile(sarif) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CVE-2026-116587") {
		t.Error("the SARIF lacks CVE-2026-116587: trivy read TRIVY_SEVERITY from the environment")
	}
}

// TestTrivyReadsDHIByDebianVersion pins what the pinned Trivy makes of a
// Docker Hardened Image that says ID=dhi, the two facts the scan's guards
// stand on. Trivy has no analyser for ID=dhi and takes Debian from
// /etc/debian_version alone: with the file, the image reads as plain
// Debian, which only the model guard catches; without it, as "none",
// which the blind guard catches. A Trivy that reads it otherwise fails
// this, and the guards want a second look.
//
// A CycloneDX report needs no vulnerability database, so Trivy runs
// offline from an empty cache and downloads nothing.
func TestTrivyReadsDHIByDebianVersion(t *testing.T) {
	t.Parallel()
	trivy, err := exec.LookPath("trivy")
	if err != nil {
		t.Fatalf("trivy is not on PATH, and the scan's guards rest on how it reads an image: %v", err)
	}

	tests := []struct {
		name          string
		debianVersion bool
		wantOS        string
		wantVersion   string
	}{
		{name: "with-debian-version", debianVersion: true, wantOS: "debian", wantVersion: "13.2"},
		{name: "without-debian-version", wantOS: "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			files := map[string]string{
				"etc/os-release": dhiRelease,
				// One package, as DHI builds it, so the OS has something to show
				"var/lib/dpkg/status": "Package: coreutils\nStatus: install ok installed\nPriority: required\n" +
					"Section: utils\nArchitecture: arm64\nVersion: 9.7-3+dhi3\nDescription: core utilities\n\n",
			}
			if tt.debianVersion {
				files["etc/debian_version"] = "13.2\n"
			}
			for name, body := range files {
				p := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			sbom := filepath.Join(t.TempDir(), "sbom.json")
			trivyCache := execx.OS{Env: []string{"TRIVY_CACHE_DIR=" + t.TempDir()}}
			res, err := trivyCache.Run(t.Context(), trivy, "rootfs", "--format", "cyclonedx", "--offline-scan",
				"--skip-java-db-update", "--skip-version-check", "--quiet", "--output", sbom, root)
			if err != nil || res.Code != 0 {
				t.Fatalf("trivy rootfs: %v, exit %d: %s", err, res.Code, res.Stderr)
			}
			data, err := os.ReadFile(sbom) //nolint:gosec // G304: the test's own temporary file
			if err != nil {
				t.Fatal(err)
			}
			var bom struct {
				Components []struct{ Type, Name, Version string }
			}
			if err = json.Unmarshal(data, &bom); err != nil {
				t.Fatal(err)
			}
			var oses []string
			for _, c := range bom.Components {
				if c.Type == "operating-system" {
					oses = append(oses, c.Name+" "+c.Version)
				}
			}
			if want := tt.wantOS + " " + tt.wantVersion; len(oses) != 1 || oses[0] != want {
				t.Errorf("Trivy read the image as %q, want %q", oses, want)
			}
		})
	}
}
