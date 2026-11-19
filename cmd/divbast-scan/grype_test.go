// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// writes answers as the real tools would, through a Fake that checks
// every argv: a call that succeeds writes, for each -o FORMAT=PATH or
// --output PATH it names, the content scripted for PATH.
type writes struct {
	fake  *execx.Fake
	files map[string][]byte
}

func (w writes) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	res, err := w.fake.Run(ctx, name, args...)
	if err != nil || res.Code != 0 {
		return res, err
	}
	for i := 0; i+1 < len(args); i++ {
		path := ""
		switch args[i] {
		case "-o":
			_, path, _ = strings.Cut(args[i+1], "=")
		case "--output":
			path = args[i+1]
		}
		if content, ok := w.files[path]; ok {
			if err := os.WriteFile(path, content, 0o600); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

const dhiProbe = "pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-13"

// edited is the Grype report in report with the match whose ID is drop
// left out, and the CycloneDX in cdx with each package named pkg at
// version.
func edited(t *testing.T, report []byte, drop string, cdx []byte, pkg, version string) (r, c []byte) {
	t.Helper()
	var rep map[string]any
	if err := json.Unmarshal(report, &rep); err != nil {
		t.Fatal(err)
	}
	matches, _ := rep["matches"].([]any)
	rep["matches"] = slices.DeleteFunc(slices.Clone(matches), func(m any) bool {
		v, _ := m.(map[string]any)["vulnerability"].(map[string]any)
		return v["id"] == drop
	})
	var bom map[string]any
	if err := json.Unmarshal(cdx, &bom); err != nil {
		t.Fatal(err)
	}
	components, _ := bom["components"].([]any)
	for _, comp := range components {
		if c, _ := comp.(map[string]any); c["name"] == pkg {
			c["version"] = version
		}
	}
	r, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if c, err = json.Marshal(bom); err != nil {
		t.Fatal(err)
	}
	return r, c
}

func TestRunGrype(t *testing.T) {
	t.Parallel()

	dhiReport, dhiCDX, dhiSARIF := recorded(t, "grype-dhi.json"), recorded(t, "grype-dhi.cdx.json"), recorded(t, "grype-dhi.sarif")
	debReport, debCDX := recorded(t, "grype-debian.json"), recorded(t, "grype-debian.cdx.json")
	index := &execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}
	refused := &execx.Result{Stderr: skopeoRecording(t, "skopeo-no-such-package.txt"), Code: 1}
	probeHit, probeMiss := recorded(t, "grype-probe-dhi-13.json"), recorded(t, "grype-probe-dhi-14.json")

	// The published image without the brotli finding, and shipping
	// brotli at an older version: the candidate's brotli finding is new
	pubNoBrotli, pubNoBrotliCDX := edited(t, dhiReport, "DHI-fwcj-m32u-e4uq-6hzy", dhiCDX, "brotli", "1.0.9-1")
	// Without the finding with no severity, and shipping qemu at an older
	// version: the candidate's is new, and listed
	pubNoUnknown, pubOldQemu := edited(t, dhiReport, "DHI-23nz-y4cq-6vsi-5jh5", dhiCDX, "qemu", "1:10.0.10+ds-0+deb13u1+dhi0")

	tests := []struct {
		name      string
		osRelease string
		// dbUpdate is how grype db update ends; nil, never run.
		dbUpdate *execx.Result
		// probe is grype's answer to the probe; nil, never asked.
		probe []byte
		// candidate, candidateCDX are the layout scan's outputs; nil, never run.
		candidate, candidateCDX []byte
		skopeo                  *execx.Result
		// baseline, baselineCDX are the published scan's; nil, never run.
		baseline, baselineCDX []byte
		wantCode              int
		wantStdout            []string
		wantStderr            []string
		wantSummary           []string
		// sarif is whether the SARIF must be there afterwards.
		sarif bool
	}{
		{
			name:     "routes-dhi-to-grype",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: dhiCDX,
			skopeo:   index,
			baseline: dhiReport, baselineCDX: dhiCDX,
			wantStdout: []string{"says ID=dhi", "grype", "nothing new against what is published (4 advisory)"},
			sarif:      true,
		},
		{
			// The published image from before Docker's cutover, read as
			// Debian, with every finding under another ID: the packages
			// are the same, so nothing is new
			name:     "first-switch-compare",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: dhiCDX,
			skopeo:   index,
			baseline: debReport, baselineCDX: debCDX,
			wantStdout: []string{"0 new, so blocking", "nothing new against what is published (4 advisory)"},
			sarif:      true,
		},
		{
			name:     "new-blocks",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: dhiCDX,
			skopeo:   index,
			baseline: pubNoBrotli, baselineCDX: pubNoBrotliCDX,
			wantCode:   1,
			wantStdout: []string{"1 new, so blocking:\n  DHI-fwcj-m32u-e4uq-6hzy HIGH brotli 1.1.0-1"},
			wantStderr: []string{"1 finding(s) the published image does not have"},
			sarif:      true,
		},
		{
			name:     "unknown-severity-listed",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: dhiCDX,
			skopeo:   index,
			baseline: pubNoUnknown, baselineCDX: pubOldQemu,
			wantStdout: []string{
				"0 new, so blocking:\n1 new with no severity, so listed, not blocking:\n  DHI-23nz-y4cq-6vsi-5jh5 UNKNOWN qemu",
				"nothing new against what is published (3 advisory, 1 listed with no severity)",
			},
			wantSummary: []string{"**New with no severity, so listed, not blocking: 1**"},
			sarif:       true,
		},
		{
			// Nothing published: every finding an advisory, and the probe
			// and the guards still ran
			name:     "first-publish-dhi",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: dhiCDX,
			skopeo:     refused,
			wantStdout: []string{"so all 4 finding(s) are advisory"},
			sarif:      true,
		},
		{
			name:     "guards-blind",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport,
			candidateCDX: []byte(`{"components":[{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"},
				{"type":"operating-system","name":"dhi","version":"13"}]}`),
			wantCode:   1,
			wantStderr: []string{"grype recognised dhi 13 but saw 0 OS packages"},
		},
		{
			name:     "guards-model-distro",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: debReport, candidateCDX: debCDX,
			wantCode:   1,
			wantStderr: []string{"ID=dhi", "debian 13.2", "the wrong model"},
		},
		{
			name:     "guards-model-purl",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: bytes.ReplaceAll(dhiCDX, []byte("pkg:deb/dhi/curl"), []byte("pkg:deb/debian/curl")),
			wantCode:   1,
			wantStderr: []string{"ID=dhi", "pkg:deb/debian/curl", "the wrong model"},
		},
		{
			name:     "guards-model-namespace",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate:    bytes.Replace(dhiReport, []byte(`"namespace": "dhi:distro:dhi:13"`), []byte(`"namespace": "debian:distro:debian:13"`), 1),
			candidateCDX: dhiCDX,
			wantCode:     1,
			wantStderr:   []string{"ID=dhi", "debian:distro:debian:13", "the wrong model"},
		},
		{
			name:     "probe-fails",
			dbUpdate: &execx.Result{}, probe: probeMiss,
			wantCode:   1,
			wantStderr: []string{dhiProbe, "grype db search --provider dhi --distro dhi-13"},
		},
		{
			name:       "no-probe-for-the-release",
			osRelease:  "ID=dhi\nID_LIKE=debian\nVERSION_ID=14\n",
			dbUpdate:   &execx.Result{},
			wantCode:   1,
			wantStderr: []string{"no probe", "ID_LIKE=debian", "VERSION_ID=14", "grype db search --provider dhi --distro dhi-14"},
		},
		{
			name:     "db-mismatch",
			dbUpdate: &execx.Result{}, probe: probeHit,
			candidate: dhiReport, candidateCDX: dhiCDX,
			skopeo:   index,
			baseline: bytes.ReplaceAll(dhiReport, []byte("2026-11-19T00:22:15Z"), []byte("2026-11-18T00:22:15Z")), baselineCDX: dhiCDX,
			wantCode:   1,
			wantStderr: []string{"different vulnerability databases"},
			// The candidate's SARIF is under the right model, and stays, as
			// when Trivy's published scan fails
			sarif: true,
		},
		{
			name:       "db-update-fails",
			dbUpdate:   &execx.Result{Stderr: []byte("ERROR no network\n"), Code: 1},
			wantCode:   1,
			wantStderr: []string{"could not update its vulnerability database", "no network"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := func(name string) string { return filepath.Join(dir, name) }
			cache := p("cache")
			cfg := filepath.Join(cache, "grype.yaml")
			release := tt.osRelease
			if release == "" {
				release = dhiRelease
			}
			writeLayoutFor(t, p("layout"), release, "arm64")

			files := map[string][]byte{}
			var calls []execx.Call
			if tt.dbUpdate != nil {
				calls = append(calls, execx.Call{Argv: []string{"grype", "-c", cfg, "db", "update"}, Result: *tt.dbUpdate})
			}
			if tt.probe != nil {
				calls = append(calls, execx.Call{Argv: []string{"grype", "-c", cfg, dhiProbe, "-o", "json"}, Result: execx.Result{Stdout: tt.probe}})
			}
			if tt.candidate != nil {
				calls = append(calls, execx.Call{Argv: []string{
					"grype", "-c", cfg, "oci-dir:" + p("layout"), "--platform", "linux/arm64",
					"-o", "json=" + p("report.json"), "-o", "cyclonedx-json=" + p("report.json.cdx.json"), "-o", "sarif=" + p("report.sarif"),
				}})
				files[p("report.json")], files[p("report.json.cdx.json")], files[p("report.sarif")] = tt.candidate, tt.candidateCDX, dhiSARIF
			}
			if tt.skopeo != nil {
				calls = append(calls, execx.Call{Argv: skopeoArgv, Result: *tt.skopeo})
			}
			if tt.baseline != nil {
				calls = append(calls, execx.Call{Argv: []string{
					"grype", "-c", cfg, "registry:" + published, "--platform", "linux/arm64",
					"-o", "json=" + p("baseline.json"), "-o", "cyclonedx-json=" + p("baseline.json.cdx.json"),
				}})
				files[p("baseline.json")], files[p("baseline.json.cdx.json")] = tt.baseline, tt.baselineCDX
			}

			args := []string{
				"-layout", p("layout"), "-report", p("report.json"), "-published", published,
				"-baseline", p("baseline.json"), "-sarif", p("report.sarif"), "-cache", cache,
			}
			env := map[string]string{"GITHUB_STEP_SUMMARY": p("summary.md")}
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, writes{execx.NewFake(t, calls...), files}, execx.OS{}, offline(t),
				func(key string) string { return env[key] }, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run() = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}
			if len(tt.wantSummary) > 0 {
				summary, err := os.ReadFile(p("summary.md"))
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range tt.wantSummary {
					if !strings.Contains(string(summary), want) {
						t.Errorf("summary = %q, want it to contain %q", summary, want)
					}
				}
			}
			// A refused scan leaves no SARIF behind, so code scanning, which
			// uploads one even from a failed scan, never sees the wrong model
			_, err := os.Stat(p("report.sarif"))
			switch {
			case tt.sarif && err != nil:
				t.Errorf("no SARIF after the scan: %v", err)
			case !tt.sarif && !errors.Is(err, fs.ErrNotExist):
				t.Errorf("a SARIF was left after the refusal: %v", err)
			}
		})
	}
}

func TestClearedEnv(t *testing.T) {
	t.Parallel()
	environ := []string{"PATH=/bin", "GRYPE_ONLY_FIXED=true", "TRIVY_SEVERITY=LOW", "GRYPE_DB_CACHE_DIR=/x", "MY_GRYPE_X=1"}
	if got := cleared("GRYPE_", environ); strings.Join(got, " ") != "GRYPE_ONLY_FIXED= GRYPE_DB_CACHE_DIR=" {
		t.Errorf(`cleared("GRYPE_") = %q`, got)
	}
	if got := cleared("TRIVY_", environ); strings.Join(got, " ") != "TRIVY_SEVERITY=" {
		t.Errorf(`cleared("TRIVY_") = %q`, got)
	}
}
