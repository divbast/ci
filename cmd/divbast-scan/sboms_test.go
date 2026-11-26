// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

// The SBOM the tests' images declare, at the path internal/scan's
// recording of grype placed it, and the label value that declares it.
const (
	sbomPath = "usr/local/share/divbast/sbom.cdx.json"
	sbomAt   = "/" + sbomPath
)

// fixtureSBOM is internal/scan's sbom.cdx.json: unrar 6.11 by its CPE, and
// brotli 1.1.0-1 by its package URL. grype-sbom.json is grype's scan of it.
func fixtureSBOM(t *testing.T) []byte {
	t.Helper()
	return recorded(t, "sbom.cdx.json")
}

func TestDeclaredSBOMs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		labels  map[string]string
		want    []string
		wantErr []string
	}{
		{name: "no-labels"},
		{name: "other-labels", labels: map[string]string{lockfileLabel: lockLabel}},
		{name: "one", labels: map[string]string{sbomLabel: sbomAt}, want: []string{sbomPath}},
		{
			name:   "two-in-order",
			labels: map[string]string{sbomLabel: " /srv/b/tools.cdx.json ,/srv/a/codecs.cdx.json"},
			want:   []string{"srv/b/tools.cdx.json", "srv/a/codecs.cdx.json"},
		},
		{name: "empty", labels: map[string]string{sbomLabel: ""}, wantErr: []string{sbomLabel, "empty path"}},
		{name: "empty-entry", labels: map[string]string{sbomLabel: sbomAt + ","}, wantErr: []string{"empty path"}},
		{name: "relative", labels: map[string]string{sbomLabel: sbomPath}, wantErr: []string{`"` + sbomPath + `"`, "no clean absolute path"}},
		{
			name:    "unclean",
			labels:  map[string]string{sbomLabel: "/usr/local/../local/share/divbast/sbom.cdx.json"},
			wantErr: []string{"no clean absolute path"},
		},
		{
			name:    "not-cyclonedx-json",
			labels:  map[string]string{sbomLabel: "/usr/local/share/divbast/sbom.spdx.json"},
			wantErr: []string{"/usr/local/share/divbast/sbom.spdx.json", "CycloneDX JSON", ".cdx.json"},
		},
		{
			name:    "suffix-alone",
			labels:  map[string]string{sbomLabel: "/usr/local/share/divbast/.cdx.json"},
			wantErr: []string{"/usr/local/share/divbast/.cdx.json", ".cdx.json"},
		},
		{name: "twice", labels: map[string]string{sbomLabel: sbomAt + ", " + sbomAt}, wantErr: []string{sbomAt, "twice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := declaredSBOMs(tt.labels, "image")
			if tt.wantErr == nil {
				if err != nil || !slices.Equal(got, tt.want) {
					t.Errorf("declaredSBOMs() = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("declaredSBOMs() = %q, want an error", got)
			}
			for _, want := range append([]string{"image's " + sbomLabel}, tt.wantErr...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("declaredSBOMs() error %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestDeclaredAdvisorySBOMs(t *testing.T) {
	t.Parallel()
	const other = "/srv/a/codecs.cdx.json"
	both := sbomAt + "," + other
	tests := []struct {
		name    string
		labels  map[string]string
		want    map[string]bool
		wantErr []string
	}{
		{name: "no-label", labels: map[string]string{sbomLabel: sbomAt}},
		{name: "no-labels"},
		{
			name:   "one-in-both",
			labels: map[string]string{sbomLabel: sbomAt, advisoryLabel: sbomAt},
			want:   map[string]bool{sbomPath: true},
		},
		{
			name:   "one-of-two",
			labels: map[string]string{sbomLabel: both, advisoryLabel: " " + other},
			want:   map[string]bool{"srv/a/codecs.cdx.json": true},
		},
		{
			name:    "not-in-sboms",
			labels:  map[string]string{sbomLabel: sbomAt, advisoryLabel: other},
			wantErr: []string{other, "is not in its " + sbomLabel + " label"},
		},
		{
			name:    "no-sboms-label",
			labels:  map[string]string{advisoryLabel: sbomAt},
			wantErr: []string{sbomAt, "is not in its " + sbomLabel + " label"},
		},
		{
			name:    "empty-entry",
			labels:  map[string]string{sbomLabel: sbomAt, advisoryLabel: sbomAt + ","},
			wantErr: []string{"empty path"},
		},
		{
			name:    "relative",
			labels:  map[string]string{sbomLabel: sbomAt, advisoryLabel: sbomPath},
			wantErr: []string{`"` + sbomPath + `"`, "no clean absolute path"},
		},
		{
			name:    "unclean",
			labels:  map[string]string{sbomLabel: sbomAt, advisoryLabel: "/usr/local/../local/share/divbast/sbom.cdx.json"},
			wantErr: []string{"no clean absolute path"},
		},
		{
			name:    "twice",
			labels:  map[string]string{sbomLabel: sbomAt, advisoryLabel: sbomAt + ", " + sbomAt},
			wantErr: []string{sbomAt, "twice"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			paths, err := declaredSBOMs(tt.labels, "image")
			if err != nil && tt.wantErr == nil {
				t.Fatalf("declaredSBOMs() error %v", err)
			}
			var got map[string]bool
			if err == nil {
				got, err = declaredAdvisorySBOMs(tt.labels, "image", paths)
			}
			if tt.wantErr == nil {
				if err != nil || !maps.Equal(got, tt.want) {
					t.Errorf("declaredAdvisorySBOMs() = %v, %v; want %v", got, err, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("declaredAdvisorySBOMs() = %v, want an error", got)
			}
			for _, want := range append([]string{"image's " + advisoryLabel}, tt.wantErr...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("declaredAdvisorySBOMs() error %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// TestAdvisorySBOMHeld is the same new HIGH finding in two SBOMs of one
// image, the second marked advisory: the first blocks, the second is held
// and the verdict passes, whether or not the published image carries an
// SBOM.
func TestAdvisorySBOMHeld(t *testing.T) {
	t.Parallel()
	const bundle, tools = "opt/bundle/sbom.cdx.json", "usr/share/tools.cdx.json"
	in := func(where string) scan.Finding {
		return scan.Finding{ID: "CVE-2022-30333", Pkg: "unrar", Version: "6.11", Fixed: "6.12", Severity: "HIGH", Where: where}
	}
	advisory := map[string]bool{bundle: true}
	tests := []struct {
		name      string
		where     string
		uncarried bool
		wantHold  string
	}{
		{name: "advisory", where: bundle, wantHold: scan.AdvisorySBOM},
		{name: "not-advisory", where: tools},
		{name: "not-advisory-uncarried", where: tools, uncarried: true, wantHold: scan.UncarriedSBOM},
		// The mark is permanent, and an uncarried SBOM is a hold that ends
		{name: "advisory-uncarried", where: bundle, uncarried: true, wantHold: scan.AdvisorySBOM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := []scan.Finding{in(tt.where)}
			holdSBOMs(findings, advisory, tt.uncarried)
			if findings[0].Hold != tt.wantHold {
				t.Errorf("Hold = %q, want %q", findings[0].Hold, tt.wantHold)
			}
			split := scan.Compare(findings, nil, nil)
			if blocks := len(split.New) > 0; blocks != (tt.wantHold == "") {
				t.Errorf("Compare() = %+v, want it to block only without a hold", split)
			}
			if tt.wantHold == scan.AdvisorySBOM {
				if len(split.Held) != 1 {
					t.Errorf("Compare() = %+v, want the finding held", split)
				}
				if want := "1 new in an SBOM the image marks advisory, so listed, not blocking:\n"; !strings.Contains(scan.Listing("x", "new, so blocking", &split), want) {
					t.Errorf("Listing() lacks %q", want)
				}
			}
		})
	}
}

func TestReadSBOMs(t *testing.T) {
	t.Parallel()
	bom := func(components string) string {
		return `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + components + `]}`
	}
	const unrar = `{"type":"application","name":"unrar","version":"6.11","cpe":"cpe:2.3:a:rarlab:unrar:6.11:*:*:*:*:*:*:*"}`
	tests := []struct {
		name    string
		files   []imageFile
		wantErr []string
	}{
		{name: "absent", wantErr: []string{"holds no file there"}},
		{name: "symlink", files: []imageFile{{name: sbomPath, link: "../../../../srv/sbom.cdx.json"}}, wantErr: []string{"symlink", "declare the file itself"}},
		{name: "too-large", files: []imageFile{{name: sbomPath, body: strings.Repeat(" ", maxSBOM+1)}}, wantErr: []string{"16777217 bytes", "16777216"}},
		{name: "not-json", files: []imageFile{{name: sbomPath, body: "{"}}, wantErr: []string{"not CycloneDX JSON"}},
		{
			name:    "not-cyclonedx",
			files:   []imageFile{{name: sbomPath, body: `{"bomFormat":"SPDX","components":[` + unrar + `]}`}},
			wantErr: []string{"not CycloneDX JSON", `bomFormat "SPDX"`},
		},
		{name: "no-component", files: []imageFile{{name: sbomPath, body: bom("")}}, wantErr: []string{"names no component"}},
		{
			name:    "no-name",
			files:   []imageFile{{name: sbomPath, body: bom(`{"type":"application","version":"6.11","cpe":"cpe:2.3:a:rarlab:unrar:6.11:*:*:*:*:*:*:*"}`)}},
			wantErr: []string{"component 1", "no name"},
		},
		{
			name:    "no-version",
			files:   []imageFile{{name: sbomPath, body: bom(unrar + `,{"type":"application","name":"7-zip","cpe":"cpe:2.3:a:7-zip:7-zip:26.06:*:*:*:*:*:*:*"}`)}},
			wantErr: []string{"component 2, 7-zip", "no version"},
		},
		{
			name:    "no-identifier",
			files:   []imageFile{{name: sbomPath, body: bom(`{"type":"application","name":"unrar","version":"6.11"}`)}},
			wantErr: []string{"component 1, unrar 6.11", "neither a purl nor a cpe"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			layout := filepath.Join(t.TempDir(), "layout")
			writeImage(t, layout, dhiRelease, "arm64", map[string]string{sbomLabel: sbomAt}, tt.files...)
			got, err := readSBOMs(t.Context(), execx.OS{}, layout, "arm64", "image", []string{sbomPath})
			if err == nil {
				t.Fatalf("readSBOMs() = %+v, want an error", got)
			}
			// Every refusal names the image and the file
			for _, want := range append([]string{"image", sbomAt}, tt.wantErr...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("readSBOMs() error %q, want it to contain %q", err, want)
				}
			}
		})
	}

	t.Run("read", func(t *testing.T) {
		t.Parallel()
		layout := filepath.Join(t.TempDir(), "layout")
		writeImage(t, layout, dhiRelease, "arm64", map[string]string{sbomLabel: sbomAt}, imageFile{name: sbomPath, body: string(fixtureSBOM(t))})
		got, err := readSBOMs(t.Context(), execx.OS{}, layout, "arm64", "image", []string{sbomPath})
		if err != nil {
			t.Fatalf("readSBOMs() = %v", err)
		}
		want := []scan.Pkg{{Name: "unrar", Version: "6.11"}, {Name: "brotli", Version: "1.1.0-1"}}
		if !slices.Equal(got.paths, []string{sbomPath}) || !slices.Equal(got.components[sbomPath], want) ||
			!bytes.Equal(got.files[sbomPath], fixtureSBOM(t)) {
			t.Errorf("readSBOMs() = %+v, want %s with %v", got, sbomPath, want)
		}
	})

	t.Run("none-declared", func(t *testing.T) {
		t.Parallel()
		got, err := readSBOMs(t.Context(), execx.OS{}, filepath.Join(t.TempDir(), "no-layout"), "arm64", "image", nil)
		if err != nil || len(got.paths) > 0 {
			t.Errorf("readSBOMs() of none = %+v, %v; want nothing, read from nowhere", got, err)
		}
	})
}

// sarifURIsOf reads the SARIF at path: the location URIs of each result
// whose rule is rule.
func sarifURIsOf(t *testing.T, path, rule string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Runs []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct{ ArtifactLocation struct{ URI string } }
				}
			}
		}
	}
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	var uris []string
	for _, r := range s.Runs {
		for _, res := range r.Results {
			if res.RuleID == rule {
				for _, l := range res.Locations {
					uris = append(uris, l.PhysicalLocation.ArtifactLocation.URI)
				}
			}
		}
	}
	return uris
}

// TestSBOMFindingsJudged runs the scan of a DHI image that declares an
// SBOM, against each published image a finding in it can meet: one that
// carries the same SBOM, one that carries an older one, one that carries
// none, one whose own SBOM cannot be read, and none at all.
func TestSBOMFindingsJudged(t *testing.T) {
	t.Parallel()

	sbom, lock := fixtureSBOM(t), fixtureLock(t)
	dhiReport, dhiCDX, dhiSARIF := recorded(t, "grype-dhi.json"), recorded(t, "grype-dhi.cdx.json"), recorded(t, "grype-dhi.sarif")
	bomReport, bomCDX, bomSARIF := recorded(t, "grype-sbom.json"), recorded(t, "grype-sbom.cdx.json"), recorded(t, "grype-sbom.sarif")
	lockReport, lockCDX, lockSARIF := recorded(t, "grype-lockfile.json"), recorded(t, "grype-lockfile.cdx.json"), recorded(t, "grype-lockfile.sarif")
	probeHit := recorded(t, "grype-probe-dhi-13.json")
	index := &execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}
	refused := &execx.Result{Stderr: skopeoRecording(t, "skopeo-no-such-package.txt"), Code: 1}

	// The published SBOM, with unrar at 6.02, and grype's scan of it
	// without unrar's finding: the candidate's unrar finding is new
	olderSBOM := strings.ReplaceAll(string(sbom), "6.11", "6.02")
	pubNoUnrar, pubNoUnrarCDX := edited(t, bomReport, "CVE-2022-30333", bomCDX, "unrar", "6.02")
	// grype's CycloneDX of the candidate's SBOM without unrar: grype read
	// one of its two components
	_, missedUnrar := edited(t, bomReport, "", bomCDX, "unrar", "6.10")

	sbomLabelled := map[string]string{sbomLabel: sbomAt}
	both := map[string]string{sbomLabel: sbomAt, lockfileLabel: lockLabel}
	unrarLine := "  CVE-2022-30333 HIGH unrar 6.11, fixed in 6.12, " + sbomPath + "\n"
	tests := []struct {
		name string
		// labels are the candidate's, files beside its os-release; nil,
		// the SBOM's label and the SBOM.
		labels map[string]string
		files  []imageFile
		// pubLabels and pubFiles are the published image's; pubReport and
		// pubCDX grype's scan of its SBOM, nil for none.
		pubLabels         map[string]string
		pubFiles          []imageFile
		pubReport, pubCDX []byte
		candidateCDX      []byte
		skopeo            *execx.Result
		copied            bool
		lockfiles         bool
		wantCode          int
		wantStdout        []string
		notInStdout       []string
		wantStderr        []string
		notInStderr       []string
		wantSummary       []string
		wantSARIF         bool
	}{
		{
			// The published image carries the same SBOM: every finding in it
			// already published
			name:      "already-published",
			pubLabels: sbomLabelled, pubFiles: []imageFile{{name: sbomPath, body: string(sbom)}},
			pubReport: bomReport, pubCDX: bomCDX,
			skopeo: index, copied: true,
			wantStdout: []string{
				"declares " + sbomAt + " in its " + sbomLabel + " label, so grype scans them too\n",
				"already published, so advisory:",
				unrarLine,
				"nothing new against what is published (",
			},
			notInStdout: []string{"so listed, not blocking"},
			wantSARIF:   true,
		},
		{
			// The published SBOM had unrar at an older version, without the
			// finding: new, so blocking, named with its file
			name:      "new-blocks",
			pubLabels: sbomLabelled, pubFiles: []imageFile{{name: sbomPath, body: olderSBOM}},
			pubReport: pubNoUnrar, pubCDX: pubNoUnrarCDX,
			skopeo: index, copied: true,
			wantCode:    1,
			wantStdout:  []string{"1 new, so blocking:\n" + unrarLine},
			wantStderr:  []string{"1 finding(s) the published image does not have"},
			wantSummary: []string{"| [CVE-2022-30333](https://nvd.nist.gov/vuln/detail/CVE-2022-30333) | HIGH | `unrar` | 6.11 | 6.12 | " + sbomPath + " |"},
		},
		{
			// Until a published image carries an SBOM, none of its findings
			// blocks; brotli's are already published by the image's own scan
			name:   "published-carries-none",
			skopeo: index, copied: true,
			wantStdout: []string{
				digest + " carries no SBOM, so the findings in " + sbomAt + " are listed, not blocking, until a published image carries one",
				"0 new, so blocking:\n",
				"1 new in an SBOM the published image does not carry, so listed, not blocking:\n" + unrarLine,
				", 1 in SBOMs listed, not blocking)",
			},
			wantSummary: []string{"**New in an SBOM the published image does not carry, so listed, not blocking: 1**"},
		},
		{
			// The published image's SBOM is held to the candidate's rules,
			// and no error names the copy's temporary directory
			name:      "published-unreadable",
			pubLabels: sbomLabelled, pubFiles: []imageFile{{name: sbomPath, body: `{"bomFormat":"SPDX"}`}},
			skopeo: index, copied: true,
			wantCode: 1,
			wantStderr: []string{
				"could not tell which SBOMs " + digest + " carries",
				digest + " declares " + sbomAt + " in its " + sbomLabel + " label, but it is not CycloneDX JSON",
			},
			notInStderr: []string{"divbast-scan-declared-"},
		},
		{
			// Nothing published: every finding an advisory, and nothing copied
			name:   "nothing-published",
			skopeo: refused,
			wantStdout: []string{
				"advisory: nothing readable to compare with:",
				unrarLine,
			},
			notInStdout: []string{"published image does not carry"},
		},
		{
			// grype's CycloneDX must name every component the SBOM does
			name:         "grype-missed-a-component",
			candidateCDX: missedUnrar,
			wantCode:     1,
			wantStderr:   []string{"grype read 1 of the 2 components " + sbomAt + " names, so a clean scan of it would prove nothing"},
		},
		{
			// An image declaring a lockfile too: both are scanned, and the
			// published image is copied once for both
			name:   "with-a-lockfile",
			labels: both, files: []imageFile{{name: sbomPath, body: string(sbom)}, {name: lockPath, body: string(lock)}},
			pubLabels: both, pubFiles: []imageFile{{name: sbomPath, body: olderSBOM}, {name: lockPath, body: string(lock)}},
			pubReport: pubNoUnrar, pubCDX: pubNoUnrarCDX,
			skopeo: index, copied: true, lockfiles: true,
			wantCode: 1,
			wantStdout: []string{
				"declares " + lockLabel + " in its " + lockfileLabel + " label",
				"declares " + sbomAt + " in its " + sbomLabel + " label",
				"1 new, so blocking:\n" + unrarLine,
				// The published lockfile was scanned: its findings already published
				"already published, so advisory:",
				"  GHSA-xvch-5gv4-984h CRITICAL minimist 1.2.5, fixed in 1.2.6, " + lockPath + "\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := func(name string) string { return filepath.Join(dir, name) }
			tmp := p("tmp")
			if err := os.Mkdir(tmp, 0o700); err != nil {
				t.Fatal(err)
			}
			cache := p("cache")
			cfg := filepath.Join(cache, "grype.yaml")
			labels, extra := tt.labels, tt.files
			if labels == nil {
				labels, extra = sbomLabelled, []imageFile{{name: sbomPath, body: string(sbom)}}
			}
			writeImage(t, p("layout"), dhiRelease, "arm64", labels, extra...)

			candidateCDX := bomCDX
			if tt.candidateCDX != nil {
				candidateCDX = tt.candidateCDX
			}
			files := map[string][]byte{
				p("report.json"): dhiReport, p("report.json.cdx.json"): dhiCDX, p("report.sarif"): dhiSARIF,
				p("report.json.sboms.1.json"): bomReport, p("report.json.sboms.1.cdx.json"): candidateCDX,
				"{DIR}/candidate-sboms.1.sarif": bomSARIF,
				p("report.json.lockfiles.json"): lockReport, p("report.json.lockfiles.cdx.json"): lockCDX,
				"{DIR}/candidate.sarif": lockSARIF,
			}
			calls := []execx.Call{
				{Argv: []string{"grype", "-c", cfg, "db", "update"}},
				{Argv: []string{"grype", "-c", cfg, dhiProbe, "-o", "json"}, Result: execx.Result{Stdout: probeHit}},
				{Argv: []string{
					"grype", "-c", cfg, "oci-dir:" + p("layout"), "--platform", "linux/arm64",
					"-o", "json=" + p("report.json"), "-o", "cyclonedx-json=" + p("report.json.cdx.json"), "-o", "sarif=" + p("report.sarif"),
				}},
			}
			if tt.lockfiles {
				calls = append(calls, execx.Call{Argv: []string{
					"grype", "-c", cfg, "dir:{DIR}/candidate",
					"-o", "json=" + p("report.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("report.json.lockfiles.cdx.json"),
					"-o", "sarif={DIR}/candidate.sarif",
				}})
			}
			calls = append(calls, execx.Call{Argv: []string{
				"grype", "-c", cfg, "sbom:{DIR}/candidate-sboms/" + sbomPath,
				"-o", "json=" + p("report.json.sboms.1.json"), "-o", "cyclonedx-json=" + p("report.json.sboms.1.cdx.json"),
				"-o", "sarif={DIR}/candidate-sboms.1.sarif",
			}})
			if tt.skopeo != nil {
				calls = append(calls, execx.Call{Argv: skopeoArgv, Result: *tt.skopeo})
			}
			if tt.copied {
				calls = append(calls,
					execx.Call{Argv: []string{
						"grype", "-c", cfg, "registry:" + digest, "--platform", "linux/arm64",
						"-o", "json=" + p("baseline.json"), "-o", "cyclonedx-json=" + p("baseline.json.cdx.json"),
					}},
					execx.Call{Argv: copyArgv})
				files[p("baseline.json")], files[p("baseline.json.cdx.json")] = dhiReport, dhiCDX
			}
			if tt.lockfiles {
				calls = append(calls, execx.Call{Argv: []string{
					"grype", "-c", cfg, "dir:{DIR}/published",
					"-o", "json=" + p("baseline.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("baseline.json.lockfiles.cdx.json"),
				}})
				files[p("baseline.json.lockfiles.json")], files[p("baseline.json.lockfiles.cdx.json")] = lockReport, lockCDX
			}
			if tt.pubReport != nil {
				calls = append(calls, execx.Call{Argv: []string{
					"grype", "-c", cfg, "sbom:{DIR}/published-sboms/" + sbomPath,
					"-o", "json=" + p("baseline.json.sboms.1.json"), "-o", "cyclonedx-json=" + p("baseline.json.sboms.1.cdx.json"),
				}})
				files[p("baseline.json.sboms.1.json")], files[p("baseline.json.sboms.1.cdx.json")] = tt.pubReport, tt.pubCDX
			}
			runner := &lockRunner{
				t: t, fake: execx.NewFake(t, calls...), tmp: tmp, files: files, seen: map[string]string{},
				published: func(layout string) { writeImage(t, layout, dhiRelease, "arm64", tt.pubLabels, tt.pubFiles...) },
			}

			args := []string{
				"-layout", p("layout"), "-report", p("report.json"), "-published", published,
				"-baseline", p("baseline.json"), "-sarif", p("report.sarif"), "-cache", cache,
			}
			env := map[string]string{"GITHUB_STEP_SUMMARY": p("summary.md"), "TMPDIR": tmp}
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, runner, execx.OS{}, offline(t), func(key string) string { return env[key] }, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run() = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
				}
			}
			for _, not := range tt.notInStdout {
				if strings.Contains(stdout.String(), not) {
					t.Errorf("stdout = %q, want it not to contain %q", stdout.String(), not)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}
			for _, not := range tt.notInStderr {
				if strings.Contains(stderr.String(), not) {
					t.Errorf("stderr = %q, want it not to contain %q", stderr.String(), not)
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
			// grype read the SBOM itself, as the image ships it
			if got := runner.seen["sbom:{DIR}/candidate-sboms/"+sbomPath]; got != string(sbom) {
				t.Errorf("the candidate's SBOM scan read %d bytes, want the image's %d", len(got), len(sbom))
			}
			if tt.pubReport != nil {
				if got, want := runner.seen["sbom:{DIR}/published-sboms/"+sbomPath], tt.pubFiles[0].body; got != want {
					t.Errorf("the published SBOM scan read %q, want the published image's %q", got, want)
				}
			}
			// unrar's finding reaches code scanning in grype's run, at the
			// SBOM's path in the image
			if tt.wantSARIF {
				_, rules := sarifRuleIDs(t, p("report.sarif"))
				if !slices.Contains(rules, "CVE-2022-30333-unrar") {
					t.Errorf("SARIF rules %q, want CVE-2022-30333-unrar among them", rules)
				}
				if got := sarifURIsOf(t, p("report.sarif"), "CVE-2022-30333-unrar"); !slices.Equal(got, []string{sbomPath}) {
					t.Errorf("unrar's SARIF result is at %q, want %s", got, sbomPath)
				}
			}
			if left, err := os.ReadDir(tmp); err != nil || len(left) > 0 {
				t.Errorf("run() left %v in its TMPDIR (error %v), want nothing", left, err)
			}
		})
	}
}

// TestRunSBOMTrivy is an image Trivy scans, with an SBOM: grype, set up in
// -cache, scans the SBOM, and a new finding in it blocks.
func TestRunSBOMTrivy(t *testing.T) {
	t.Parallel()
	sbom := fixtureSBOM(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	tmp := p("tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := p("cache")
	cfg := filepath.Join(cache, "grype.yaml")
	labelled := map[string]string{sbomLabel: sbomAt}
	writeImage(t, p("layout"), debianRelease, "arm64", labelled, imageFile{name: sbomPath, body: string(sbom)})
	olderSBOM := strings.ReplaceAll(string(sbom), "6.11", "6.02")
	pubReport, pubCDX := edited(t, recorded(t, "grype-sbom.json"), "CVE-2022-30333", recorded(t, "grype-sbom.cdx.json"), "unrar", "6.02")

	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	trivySARIF := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"CVE-1"}]}},"results":[{"ruleId":"CVE-1"}]}]}`)
	files := map[string][]byte{
		p("report.json"):              []byte(report(t, "arm64", "", 3, "CVE-1")),
		p("report.sarif"):             trivySARIF,
		p("baseline.json"):            []byte(report(t, "arm64", digest, 3, "CVE-1")),
		p("report.json.sboms.1.json"): recorded(t, "grype-sbom.json"), p("report.json.sboms.1.cdx.json"): recorded(t, "grype-sbom.cdx.json"),
		"{DIR}/candidate-sboms.1.sarif": recorded(t, "grype-sbom.sarif"),
		p("baseline.json.sboms.1.json"): pubReport, p("baseline.json.sboms.1.cdx.json"): pubCDX,
	}
	calls := []execx.Call{
		{Argv: append(append([]string{"trivy", "image", "--input", p("layout")}, scanArgs...), "--output", p("report.json"))},
		{Argv: []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", p("report.sarif"), p("report.json")}},
		{Argv: []string{"grype", "-c", cfg, "db", "update"}},
		{Argv: []string{
			"grype", "-c", cfg, "sbom:{DIR}/candidate-sboms/" + sbomPath,
			"-o", "json=" + p("report.json.sboms.1.json"), "-o", "cyclonedx-json=" + p("report.json.sboms.1.cdx.json"),
			"-o", "sarif={DIR}/candidate-sboms.1.sarif",
		}},
		{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
		{Argv: append(append([]string{
			"trivy", "image", "--image-src", "remote", "--platform", "linux/arm64", "--skip-db-update",
		}, scanArgs...), "--output", p("baseline.json"), digest)},
		{Argv: copyArgv},
		{Argv: []string{
			"grype", "-c", cfg, "sbom:{DIR}/published-sboms/" + sbomPath,
			"-o", "json=" + p("baseline.json.sboms.1.json"), "-o", "cyclonedx-json=" + p("baseline.json.sboms.1.cdx.json"),
		}},
	}
	runner := &lockRunner{
		t: t, fake: execx.NewFake(t, calls...), tmp: tmp, files: files, seen: map[string]string{},
		published: func(layout string) {
			writeImage(t, layout, debianRelease, "arm64", labelled, imageFile{name: sbomPath, body: olderSBOM})
		},
	}
	args := []string{
		"-layout", p("layout"), "-report", p("report.json"), "-published", published,
		"-baseline", p("baseline.json"), "-sarif", p("report.sarif"), "-cache", cache,
	}
	env := map[string]string{"TMPDIR": tmp}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), args, runner, execx.OS{}, offline(t), func(key string) string { return env[key] }, &stdout, &stderr)
	if code != 1 {
		t.Errorf("run() = %d, want 1; stderr: %s", code, stderr.String())
	}
	if want := "1 new, so blocking:\n  CVE-2022-30333 HIGH unrar 6.11, fixed in 6.12, " + sbomPath + "\n"; !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
	}
	runs, rules := sarifRuleIDs(t, p("report.sarif"))
	if runs != 2 || !slices.Contains(rules, "CVE-1") || !slices.Contains(rules, "CVE-2022-30333-unrar") {
		t.Errorf("SARIF holds %d runs with rules %q; want Trivy's and grype's, each with its own", runs, rules)
	}
}

// TestRunAdvisorySBOM is TestRunSBOMTrivy with the SBOM marked advisory: the
// finding that blocked there is listed, in the report, the summary and the
// SARIF, and the run passes.
func TestRunAdvisorySBOM(t *testing.T) {
	t.Parallel()
	sbom := fixtureSBOM(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	tmp := p("tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := p("cache")
	cfg := filepath.Join(cache, "grype.yaml")
	labelled := map[string]string{sbomLabel: sbomAt, advisoryLabel: sbomAt}
	writeImage(t, p("layout"), debianRelease, "arm64", labelled, imageFile{name: sbomPath, body: string(sbom)})
	olderSBOM := strings.ReplaceAll(string(sbom), "6.11", "6.02")
	pubReport, pubCDX := edited(t, recorded(t, "grype-sbom.json"), "CVE-2022-30333", recorded(t, "grype-sbom.cdx.json"), "unrar", "6.02")

	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	trivySARIF := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"CVE-1"}]}},"results":[{"ruleId":"CVE-1"}]}]}`)
	files := map[string][]byte{
		p("report.json"):              []byte(report(t, "arm64", "", 3, "CVE-1")),
		p("report.sarif"):             trivySARIF,
		p("baseline.json"):            []byte(report(t, "arm64", digest, 3, "CVE-1")),
		p("report.json.sboms.1.json"): recorded(t, "grype-sbom.json"), p("report.json.sboms.1.cdx.json"): recorded(t, "grype-sbom.cdx.json"),
		"{DIR}/candidate-sboms.1.sarif": recorded(t, "grype-sbom.sarif"),
		p("baseline.json.sboms.1.json"): pubReport, p("baseline.json.sboms.1.cdx.json"): pubCDX,
	}
	calls := []execx.Call{
		{Argv: append(append([]string{"trivy", "image", "--input", p("layout")}, scanArgs...), "--output", p("report.json"))},
		{Argv: []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", p("report.sarif"), p("report.json")}},
		{Argv: []string{"grype", "-c", cfg, "db", "update"}},
		{Argv: []string{
			"grype", "-c", cfg, "sbom:{DIR}/candidate-sboms/" + sbomPath,
			"-o", "json=" + p("report.json.sboms.1.json"), "-o", "cyclonedx-json=" + p("report.json.sboms.1.cdx.json"),
			"-o", "sarif={DIR}/candidate-sboms.1.sarif",
		}},
		{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
		{Argv: append(append([]string{
			"trivy", "image", "--image-src", "remote", "--platform", "linux/arm64", "--skip-db-update",
		}, scanArgs...), "--output", p("baseline.json"), digest)},
		{Argv: copyArgv},
		{Argv: []string{
			"grype", "-c", cfg, "sbom:{DIR}/published-sboms/" + sbomPath,
			"-o", "json=" + p("baseline.json.sboms.1.json"), "-o", "cyclonedx-json=" + p("baseline.json.sboms.1.cdx.json"),
		}},
	}
	runner := &lockRunner{
		t: t, fake: execx.NewFake(t, calls...), tmp: tmp, files: files, seen: map[string]string{},
		published: func(layout string) {
			writeImage(t, layout, debianRelease, "arm64", labelled, imageFile{name: sbomPath, body: olderSBOM})
		},
	}
	args := []string{
		"-layout", p("layout"), "-report", p("report.json"), "-published", published,
		"-baseline", p("baseline.json"), "-sarif", p("report.sarif"), "-cache", cache,
	}
	env := map[string]string{"TMPDIR": tmp, "GITHUB_STEP_SUMMARY": p("summary.md")}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), args, runner, execx.OS{}, offline(t), func(key string) string { return env[key] }, &stdout, &stderr)
	if code != 0 {
		t.Errorf("run() = %d, want 0; stderr: %s", code, stderr.String())
	}
	unrar := "CVE-2022-30333 HIGH unrar 6.11, fixed in 6.12, " + sbomPath + "\n"
	for _, want := range []string{
		"0 new, so blocking:\n",
		"1 new in an SBOM the image marks advisory, so listed, not blocking:\n  " + unrar,
		", 1 in advisory SBOMs listed, not blocking)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
		}
	}
	summary, err := os.ReadFile(p("summary.md"))
	if err != nil || !strings.Contains(string(summary), "| `unrar` | 6.11 | 6.12 | "+sbomPath+" |") {
		t.Errorf("summary = %q (error %v), want it to name unrar", summary, err)
	}
	runs, rules := sarifRuleIDs(t, p("report.sarif"))
	if runs != 2 || !slices.Contains(rules, "CVE-1") || !slices.Contains(rules, "CVE-2022-30333-unrar") {
		t.Errorf("SARIF holds %d runs with rules %q; want Trivy's and grype's, each with its own", runs, rules)
	}
}

// TestRunSBOMRefusals is a candidate whose SBOM cannot be read: nothing is
// scanned, and no SARIF written.
func TestRunSBOMRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		label string
		files []imageFile
		want  []string
	}{
		{"not-cyclonedx-json", "/usr/local/share/divbast/sbom.spdx.json", nil, []string{"sbom.spdx.json", ".cdx.json"}},
		{"absent", sbomAt, nil, []string{"declares " + sbomAt, "holds no file there"}},
		{"no-identifier", sbomAt, []imageFile{{name: sbomPath, body: `{"bomFormat":"CycloneDX","components":[{"name":"unrar","version":"6.11"}]}`}}, []string{"neither a purl nor a cpe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := func(name string) string { return filepath.Join(dir, name) }
			writeImage(t, p("layout"), dhiRelease, "arm64", map[string]string{sbomLabel: tt.label}, tt.files...)
			args := []string{
				"-layout", p("layout"), "-report", p("report.json"), "-published", published,
				"-baseline", p("baseline.json"), "-sarif", p("report.sarif"), "-cache", p("cache"),
			}
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, execx.NewFake(t), execx.OS{}, offline(t), func(string) string { return "" }, &stdout, &stderr)
			if code != 1 {
				t.Errorf("run() = %d, want 1; stderr: %s", code, stderr.String())
			}
			for _, want := range tt.want {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}
			if _, err := os.Stat(p("report.sarif")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a SARIF was written though nothing was scanned: %v", err)
			}
		})
	}
}
