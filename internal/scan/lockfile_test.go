// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

// lockPath is where the lockfile in the recordings sat, under the root
// grype scanned, as the scan lists it.
const lockPath = "usr/share/doc/app/pnpm-lock.yaml"

func TestParseGrypeLockfile(t *testing.T) {
	t.Parallel()
	rep := parseGrype(t, "grype-lockfile.json", "grype-lockfile.cdx.json")
	want := []scan.Finding{
		{
			ID: "GHSA-35jh-r3h4-6jhm", Pkg: "lodash", Version: "4.17.20", Fixed: "4.17.21", Severity: "HIGH",
			URL: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", Where: lockPath,
			Aliases: []string{"CVE-2021-23337"}, Namespace: "github:language:javascript",
		},
		{
			ID: "GHSA-xvch-5gv4-984h", Pkg: "minimist", Version: "1.2.5", Fixed: "1.2.6", Severity: "CRITICAL",
			URL: "https://github.com/advisories/GHSA-xvch-5gv4-984h", Where: lockPath,
			Aliases: []string{"CVE-2021-44906"}, Namespace: "github:language:javascript",
		},
		{
			ID: "GHSA-r5fr-rjxr-66jc", Pkg: "lodash", Version: "4.17.20", Fixed: "4.18.0", Severity: "HIGH",
			URL: "https://github.com/advisories/GHSA-r5fr-rjxr-66jc", Where: lockPath,
			Aliases: []string{"CVE-2026-4800"}, Namespace: "github:language:javascript",
		},
	}
	if !sameFindings(rep.Findings, want) {
		t.Errorf("findings =\n%+v\nwant\n%+v", rep.Findings, want)
	}
	// Every package the lockfile holds, both of pnpm 12's documents, and
	// no OS
	if rep.Packages != 27 || rep.OSPackages != 0 || rep.OS != "" {
		t.Errorf("packages, OS packages, OS = %d, %d, %q; want 27, 0, none", rep.Packages, rep.OSPackages, rep.OS)
	}
	if want := map[string]int{lockPath: 27}; !maps.Equal(rep.PackagesIn, want) {
		t.Errorf("packages by file = %v, want %v", rep.PackagesIn, want)
	}
	if !slices.Contains(rep.Inventory, scan.Pkg{Name: "@pnpm/exe.linux-x64", Version: "12.14.0"}) {
		t.Errorf("inventory = %+v, want pnpm's platform binaries in it", rep.Inventory)
	}
}

func TestGrypeDir(t *testing.T) {
	t.Parallel()
	const cfg = "/ci/grype.yaml"
	dir := t.TempDir()
	report, cdx, sarif := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.cdx.json"), filepath.Join(dir, "r.sarif")
	fake := execx.NewFake(t,
		execx.Call{Argv: []string{
			"grype", "-c", cfg, "dir:/w/root",
			"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx, "-o", "sarif=" + sarif,
			"--vex", "openvex.json",
		}},
		execx.Call{Argv: []string{"grype", "-c", cfg, "dir:/w/published", "-o", "json=" + report, "-o", "cyclonedx-json=" + cdx}},
	)
	g := scan.Grype{Run: fake, VEX: []string{"openvex.json"}, Config: cfg}
	if err := g.Dir(t.Context(), "/w/root", report, cdx, sarif); err != nil {
		t.Fatalf("Dir() = %v", err)
	}
	g.VEX = nil
	if err := g.Dir(t.Context(), "/w/published", report, cdx, ""); err != nil {
		t.Fatalf("Dir() without a SARIF = %v", err)
	}
}

func TestCompareHolds(t *testing.T) {
	t.Parallel()
	dev := scan.Finding{ID: "GHSA-d", Pkg: "lodash", Version: "4.17.20", Severity: "HIGH", Where: lockPath, Hold: scan.BuildOnly}
	runtime := scan.Finding{ID: "GHSA-r", Pkg: "minimist", Version: "1.2.5", Severity: "CRITICAL", Where: lockPath}
	uncarried := scan.Finding{ID: "GHSA-u", Pkg: "react", Version: "18.3.1", Severity: "HIGH", Where: lockPath, Hold: scan.Uncarried}
	oldDev := scan.Finding{ID: "GHSA-o", Pkg: "debug", Version: "2.6.9", Severity: "HIGH", Where: lockPath, Hold: scan.BuildOnly}
	got := scan.Compare([]scan.Finding{dev, runtime, uncarried, oldDev}, []scan.Finding{oldDev}, nil)
	if !sameFindings(got.New, []scan.Finding{runtime}) || !sameFindings(got.Held, []scan.Finding{dev, uncarried}) ||
		!sameFindings(got.Old, []scan.Finding{oldDev}) || len(got.Listed) != 0 {
		t.Errorf("Compare() = %+v; want the runtime finding new, the two held, the published one old", got)
	}

	listing := scan.Listing("x", "new, so blocking", &got)
	for _, want := range []string{
		"1 new, so blocking:\n  GHSA-r CRITICAL minimist 1.2.5, no fix, " + lockPath + "\n",
		"1 new in a lockfile's build-only packages, so listed, not blocking:\n  GHSA-d HIGH lodash 4.17.20, no fix, " + lockPath + "\n",
		"1 new in a lockfile the published image does not carry, so listed, not blocking:\n  GHSA-u HIGH react 18.3.1",
		"1 already published, so advisory:\n  GHSA-o",
	} {
		if !strings.Contains(listing, want) {
			t.Errorf("Listing() = %q, want it to contain %q", listing, want)
		}
	}
	summary := scan.Summary("amd64", "x", "New, so blocking", "", &got)
	for _, want := range []string{
		"**New in a lockfile's build-only packages, so listed, not blocking: 1**\n\n| Vulnerability |",
		"| GHSA-d | HIGH | `lodash` | 4.17.20 | no fix | " + lockPath + " |",
		"**New in a lockfile the published image does not carry, so listed, not blocking: 1**",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("Summary() = %q, want it to contain %q", summary, want)
		}
	}
}

// runsOf reads the SARIF at path: each run's tool, and its results' and
// rules' IDs.
func runsOf(t *testing.T, path string) (tools []string, results, rules [][]string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []struct{ ID string }
				}
			}
			Results []struct{ RuleID string }
		}
	}
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Runs {
		tools = append(tools, r.Tool.Driver.Name)
		res, rul := make([]string, 0, len(r.Results)), make([]string, 0, len(r.Tool.Driver.Rules))
		for _, x := range r.Results {
			res = append(res, x.RuleID)
		}
		for _, x := range r.Tool.Driver.Rules {
			rul = append(rul, x.ID)
		}
		results, rules = append(results, res), append(rules, rul)
	}
	return tools, results, rules
}

func TestMergeSARIF(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Each as the scan leaves it: HIGH and CRITICAL alone
	image := write("image.sarif", readTestdata(t, "grype-dhi.sarif"))
	if err := (scan.Grype{}).SARIF(write("image.json", readTestdata(t, "grype-dhi.json")), image); err != nil {
		t.Fatal(err)
	}
	lock := write("lock.sarif", readTestdata(t, "grype-lockfile.sarif"))
	if err := (scan.Grype{}).SARIF(write("lock.json", readTestdata(t, "grype-lockfile.json")), lock); err != nil {
		t.Fatal(err)
	}
	if err := scan.MergeSARIF(image, lock); err != nil {
		t.Fatalf("MergeSARIF() = %v", err)
	}
	tools, results, rules := runsOf(t, image)
	// One run, as code scanning takes one per tool and category: the
	// lockfile's results after the image's, and lodash's GHSA-35jh rule,
	// which both have, once
	wantResults := []string{
		"DHI-mucl-alvq-4tv5-5ujl-qemu", "GHSA-35jh-r3h4-6jhm-lodash", "DHI-fwcj-m32u-e4uq-6hzy-brotli",
		"GHSA-35jh-r3h4-6jhm-lodash", "GHSA-xvch-5gv4-984h-minimist", "GHSA-r5fr-rjxr-66jc-lodash",
	}
	if !slices.Equal(tools, []string{"grype"}) || !slices.Equal(results[0], wantResults) {
		t.Errorf("merged SARIF runs %q with results %q; want one grype run with %q", tools, results, wantResults)
	}
	gotRules := slices.Sorted(slices.Values(rules[0]))
	wantRules := []string{
		"DHI-fwcj-m32u-e4uq-6hzy-brotli", "DHI-mucl-alvq-4tv5-5ujl-qemu", "GHSA-35jh-r3h4-6jhm-lodash",
		"GHSA-r5fr-rjxr-66jc-lodash", "GHSA-xvch-5gv4-984h-minimist",
	}
	if !slices.Equal(gotRules, wantRules) {
		t.Errorf("merged rules %q, want %q, each once", gotRules, wantRules)
	}

	// Into Trivy's SARIF, grype's run goes beside Trivy's, a tool of its
	// own
	trivy := write("trivy.sarif", []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"CVE-1"}]}},"results":[{"ruleId":"CVE-1"}]}]}`))
	if err := scan.MergeSARIF(trivy, lock); err != nil {
		t.Fatalf("MergeSARIF(Trivy's) = %v", err)
	}
	if tools, results, _ := runsOf(t, trivy); !slices.Equal(tools, []string{"Trivy", "grype"}) || len(results[1]) != 3 {
		t.Errorf("merged into Trivy's: runs %q, results %q; want Trivy's and grype's with its 3", tools, results)
	}

	if err := scan.MergeSARIF(write("bad.sarif", []byte("{")), lock); err == nil {
		t.Error("MergeSARIF() into a SARIF that is no JSON = nil, want an error")
	}
}

// TestMergeSARIFWritesArrays checks that runs with no rules or results,
// as grype writes them when it finds nothing, merge into runs that are
// still arrays all through.
func TestMergeSARIFWritesArrays(t *testing.T) {
	t.Parallel()
	const empty = `{"runs":[{"tool":{"driver":{"name":"grype","rules":null}},"results":null}]}`
	tests := []struct{ name, into, from string }{
		{"same tool, both null", empty, empty},
		{"same tool, no keys", `{"runs":[{"tool":{"driver":{"name":"grype"}}}]}`, `{"runs":[{"tool":{"driver":{"name":"grype"}}}]}`},
		{"other tool, null kept", `{"runs":[{"tool":{"driver":{"name":"Trivy","rules":null}},"results":null}]}`, empty},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			into, from := filepath.Join(dir, "into.sarif"), filepath.Join(dir, "from.sarif")
			for path, body := range map[string]string{into: tt.into, from: tt.from} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := scan.MergeSARIF(into, from); err != nil {
				t.Fatalf("MergeSARIF() = %v", err)
			}
			requireSARIFArrays(t, into)
		})
	}
}
