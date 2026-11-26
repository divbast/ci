// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

// grypeOutputs answers as the real grype would, through a Fake that
// checks every argv: a call that succeeds writes, for each -o FORMAT=PATH
// it names, the content scripted for FORMAT.
type grypeOutputs struct {
	fake    *execx.Fake
	outputs map[string][]byte
}

func (g grypeOutputs) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	res, err := g.fake.Run(ctx, name, args...)
	if err != nil || res.Code != 0 {
		return res, err
	}
	for i, a := range args {
		if a != "-o" || i+1 >= len(args) {
			continue
		}
		format, path, ok := strings.Cut(args[i+1], "=")
		if content, scripted := g.outputs[format]; ok && scripted {
			if err := os.WriteFile(path, content, 0o600); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// parseGrype reads the Grype report name and its CycloneDX cdx in testdata.
func parseGrype(t *testing.T, name, cdx string) scan.Report {
	t.Helper()
	rep, err := scan.ParseGrype(bytes.NewReader(readTestdata(t, name)), bytes.NewReader(readTestdata(t, cdx)))
	if err != nil {
		t.Fatalf("ParseGrype(%s, %s): %v", name, cdx, err)
	}
	return rep
}

func TestParseGrypeDHI(t *testing.T) {
	t.Parallel()
	rep := parseGrype(t, "grype-dhi.json", "grype-dhi.cdx.json")

	// Grype's order; MEDIUM and LOW dropped, and the finding with no
	// severity kept, as UNKNOWN, to be listed and never block
	want := []scan.Finding{
		{
			ID: "DHI-mucl-alvq-4tv5-5ujl", Pkg: "qemu", Version: "1:10.0.11+ds-0+deb13u1+dhi0", Severity: "CRITICAL",
			URL: "https://scout.docker.com/v/DHI-mucl-alvq-4tv5-5ujl", Where: "dhi package",
			Aliases: []string{"CVE-2019-12928"}, Namespace: "dhi:distro:dhi:13",
		},
		{
			ID: "GHSA-35jh-r3h4-6jhm", Pkg: "lodash", Version: "4.17.15", Fixed: "4.17.21", Severity: "HIGH",
			URL: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", Where: "app/node_modules/lodash/package.json",
			Aliases: []string{"CVE-2021-23337"}, Namespace: "github:language:javascript",
		},
		{
			ID: "DHI-fwcj-m32u-e4uq-6hzy", Pkg: "brotli", Version: "1.1.0-1", Fixed: "1.1.0-2+deb13u1+dhi1", Severity: "HIGH",
			URL: "https://scout.docker.com/v/DHI-fwcj-m32u-e4uq-6hzy", Where: "dhi package",
			Aliases: []string{"CVE-2025-6176"}, Namespace: "dhi:distro:dhi:13",
		},
		{
			ID: "DHI-23nz-y4cq-6vsi-5jh5", Pkg: "qemu", Version: "1:10.0.11+ds-0+deb13u1+dhi0", Severity: "UNKNOWN",
			URL: "https://scout.docker.com/v/DHI-23nz-y4cq-6vsi-5jh5", Where: "dhi package",
			Aliases: []string{"CVE-2026-61475"}, Namespace: "dhi:distro:dhi:13",
		},
	}
	if !sameFindings(rep.Findings, want) {
		t.Errorf("findings =\n%+v\nwant\n%+v", rep.Findings, want)
	}
	if rep.Family != "dhi" || rep.OS != "dhi 13" {
		t.Errorf("family, OS = %q, %q; want dhi, dhi 13", rep.Family, rep.OS)
	}
	if rep.Packages != 6 || rep.OSPackages != 5 {
		t.Errorf("packages, OS packages = %d, %d; want 6, 5: from the CycloneDX, which lists every package", rep.Packages, rep.OSPackages)
	}
	if rep.Arch != "arm64" {
		t.Errorf("arch = %q, want arm64", rep.Arch)
	}
	if !slices.Contains(rep.Inventory, scan.Pkg{Name: "qemu", Version: "1:10.0.11+ds-0+deb13u1+dhi0"}) ||
		!slices.Contains(rep.Inventory, scan.Pkg{Name: "lodash", Version: "4.17.15"}) || len(rep.Inventory) != 6 {
		t.Errorf("inventory = %+v, want the six packages", rep.Inventory)
	}
	if len(rep.OSPURLs) != 5 || !slices.Contains(rep.OSPURLs, "pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-13&upstream=brotli") {
		t.Errorf("OS PURLs = %q, want the five dpkg packages'", rep.OSPURLs)
	}
	if !strings.HasPrefix(rep.DB, "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-11-19T00:22:15Z_") {
		t.Errorf("DB = %q, want the database the report names", rep.DB)
	}
	if !slices.Contains(rep.Providers, "dhi") || !slices.Contains(rep.Providers, "debian") {
		t.Errorf("providers = %q, want dhi and debian among them", rep.Providers)
	}
}

func TestParseGrypeDebian(t *testing.T) {
	t.Parallel()
	rep := parseGrype(t, "grype-debian.json", "grype-debian.cdx.json")
	if rep.Family != "debian" || rep.OS != "debian 13.2" {
		t.Errorf("family, OS = %q, %q; want debian, debian 13.2", rep.Family, rep.OS)
	}
	if len(rep.Findings) != 5 {
		t.Fatalf("findings = %d, want 5", len(rep.Findings))
	}
	for _, f := range rep.Findings {
		if f.Namespace == "" || f.Where == "" {
			t.Errorf("finding %+v lacks its namespace or where", f)
		}
	}
	if len(rep.OSPURLs) != 5 || !strings.HasPrefix(rep.OSPURLs[0], "pkg:deb/debian/") {
		t.Errorf("OS PURLs = %q, want Debian's", rep.OSPURLs)
	}
}

func TestParseGrypeNoPackages(t *testing.T) {
	t.Parallel()
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"container","name":"layout"}},
		"components":[{"type":"operating-system","name":"dhi","version":"13"}]}`
	rep, err := scan.ParseGrype(strings.NewReader(`{"matches":[],"distro":{"name":"dhi","version":"13"}}`), strings.NewReader(cdx))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Packages != 0 || rep.OSPackages != 0 || rep.OS != "dhi 13" {
		t.Errorf("packages, OS packages, OS = %d, %d, %q; want 0, 0, dhi 13", rep.Packages, rep.OSPackages, rep.OS)
	}
}

func TestParseGrypeRejects(t *testing.T) {
	t.Parallel()
	good := string(readTestdata(t, "grype-dhi.cdx.json"))
	for name, in := range map[string][2]string{
		"report-not-json": {"{", good},
		"cdx-not-json":    {`{"matches":[]}`, "{"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := scan.ParseGrype(strings.NewReader(in[0]), strings.NewReader(in[1])); err == nil {
				t.Error("ParseGrype() error = nil, want one")
			}
		})
	}
}

func TestGrypeWriteConfig(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, err := scan.Grype{}.WriteConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(cfg) != dir {
		t.Errorf("config at %s, want it in %s", cfg, dir)
	}
	data, err := os.ReadFile(cfg) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"check-for-app-update: false\n",
		"  auto-update: false\n",
		"  require-update-check: false\n",
		"  cache-dir: " + jsonString(t, filepath.Join(dir, "db")) + "\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("config =\n%s\nwant it to hold %q", data, want)
		}
	}
}

// jsonString is s as a JSON string, which YAML reads as the same string.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGrypeArgs(t *testing.T) {
	t.Parallel()
	const cfg = "/ci/grype.yaml"
	dir := t.TempDir()
	report, cdx, sarif := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.cdx.json"), filepath.Join(dir, "r.sarif")
	outputs := map[string][]byte{
		"json":           readTestdata(t, "grype-dhi.json"),
		"cyclonedx-json": readTestdata(t, "grype-dhi.cdx.json"),
		"sarif":          readTestdata(t, "grype-dhi.sarif"),
	}
	fake := execx.NewFake(t,
		execx.Call{Argv: []string{"grype", "-c", cfg, "db", "update"}},
		execx.Call{Argv: []string{
			"grype", "-c", cfg, "oci-dir:/w/layout", "--platform", "linux/arm64",
			"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx, "-o", "sarif=" + sarif,
			"--vex", "openvex.json", "--vex", "/tmp/v/dhi-aspnetcore.vex.json",
		}},
		execx.Call{Argv: []string{
			"grype", "-c", cfg, "registry:ghcr.io/divbast/prowlarr:latest", "--platform", "linux/arm64",
			"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx,
			"--vex", "openvex.json", "--vex", "/tmp/v/dhi-aspnetcore.vex.json",
		}},
	)
	g := scan.Grype{Run: grypeOutputs{fake, outputs}, VEX: []string{"openvex.json", "/tmp/v/dhi-aspnetcore.vex.json"}, Config: cfg}
	if err := g.UpdateDB(t.Context()); err != nil {
		t.Fatalf("UpdateDB() = %v", err)
	}
	if err := g.Layout(t.Context(), "/w/layout", "arm64", report, cdx, sarif); err != nil {
		t.Fatalf("Layout() = %v", err)
	}
	if err := g.Published(t.Context(), "ghcr.io/divbast/prowlarr:latest", "arm64", report, cdx); err != nil {
		t.Fatalf("Published() = %v", err)
	}
}

// TestGrypeIgnoresCallerConfig is a working directory holding a caller's
// .grype.yaml, which Grype reads unless given a configuration: every call
// names ci's own, so the caller's is never read. A local run with the real
// grype is in the ledger: the caller's file hid a finding without -c, and
// none with it.
func TestGrypeIgnoresCallerConfig(t *testing.T) {
	// Not parallel: it changes the working directory
	probe := readTestdata(t, "grype-probe-dhi-13.json")
	caller := t.TempDir()
	if err := os.WriteFile(filepath.Join(caller, ".grype.yaml"), []byte("ignore:\n  - vulnerability: DHI-fwcj-m32u-e4uq-6hzy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(caller)
	cfg := filepath.Join(t.TempDir(), "grype.yaml")
	fake := execx.NewFake(t,
		execx.Call{
			Argv:   []string{"grype", "-c", cfg, "pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-13", "-o", "json"},
			Result: execx.Result{Stdout: probe},
		},
	)
	g := scan.Grype{Run: fake, Config: cfg}
	if err := g.Probe(t.Context(), "pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-13", "dhi:distro:dhi:13"); err != nil {
		t.Errorf("Probe() = %v", err)
	}
}

func TestGrypeNeedsItsConfig(t *testing.T) {
	t.Parallel()
	// No call is scripted: without ci's configuration, grype is never run
	g := scan.Grype{Run: execx.NewFake(t)}
	if err := g.UpdateDB(t.Context()); err == nil {
		t.Error("UpdateDB() with no Config: nil error")
	}
	if err := g.Layout(t.Context(), "/w/layout", "amd64", "r", "c", "s"); err == nil {
		t.Error("Layout() with no Config: nil error")
	}
}

func TestProbeRequiresNamespace(t *testing.T) {
	t.Parallel()
	const purl = "pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-13"
	tests := []struct {
		name, recording string
		wantErr         []string
	}{
		{name: "dhi-namespace", recording: "grype-probe-dhi-13.json"},
		{name: "debian-namespace-only", recording: "grype-probe-debian-13.json", wantErr: []string{purl, "debian:distro:debian:13"}},
		{name: "no-match", recording: "grype-probe-dhi-14.json", wantErr: []string{purl, "no record"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := execx.NewFake(t, execx.Call{
				Argv:   []string{"grype", "-c", "/ci/grype.yaml", purl, "-o", "json"},
				Result: execx.Result{Stdout: readTestdata(t, tt.recording)},
			})
			err := scan.Grype{Run: fake, Config: "/ci/grype.yaml"}.Probe(t.Context(), purl, "dhi:distro:dhi:13")
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Probe() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Probe() = nil, want an error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Probe() error = %q, want it to name %q", err, want)
				}
			}
		})
	}
}

func TestGrypeFails(t *testing.T) {
	t.Parallel()
	failed := execx.Result{Stderr: []byte("ERROR db update failed\n"), Code: 1}
	var log bytes.Buffer
	fake := execx.NewFake(t,
		execx.Call{Argv: []string{"grype", "-c", "/ci/grype.yaml", "db", "update"}, Result: failed},
		execx.Call{Argv: []string{"grype", "-c", "/ci/grype.yaml", "pkg:x", "-o", "json"}, Result: failed},
	)
	g := scan.Grype{Run: fake, Config: "/ci/grype.yaml", Log: &log}
	if err := g.UpdateDB(t.Context()); err == nil {
		t.Error("UpdateDB() = nil, want grype's exit status")
	}
	if err := g.Probe(t.Context(), "pkg:x", "dhi:distro:dhi:13"); err == nil {
		t.Error("Probe() = nil, want grype's exit status")
	}
	if !strings.Contains(log.String(), "db update failed") {
		t.Errorf("log = %q, want grype's own message", log.String())
	}
}

// sarifRules returns the rule IDs of the results in the SARIF at path.
func sarifRules(t *testing.T, path string) (results, rules []string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Rules []struct{ ID string } }
			}
			Results []struct{ RuleID string }
		}
	}
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Runs {
		for _, res := range r.Results {
			results = append(results, res.RuleID)
		}
		for _, rule := range r.Tool.Driver.Rules {
			rules = append(rules, rule.ID)
		}
	}
	return results, rules
}

func TestGrypeSARIFKeepsHighAndCritical(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	report, cdx, sarif := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.cdx.json"), filepath.Join(dir, "r.sarif")
	run := func(sarifIn []byte) error {
		fake := execx.NewFake(t, execx.Call{Argv: []string{
			"grype", "-c", "/ci/grype.yaml", "oci-dir:/w/layout", "--platform", "linux/arm64",
			"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx, "-o", "sarif=" + sarif,
		}})
		g := scan.Grype{Run: grypeOutputs{fake, map[string][]byte{
			"json": readTestdata(t, "grype-dhi.json"), "cyclonedx-json": readTestdata(t, "grype-dhi.cdx.json"), "sarif": sarifIn,
		}}, Config: "/ci/grype.yaml"}
		if err := g.Layout(t.Context(), "/w/layout", "arm64", report, cdx, sarif); err != nil {
			return err
		}
		return g.SARIF(report, sarif)
	}

	if err := run(readTestdata(t, "grype-dhi.sarif")); err != nil {
		t.Fatalf("Layout() and SARIF() = %v", err)
	}
	results, rules := sarifRules(t, sarif)
	want := []string{"DHI-mucl-alvq-4tv5-5ujl-qemu", "GHSA-35jh-r3h4-6jhm-lodash", "DHI-fwcj-m32u-e4uq-6hzy-brotli"}
	slices.Sort(results)
	slices.Sort(rules)
	slices.Sort(want)
	if !slices.Equal(results, want) || !slices.Equal(rules, want) {
		t.Errorf("SARIF results %q, rules %q; want each %q: HIGH and CRITICAL alone", results, rules, want)
	}

	// A SARIF whose rule IDs no longer follow grype's ID-package form
	// would otherwise come out empty, and code scanning quietly clean
	renamed := bytes.ReplaceAll(readTestdata(t, "grype-dhi.sarif"), []byte(`-qemu"`), []byte(`/qemu"`))
	if err := run(renamed); err == nil || !strings.Contains(err.Error(), "SARIF") {
		t.Errorf("SARIF() over a SARIF it cannot match = %v, want an error naming the SARIF", err)
	}
}

// requireSARIFArrays fails the test unless the SARIF at path holds an
// array in each place SARIF 2.1.0 needs one that the scan writes: runs,
// and each run's results and tool.driver.rules. JSON null is no array,
// and code scanning refuses it.
func requireSARIFArrays(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		t.Fatalf("runs = %v, want an array", doc["runs"])
	}
	for i, r := range runs {
		run, _ := r.(map[string]any)
		if _, ok := run["results"].([]any); !ok {
			t.Errorf("runs[%d].results = %v, want an array", i, run["results"])
		}
		tool, _ := run["tool"].(map[string]any)
		driver, _ := tool["driver"].(map[string]any)
		if _, ok := driver["rules"].([]any); !ok {
			t.Errorf("runs[%d].tool.driver.rules = %v, want an array", i, driver["rules"])
		}
	}
}

func TestGrypeSARIFWritesArrays(t *testing.T) {
	t.Parallel()
	const none = `{"matches":[]}`
	tests := []struct {
		name, report, sarif string
	}{
		{"no rules key", none, `{"runs":[{"tool":{"driver":{"name":"grype"}},"results":[]}]}`},
		{"rules null", none, `{"runs":[{"tool":{"driver":{"name":"grype","rules":null}},"results":null}]}`},
		{"no results key", none, `{"runs":[{"tool":{"driver":{"name":"grype","rules":[]}}}]}`},
		{
			"every rule filtered out", none,
			`{"runs":[{"tool":{"driver":{"name":"grype","rules":[{"id":"CVE-1-pkg"}]}},"results":[{"ruleId":"CVE-1-pkg"}]}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			report, sarif := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.sarif")
			for path, body := range map[string]string{report: tt.report, sarif: tt.sarif} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := (scan.Grype{}).SARIF(report, sarif); err != nil {
				t.Fatalf("SARIF() = %v", err)
			}
			requireSARIFArrays(t, sarif)
		})
	}
}
