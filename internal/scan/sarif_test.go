// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/scan"
)

// validated writes text as a SARIF file, validates it, and returns the
// error and the file as it then reads.
func validated(t *testing.T, text string) (doc map[string]any, err error) {
	t.Helper()
	dir, rerr := os.OpenRoot(t.TempDir())
	if rerr != nil {
		t.Fatal(rerr)
	}
	t.Cleanup(func() { _ = dir.Close() })
	if werr := dir.WriteFile("x.sarif", []byte(text), 0o600); werr != nil {
		t.Fatal(werr)
	}
	err = scan.ValidateSARIF(filepath.Join(dir.Name(), "x.sarif"))
	data, rerr := dir.ReadFile("x.sarif")
	if rerr != nil {
		t.Fatal(rerr)
	}
	_ = json.Unmarshal(data, &doc)
	return doc, err
}

// runOf is the first run of a SARIF document.
func runOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs, _ := doc["runs"].([]any)
	if len(runs) == 0 {
		t.Fatalf("no runs in %v", doc)
	}
	run, _ := runs[0].(map[string]any)
	return run
}

func TestValidateSARIFNullRules(t *testing.T) {
	t.Parallel()

	doc, err := validated(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":null}},"results":[]}]}`)
	if err != nil {
		t.Fatalf("ValidateSARIF() = %v, want nil", err)
	}
	run := runOf(t, doc)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if rules, ok := driver["rules"].([]any); !ok || rules == nil {
		t.Errorf("rules = %#v, want an empty array", driver["rules"])
	}
}

func TestValidateSARIFMissingResults(t *testing.T) {
	t.Parallel()

	doc, err := validated(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}}}]}`)
	if err != nil {
		t.Fatalf("ValidateSARIF() = %v, want nil", err)
	}
	run := runOf(t, doc)
	if results, ok := run["results"].([]any); !ok || results == nil {
		t.Errorf("results = %#v, want an empty array", run["results"])
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if rules, ok := driver["rules"].([]any); !ok || rules == nil {
		t.Errorf("rules = %#v, want an empty array", driver["rules"])
	}
}

func TestValidateSARIFRefused(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, text, want string }{
		{"no-runs", `{"version":"2.1.0"}`, "no runs"},
		{"runs-null", `{"runs":null}`, "no runs"},
		{"run-not-object", `{"runs":["x"]}`, "not a JSON object"},
		{"not-json", `{"runs":`, "as JSON"},
		{"empty", ``, "as JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := validated(t, tt.text)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ValidateSARIF() = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateSARIFNoRuns(t *testing.T) {
	t.Parallel()

	if _, err := validated(t, `{"version":"2.1.0"}`); err == nil {
		t.Error("ValidateSARIF() = nil, want an error for a file with no runs")
	}
}

func TestValidateSARIFRunNotObject(t *testing.T) {
	t.Parallel()

	_, err := validated(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"a"}}}, 3]}`)
	if err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("ValidateSARIF() = %v, want an error saying a run is not a JSON object", err)
	}
}

func TestValidateSARIFNoVersion(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, text string }{
		{"missing", `{"runs":[{"tool":{"driver":{"name":"a"}}}]}`},
		{"empty", `{"version":"","runs":[{"tool":{"driver":{"name":"a"}}}]}`},
		{"not-a-string", `{"version":2.1,"runs":[{"tool":{"driver":{"name":"a"}}}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := validated(t, tt.text)
			if err == nil || !strings.Contains(err.Error(), "version") {
				t.Errorf("ValidateSARIF() = %v, want an error naming the version", err)
			}
		})
	}
}

func TestValidateSARIFDuplicateDriverName(t *testing.T) {
	t.Parallel()

	_, err := validated(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype"}}},{"tool":{"driver":{"name":"Trivy"}}},{"tool":{"driver":{"name":"grype"}}}]}`)
	if err == nil || !strings.Contains(err.Error(), "grype") || !strings.Contains(err.Error(), "twice") {
		t.Errorf("ValidateSARIF() = %v, want an error saying grype names two runs", err)
	}
}

func TestValidateSARIFWrongTypedArrays(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, run, want string }{
		{"results-object", `{"tool":{"driver":{"name":"a"}},"results":{}}`, "results"},
		{"results-string", `{"tool":{"driver":{"name":"a"}},"results":"none"}`, "results"},
		{"rules-object", `{"tool":{"driver":{"name":"a","rules":{}}}}`, "rules"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := validated(t, `{"version":"2.1.0","runs":[`+tt.run+`]}`)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateSARIF() = %v, want an error naming %s", err, tt.want)
			}
			// Refused, not replaced: the file keeps what it held
			run := runOf(t, doc)
			if _, ok := run["results"].([]any); ok {
				t.Errorf("results = %#v, want the file left as it was", run["results"])
			}
		})
	}
}

// Every SARIF divbast-scan really writes passes: grype's recordings, one
// of them with a Trivy run beside it, and the files MergeSARIF makes.
func TestValidateSARIFRealOutputs(t *testing.T) {
	t.Parallel()

	const trivy = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"CVE-1"}]}},"results":[{"ruleId":"CVE-1"}]}]}`
	dir, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	write := func(name string, data []byte) string {
		t.Helper()
		if err := dir.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(dir.Name(), name)
	}
	check := func(path string) {
		t.Helper()
		if err := scan.ValidateSARIF(path); err != nil {
			t.Errorf("ValidateSARIF(%s) = %v, want nil", filepath.Base(path), err)
		}
	}
	for _, name := range []string{"grype-dhi.sarif", "grype-lockfile.sarif", "grype-sbom.sarif"} {
		check(write(name, readTestdata(t, name)))
	}
	// The merged files, as the merge tests make them
	image := write("image.sarif", readTestdata(t, "grype-dhi.sarif"))
	if err := scan.MergeSARIF(image, write("lock.sarif", readTestdata(t, "grype-lockfile.sarif"))); err != nil {
		t.Fatal(err)
	}
	check(image)
	beside := write("trivy.sarif", []byte(trivy))
	if err := scan.MergeSARIF(beside, write("lock2.sarif", readTestdata(t, "grype-lockfile.sarif"))); err != nil {
		t.Fatal(err)
	}
	if err := scan.MergeSARIF(beside, write("sbom.sarif", readTestdata(t, "grype-sbom.sarif"))); err != nil {
		t.Fatal(err)
	}
	check(beside)
}

func TestValidateSARIFMissingFile(t *testing.T) {
	t.Parallel()

	if err := scan.ValidateSARIF(filepath.Join(t.TempDir(), "none.sarif")); err == nil {
		t.Error("ValidateSARIF() = nil, want an error for a file that is not there")
	}
}

func TestValidateSARIFNoDriver(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, text, want string }{
		{"no-tool", `{"runs":[{"results":[]}]}`, "tool"},
		{"no-driver", `{"runs":[{"tool":{}}]}`, "driver"},
		{"driver-null", `{"runs":[{"tool":{"driver":null}}]}`, "driver"},
		{"no-name", `{"runs":[{"tool":{"driver":{"rules":[]}}}]}`, "name"},
		{"empty-name", `{"runs":[{"tool":{"driver":{"name":""}}}]}`, "name"},
		{"name-not-string", `{"runs":[{"tool":{"driver":{"name":3}}}]}`, "name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := validated(t, tt.text)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ValidateSARIF() = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
