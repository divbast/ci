// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// trivyOnlySARIF is a SARIF from Trivy alone, as a scanner may write one:
// a run whose driver names no rules and whose results are null, which code
// scanning refuses. The repair guards whichever scanner writes null or
// omits the arrays.
const trivyOnlySARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","version":"0.0.0"}},"results":null}]}`

// A scan by Trivy alone, which no lockfile or SBOM merge passes through,
// still leaves a SARIF code scanning accepts.
func TestRunTrivyOnlySARIFValid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	layout, rep, base, sarif := filepath.Join(dir, "layout"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "r.sarif")
	writeLayout(t, layout, debianRelease)
	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	runner := trivy{
		fake: execx.NewFake(t,
			execx.Call{Argv: append(append([]string{"trivy", "image", "--input", layout}, scanArgs...), "--output", rep)},
			execx.Call{Argv: []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", sarif, rep}},
			execx.Call{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
			execx.Call{Argv: append(append([]string{
				"trivy", "image", "--image-src", "remote", "--platform", "linux/amd64", "--skip-db-update",
			}, scanArgs...), "--output", base, published)},
		),
		reports: map[string]string{rep: report(t, "amd64", "", 1), base: report(t, "amd64", digest, 1), sarif: trivyOnlySARIF},
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-layout", layout, "-report", rep, "-published", published, "-baseline", base, "-sarif", sarif}
	if code := run(t.Context(), args, runner, execx.OS{}, offline(t), func(string) string { return "" }, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, want 0; stderr: %s", code, stderr.String())
	}
	data, err := readFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Rules any }
			}
			Results any
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1: %s", len(doc.Runs), data)
	}
	if _, ok := doc.Runs[0].Results.([]any); !ok {
		t.Errorf("results = %#v, want an array: %s", doc.Runs[0].Results, data)
	}
	if _, ok := doc.Runs[0].Tool.Driver.Rules.([]any); !ok {
		t.Errorf("rules = %#v, want an array: %s", doc.Runs[0].Tool.Driver.Rules, data)
	}
}

// A SARIF code scanning would refuse fails the scan, whatever its verdict.
func TestRunRefusesInvalidSARIF(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	layout, rep, base, sarif := filepath.Join(dir, "layout"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "r.sarif")
	writeLayout(t, layout, debianRelease)
	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	runner := trivy{
		fake: execx.NewFake(t,
			execx.Call{Argv: append(append([]string{"trivy", "image", "--input", layout}, scanArgs...), "--output", rep)},
			execx.Call{Argv: []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", sarif, rep}},
		),
		reports: map[string]string{rep: report(t, "amd64", "", 1), sarif: `{"version":"2.1.0"}`},
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-layout", layout, "-report", rep, "-published", published, "-baseline", base, "-sarif", sarif}
	code := run(t.Context(), args, runner, execx.OS{}, offline(t), func(string) string { return "" }, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "no runs") {
		t.Errorf("run() = %d, stderr %q; want 1 naming the missing runs", code, stderr.String())
	}
}
