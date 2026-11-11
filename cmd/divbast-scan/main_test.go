// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

const (
	published = "ghcr.io/divbast/librespeed:latest"
	digest    = "ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
)

// trivy answers as the real one would, through a Fake that checks every
// argv: a call that succeeds writes the report scripted for the path its
// --output names.
type trivy struct {
	fake    *execx.Fake
	reports map[string]string
}

func (tr trivy) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	res, err := tr.fake.Run(ctx, name, args...)
	if err != nil || res.Code != 0 {
		return res, err
	}
	if i := slices.Index(args, "--output"); i >= 0 && i+1 < len(args) {
		if report, ok := tr.reports[args[i+1]]; ok {
			return res, os.WriteFile(args[i+1], []byte(report), 0o600)
		}
	}
	return res, nil
}

// report is a Trivy report on an image of arch with packages packages and
// a HIGH finding in stdlib for each of ids. repoDigest is its repository
// digest, which a layout has none of.
func report(t *testing.T, arch, repoDigest string, packages int, ids ...string) string {
	t.Helper()
	pkgs := make([]map[string]string, packages)
	for i := range pkgs {
		pkgs[i] = map[string]string{"ID": "pkg" + strconv.Itoa(i)}
	}
	vulns := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		vulns = append(vulns, map[string]string{
			"VulnerabilityID": id, "PkgName": "stdlib", "InstalledVersion": "v1.27.3", "Severity": "HIGH",
		})
	}
	metadata := map[string]any{"ImageConfig": map[string]string{"architecture": arch}}
	if repoDigest != "" {
		metadata["RepoDigests"] = []string{repoDigest}
	}
	data, err := json.Marshal(map[string]any{
		"ArtifactName": "image",
		"Metadata":     metadata,
		"Results": []map[string]any{{
			"Target": "usr/local/bin/frankenphp", "Class": "lang-pkgs", "Type": "gobinary",
			"Packages": pkgs, "Vulnerabilities": vulns,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// recorded returns a recording of Trivy's stderr from internal/scan's
// testdata, where its README says how each was made.
func recorded(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join("..", "..", "internal", "scan", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func line(id string) string {
	return "  " + id + " HIGH stdlib v1.27.3, no fix, usr/local/bin/frankenphp\n"
}

const warning = "The scan is advisory because " + published + " is not anonymously pullable: " +
	"it is not published yet, or it is private. It stays advisory until " + published + " is public."

func TestRun(t *testing.T) {
	t.Parallel()

	// What the runner already wrote to the summary, which must survive.
	const before = "earlier\n"

	tests := []struct {
		name string
		// vex is the -vex flag's value, if any.
		vex string
		// candidate and baseline are the reports the two scans write, and
		// layoutResult, baselineResult and sarifResult what each call
		// returns. A nil result means the call is never made.
		candidate, baseline                       string
		layoutResult, baselineResult, sarifResult *execx.Result
		env                                       map[string]string
		wantCode                                  int
		wantStdout                                string
		wantStderr                                []string
		// notInStdout is what must not be on stdout.
		notInStdout []string
		// wantSummary is what the summary must hold after before, or nothing
		// is checked when empty; wantBaseline the same for the baseline.
		wantSummary  []string
		wantBaseline string
	}{
		{
			name:           "nothing-new",
			candidate:      report(t, "amd64", "", 3, "CVE-1", "CVE-2"),
			baseline:       report(t, "amd64", digest, 3, "CVE-2", "CVE-1"),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{},
			wantStdout: "compared with " + digest + "\n0 new, so blocking:\n" +
				"2 already published, so advisory:\n" + line("CVE-1") + line("CVE-2") +
				"nothing new against what is published (2 advisory)\n",
			wantSummary: []string{"### Vulnerability scan, amd64\n", "Compared with `" + digest + "`.", "**New, so blocking: 0**"},
		},
		{
			name:           "new-blocks",
			candidate:      report(t, "arm64", "", 3, "CVE-1", "CVE-2", "CVE-3"),
			baseline:       report(t, "arm64", digest, 3, "CVE-2"),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{},
			wantCode:       1,
			wantStdout: "compared with " + digest + "\n2 new, so blocking:\n" + line("CVE-1") + line("CVE-3") +
				"1 already published, so advisory:\n" + line("CVE-2"),
			wantStderr:  []string{"2 finding(s) the published image does not have. Move what carries them.\n"},
			wantSummary: []string{"### Vulnerability scan, arm64\n", "**New, so blocking: 2**"},
		},
		{
			name:           "new-blocks-with-vex",
			vex:            "baikal.openvex.json",
			candidate:      report(t, "amd64", "", 3, "CVE-1"),
			baseline:       report(t, "amd64", digest, 3),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{},
			wantCode:       1,
			wantStdout: "compared with " + digest + "\n1 new, so blocking:\n" + line("CVE-1") +
				"0 already published, so advisory:\n",
			wantStderr: []string{"1 finding(s) the published image does not have. Move what carries them, or argue reachability in baikal.openvex.json.\n"},
		},
		{
			name:           "advisory",
			candidate:      report(t, "amd64", "", 3, "CVE-1", "CVE-2"),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{Stderr: recorded(t, "trivy-no-such-package.txt"), Code: 1},
			wantStdout: "compared with nothing, because " + published + " is not anonymously pullable\n" +
				"2 advisory: nothing published yet:\n" + line("CVE-1") + line("CVE-2") +
				"0 already published, so advisory:\n" +
				published + " is not anonymously pullable, so all 2 finding(s) are advisory\n",
			wantStderr:   []string{"WARNING: " + warning + "\n"},
			notInStdout:  []string{"::warning"},
			wantSummary:  []string{"> **Warning:** " + warning + "\n", "**Advisory: nothing published yet: 2**"},
			wantBaseline: "{}\n",
		},
		{
			name:           "advisory-in-actions",
			candidate:      report(t, "amd64", "", 3, "CVE-1"),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{Stderr: recorded(t, "trivy-no-such-tag.txt"), Code: 1},
			env:            map[string]string{"GITHUB_ACTIONS": "true"},
			wantStdout: "::warning title=Scan is advisory::" + warning + "\n" +
				"compared with nothing, because " + published + " is not anonymously pullable\n" +
				"1 advisory: nothing published yet:\n" + line("CVE-1") +
				"0 already published, so advisory:\n" +
				published + " is not anonymously pullable, so all 1 finding(s) are advisory\n",
			wantStderr:   []string{"WARNING: " + warning + "\n"},
			wantBaseline: "{}\n",
		},
		{
			name:         "nothing-to-scan",
			candidate:    report(t, "amd64", "", 0),
			layoutResult: &execx.Result{},
			wantCode:     1,
			wantStderr:   []string{"no packages in LAYOUT: the scan found nothing to scan, not nothing wrong\n"},
		},
		{
			name:           "nothing-to-scan-published",
			candidate:      report(t, "amd64", "", 3, "CVE-1"),
			baseline:       report(t, "amd64", digest, 0),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{},
			wantCode:       1,
			wantStderr:     []string{"no packages in " + published + ": the scan found nothing to scan, not nothing wrong\n"},
		},
		{
			name:           "registry-failed",
			candidate:      report(t, "amd64", "", 3, "CVE-1"),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{Stderr: recorded(t, "trivy-manifest-429.txt"), Code: 1},
			wantCode:       1,
			wantStderr: []string{
				"TOOMANYREQUESTS: retry-after: 1s",
				"could not scan " + published + ", so no finding can be told apart from one already published",
			},
		},
		{
			name:           "registry-unauthorized",
			candidate:      report(t, "amd64", "", 3, "CVE-1"),
			layoutResult:   &execx.Result{},
			sarifResult:    &execx.Result{},
			baselineResult: &execx.Result{Stderr: recorded(t, "trivy-unauthorized.txt"), Code: 1},
			wantCode:       1,
			wantStderr:     []string{"could not scan " + published},
		},
		{
			name:         "layout-scan-fails",
			layoutResult: &execx.Result{Stderr: []byte("FATAL\tno such layout\n"), Code: 1},
			wantCode:     1,
			wantStderr:   []string{"FATAL\tno such layout\n", "LAYOUT"},
		},
		{
			name:         "sarif-fails",
			candidate:    report(t, "amd64", "", 3, "CVE-1"),
			layoutResult: &execx.Result{},
			sarifResult:  &execx.Result{Stderr: []byte("FATAL\tbad report\n"), Code: 1},
			wantCode:     1,
			wantStderr:   []string{"FATAL\tbad report\n", "SARIF"},
		},
		{
			name:         "no-architecture",
			candidate:    report(t, "", "", 3, "CVE-1"),
			layoutResult: &execx.Result{},
			sarifResult:  &execx.Result{},
			wantCode:     1,
			wantStderr:   []string{"architecture"},
		},
		{
			name:         "unreadable-report",
			candidate:    "FATAL",
			layoutResult: &execx.Result{},
			wantCode:     1,
			wantStderr:   []string{"REPORT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			paths := map[string]string{}
			for _, p := range []string{"layout", "report.json", "baseline.json", "report.sarif", "summary.md"} {
				paths[p] = filepath.Join(dir, p)
			}
			if err := os.WriteFile(paths["summary.md"], []byte(before), 0o600); err != nil {
				t.Fatal(err)
			}

			args := []string{
				"-layout", paths["layout"], "-report", paths["report.json"], "-published", published,
				"-baseline", paths["baseline.json"], "-sarif", paths["report.sarif"],
			}
			scanArgs := []string{"--severity", "HIGH,CRITICAL", "--format", "json"}
			if tt.vex != "" {
				args = append(args, "-vex", tt.vex)
				scanArgs = slices.Concat([]string{"--vex", tt.vex}, scanArgs)
			}

			var calls []execx.Call
			if tt.layoutResult != nil {
				argv := append(append([]string{"trivy", "image", "--input", paths["layout"]}, scanArgs...), "--output", paths["report.json"])
				calls = append(calls, execx.Call{Argv: argv, Result: *tt.layoutResult})
			}
			if tt.sarifResult != nil {
				argv := []string{"trivy", "convert", "--format", "sarif", "--output", paths["report.sarif"], paths["report.json"]}
				calls = append(calls, execx.Call{Argv: argv, Result: *tt.sarifResult})
			}
			if tt.baselineResult != nil {
				var c struct {
					Metadata struct{ ImageConfig struct{ Architecture string } }
				}
				if err := json.Unmarshal([]byte(tt.candidate), &c); err != nil {
					t.Fatal(err)
				}
				argv := append([]string{
					"trivy", "image", "--image-src", "remote", "--platform", "linux/" + c.Metadata.ImageConfig.Architecture,
					"--skip-db-update",
				}, scanArgs...)
				argv = append(argv, "--output", paths["baseline.json"], published)
				calls = append(calls, execx.Call{Argv: argv, Result: *tt.baselineResult})
			}
			runner := trivy{
				fake:    execx.NewFake(t, calls...),
				reports: map[string]string{paths["report.json"]: tt.candidate, paths["baseline.json"]: tt.baseline},
			}

			env := map[string]string{"GITHUB_STEP_SUMMARY": paths["summary.md"]}
			maps.Copy(env, tt.env)
			getenv := func(key string) string { return env[key] }

			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, runner, getenv, &stdout, &stderr)
			// Every message names its paths by flag, so the scratch
			// directory reads as the flag that put it there.
			errText := strings.ReplaceAll(stderr.String(), paths["layout"], "LAYOUT")
			errText = strings.ReplaceAll(errText, paths["report.json"], "REPORT")
			errText = strings.ReplaceAll(errText, paths["report.sarif"], "SARIF")

			if code != tt.wantCode {
				t.Errorf("run() = %d, want %d; stderr: %s", code, tt.wantCode, errText)
			}
			if got := stdout.String(); tt.wantStdout != "" && got != tt.wantStdout {
				t.Errorf("stdout:\n%s\nwant:\n%s", got, tt.wantStdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(errText, want) {
					t.Errorf("stderr = %q, want it to contain %q", errText, want)
				}
			}
			for _, unwanted := range tt.notInStdout {
				if strings.Contains(stdout.String(), unwanted) {
					t.Errorf("stdout = %q, want no %q", stdout.String(), unwanted)
				}
			}

			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			summary, err := root.ReadFile("summary.md")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(summary), before) {
				t.Errorf("summary = %q, want what was there before kept", summary)
			}
			for _, want := range tt.wantSummary {
				if !strings.Contains(string(summary), want) {
					t.Errorf("summary = %q, want it to contain %q", summary, want)
				}
			}
			if tt.wantBaseline != "" {
				got, err := root.ReadFile("baseline.json")
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Fatal(err)
				}
				if string(got) != tt.wantBaseline {
					t.Errorf("baseline = %q, want %q", got, tt.wantBaseline)
				}
			}
		})
	}
}

// Every message, the verdict included, lands even when GitHub Actions has
// named no summary, and nothing is written in its place.
func TestRunOutsideActions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	layout, rep, base, sarif := filepath.Join(dir, "layout"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "r.sarif")
	scanArgs := []string{"--severity", "HIGH,CRITICAL", "--format", "json"}
	runner := trivy{
		fake: execx.NewFake(t,
			execx.Call{Argv: append(append([]string{"trivy", "image", "--input", layout}, scanArgs...), "--output", rep)},
			execx.Call{Argv: []string{"trivy", "convert", "--format", "sarif", "--output", sarif, rep}},
			execx.Call{Argv: append(append([]string{
				"trivy", "image", "--image-src", "remote", "--platform", "linux/amd64", "--skip-db-update",
			}, scanArgs...), "--output", base, published)},
		),
		reports: map[string]string{rep: report(t, "amd64", "", 1), base: report(t, "amd64", digest, 1)},
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-layout", layout, "-report", rep, "-published", published, "-baseline", base, "-sarif", sarif}
	if code := run(t.Context(), args, runner, func(string) string { return "" }, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, want 0; stderr: %s", code, stderr.String())
	}
	if want := "nothing new against what is published (0 advisory)\n"; !strings.HasSuffix(stdout.String(), want) {
		t.Errorf("stdout = %q, want it to end %q", stdout.String(), want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// Only what the stub trivy wrote: no summary appeared anywhere
	if want := []string{"b.json", "r.json"}; !slices.Equal(names, want) {
		t.Errorf("files = %q, want %q", names, want)
	}
}

// A verdict that cannot reach the summary page fails the step.
func TestRunUnwritableSummary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	layout, rep, base, sarif := filepath.Join(dir, "layout"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "r.sarif")
	scanArgs := []string{"--severity", "HIGH,CRITICAL", "--format", "json"}
	runner := trivy{
		fake: execx.NewFake(t,
			execx.Call{Argv: append(append([]string{"trivy", "image", "--input", layout}, scanArgs...), "--output", rep)},
			execx.Call{Argv: []string{"trivy", "convert", "--format", "sarif", "--output", sarif, rep}},
			execx.Call{Argv: append(append([]string{
				"trivy", "image", "--image-src", "remote", "--platform", "linux/amd64", "--skip-db-update",
			}, scanArgs...), "--output", base, published)},
		),
		reports: map[string]string{rep: report(t, "amd64", "", 1), base: report(t, "amd64", digest, 1)},
	}
	missing := filepath.Join(dir, "no-such-dir", "summary.md")
	getenv := func(key string) string {
		if key == "GITHUB_STEP_SUMMARY" {
			return missing
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-layout", layout, "-report", rep, "-published", published, "-baseline", base, "-sarif", sarif}
	if code := run(t.Context(), args, runner, getenv, &stdout, &stderr); code != 1 {
		t.Errorf("run() = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write the run summary") {
		t.Errorf("stderr = %q, want it to say the summary could not be written", stderr.String())
	}
}

func TestRunUsage(t *testing.T) {
	t.Parallel()

	all := []string{"-layout", "l", "-report", "r", "-published", published, "-baseline", "b", "-sarif", "s"}
	without := func(flag string) []string {
		i := slices.Index(all, flag)
		return slices.Delete(slices.Clone(all), i, i+2)
	}
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{name: "help", args: []string{"-h"}, wantStderr: "-published"},
		{name: "no-layout", args: without("-layout"), wantCode: 2, wantStderr: "-layout is required"},
		{name: "no-report", args: without("-report"), wantCode: 2, wantStderr: "-report is required"},
		{name: "no-published", args: without("-published"), wantCode: 2, wantStderr: "-published is required"},
		{name: "no-baseline", args: without("-baseline"), wantCode: 2, wantStderr: "-baseline is required"},
		{name: "no-sarif", args: without("-sarif"), wantCode: 2, wantStderr: "-sarif is required"},
		{name: "empty-published", args: append(without("-published"), "-published", ""), wantCode: 2, wantStderr: "-published is required"},
		{name: "stray-argument", args: append(slices.Clone(all), "extra"), wantCode: 2, wantStderr: `unexpected argument "extra"`},
		{name: "unknown-flag", args: []string{"-nope"}, wantCode: 2, wantStderr: "-nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			// No call is scripted: a usage error runs nothing
			code := run(t.Context(), tt.args, execx.NewFake(t), func(string) string { return "" }, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d", tt.args, code, tt.wantCode)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// fixture is LibreSpeed's published index, public and pinned by digest.
const fixture = "ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"

// TestScanAgainstItself scans the fixture as an OCI layout and compares it
// with itself as published, with the real trivy, which must find nothing
// new. It needs the network, skopeo and trivy, so it runs only where the
// engine matrix does, with ENGINE set.
func TestScanAgainstItself(t *testing.T) {
	t.Parallel()

	if os.Getenv("ENGINE") == "" {
		t.Skip("ENGINE is unset: the scan against the published fixture runs in the engine matrix")
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy is not on PATH")
	}

	dir := t.TempDir()
	layout := filepath.Join(dir, "layout")
	// --override-os, for a run on macOS
	res, err := execx.OS{}.Run(t.Context(), "skopeo", "copy", "--override-os", "linux", "--override-arch", runtime.GOARCH,
		"docker://"+fixture, "oci:"+layout)
	if err != nil || res.Code != 0 {
		t.Fatalf("skopeo copy: %v, exit %d: %s", err, res.Code, res.Stderr)
	}

	summary := filepath.Join(dir, "summary.md")
	getenv := func(key string) string {
		if key == "GITHUB_STEP_SUMMARY" {
			return summary
		}
		return ""
	}
	args := []string{
		"-layout", layout, "-report", filepath.Join(dir, "report.json"), "-published", fixture,
		"-baseline", filepath.Join(dir, "baseline.json"), "-sarif", filepath.Join(dir, "report.sarif"),
	}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), args, execx.OS{}, getenv, &stdout, &stderr)
	t.Logf("stdout:\n%s", stdout.String())
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "nothing new against what is published") {
		t.Errorf("stdout = %q, want nothing new", stdout.String())
	}
	if !strings.HasPrefix(stdout.String(), "compared with "+fixture+"\n") {
		t.Errorf("stdout = %q, want it compared with %s", stdout.String(), fixture)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, name := range []string{"report.json", "baseline.json", "report.sarif", "summary.md"} {
		if info, err := root.Stat(name); err != nil || info.Size() == 0 {
			t.Errorf("%s: %v, want a file with something in it", name, err)
		}
	}
}
