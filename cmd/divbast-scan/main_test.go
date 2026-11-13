// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/divbast/ci/internal/registry"
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

// The warnings for a published image GitHub says is not there, and for one
// the registry refused outside GitHub Actions, where nothing asks GitHub.
const (
	absentWarning = "The scan is advisory because " + published + " is not published yet: " +
		"nothing is shipped to compare with. It blocks on new findings once " + published + " is published."
	refusedWarning = "The scan is advisory because " + published + " was refused by ghcr.io: " +
		"outside GitHub Actions nothing asks GitHub whether that means it is not published yet, is private, or is " +
		"public and failing to serve: the token a person gives the recipes cannot read packages. CI's scan asks, and decides."
)

func TestRun(t *testing.T) {
	t.Parallel()

	// What the runner already wrote to the summary, which must survive.
	const before = "earlier\n"

	// The registry showing the published image, or refusing to
	index := &execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}
	refused := &execx.Result{Stderr: skopeoRecording(t, "skopeo-no-such-package.txt"), Code: 1}

	tests := []struct {
		name string
		// image is the -published flag's value, when not published.
		image string
		// vex is the -vex flag's value, if any.
		vex string
		// skopeo is how the registry answers the read of the published
		// image, and gh how GitHub answers about its package. A nil
		// result means the call is never made.
		skopeo, gh *execx.Result
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
			skopeo:         index,
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
			skopeo:         index,
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
			skopeo:         index,
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
			// Outside GitHub Actions, nothing asks GitHub about a refusal
			name:         "advisory",
			skopeo:       refused,
			candidate:    report(t, "amd64", "", 3, "CVE-1", "CVE-2"),
			layoutResult: &execx.Result{},
			sarifResult:  &execx.Result{},
			wantStdout: "compared with nothing, because " + published + " was refused by ghcr.io\n" +
				"2 advisory: nothing readable to compare with:\n" + line("CVE-1") + line("CVE-2") +
				"0 already published, so advisory:\n" +
				published + " was refused by ghcr.io, so all 2 finding(s) are advisory\n",
			wantStderr:   []string{"WARNING: " + refusedWarning + "\n"},
			notInStdout:  []string{"::warning"},
			wantSummary:  []string{"> **Warning:** " + refusedWarning + "\n", "**Advisory: nothing readable to compare with: 2**"},
			wantBaseline: "{}\n",
		},
		{
			name:         "advisory-in-actions",
			skopeo:       refused,
			gh:           new(status(404, "Package not found.")),
			candidate:    report(t, "amd64", "", 3, "CVE-1"),
			layoutResult: &execx.Result{},
			sarifResult:  &execx.Result{},
			env:          map[string]string{"GITHUB_ACTIONS": "true"},
			wantStdout: "::warning title=Scan is advisory::" + absentWarning + "\n" +
				"compared with nothing, because " + published + " is not published yet\n" +
				"1 advisory: nothing published yet:\n" + line("CVE-1") +
				"0 already published, so advisory:\n" +
				published + " is not published yet, so all 1 finding(s) are advisory\n",
			wantStderr:   []string{"WARNING: " + absentWarning + "\n"},
			wantSummary:  []string{"> **Warning:** " + absentWarning + "\n", "**Advisory: nothing published yet: 1**"},
			wantBaseline: "{}\n",
		},
		{
			// Only ghcr.io images can be told absent from private, so any
			// other image fails before the registry is asked anything
			name:         "not-ghcr",
			image:        "docker.io/divbast/librespeed:latest",
			candidate:    report(t, "amd64", "", 3, "CVE-1"),
			layoutResult: &execx.Result{},
			sarifResult:  &execx.Result{},
			wantCode:     1,
			wantStderr: []string{
				"could not tell whether docker.io/divbast/librespeed:latest is published",
				`"docker.io/divbast/librespeed:latest" is not a ghcr.io image`,
			},
			notInStdout: []string{"compared with"},
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
			skopeo:         index,
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
			skopeo:         index,
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

			image := cmp.Or(tt.image, published)
			args := []string{
				"-layout", paths["layout"], "-report", paths["report.json"], "-published", image,
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
			if tt.skopeo != nil {
				calls = append(calls, execx.Call{Argv: skopeoArgv, Result: *tt.skopeo})
			}
			if tt.gh != nil {
				calls = append(calls, execx.Call{Argv: ghArgv, Result: *tt.gh})
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

// skopeoRecording returns a recording of what skopeo printed, the index
// it wrote to stdout or the refusal or failure it wrote to stderr, from
// internal/registry's testdata, where registry_test.go says how each was
// made.
func skopeoRecording(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join("..", "..", "internal", "registry", "testdata"))
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

// The calls that ask whether published is published: skopeo reading it as
// an anonymous client, and gh asking GitHub about its package.
var (
	skopeoArgv = []string{"skopeo", "inspect", "--raw", "--no-creds", "docker://" + published}
	ghArgv     = []string{"gh", "api", "-i", "orgs/divbast/packages/container/librespeed"}
)

// pkg is gh api -i answering 200 with a package of this visibility.
func pkg(visibility string) execx.Result {
	return execx.Result{Stdout: []byte("HTTP/2.0 200 OK\nContent-Type: application/json; charset=utf-8\r\n\r\n" +
		`{"id":1,"name":"librespeed","package_type":"container","visibility":"` + visibility + `"}`)}
}

// status is gh api -i answering a status outside 2xx, which gh exits 1 on.
func status(code int, text string) execx.Result {
	return execx.Result{
		Stdout: []byte("HTTP/2.0 " + strconv.Itoa(code) + " " + text + "\nContent-Type: application/json; charset=utf-8\r\n\r\n" +
			`{"message":"` + text + `","status":"` + strconv.Itoa(code) + `"}`),
		Stderr: []byte("gh: " + text + " (HTTP " + strconv.Itoa(code) + ")\n"),
		Code:   1,
	}
}

// TestPublishedPresenceFromRegistry checks that the scan asks the
// registry, and GitHub when the registry refuses, whether the published
// image is there, and never reads Trivy's stderr for it. Absent or
// private makes every finding an advisory, with a warning that says
// which; present compares with what Trivy finds in it, and any failure of
// that scan fails, whatever Trivy said; a registry or a GitHub that does
// not answer fails, as does a public package the registry refuses to
// show. Outside GitHub Actions no token may read packages, so nothing
// asks GitHub: a refusal is an advisory there, saying CI decides.
func TestPublishedPresenceFromRegistry(t *testing.T) {
	t.Parallel()

	refused := execx.Result{Stderr: skopeoRecording(t, "skopeo-no-such-package.txt"), Code: 1}
	index := execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}
	tests := []struct {
		name string
		// actions is whether GITHUB_ACTIONS is true.
		actions bool
		// skopeo and gh answer the presence calls; a nil gh is never asked.
		skopeo execx.Result
		gh     *execx.Result
		// trivy is what the published scan returns, nil when it never runs.
		trivy *execx.Result
		// baseline is the report that scan writes.
		baseline   string
		wantCode   int
		wantStdout []string
		wantStderr []string
		// wantBaseline is what the baseline must hold, when not empty.
		wantBaseline string
	}{
		{
			name:         "absent",
			actions:      true,
			skopeo:       refused,
			gh:           new(status(404, "Package not found.")),
			wantStdout:   []string{"::warning title=Scan is advisory::", published + " is not published yet, so all 1 finding(s) are advisory\n"},
			wantStderr:   []string{"WARNING: The scan is advisory because " + published + " is not published yet"},
			wantBaseline: "{}\n",
		},
		{
			name:         "private",
			actions:      true,
			skopeo:       refused,
			gh:           new(pkg("private")),
			wantStdout:   []string{"::warning title=Scan is advisory::", published + " is private, so all 1 finding(s) are advisory\n"},
			wantStderr:   []string{"WARNING: The scan is advisory because " + published + " is private", "until " + published + " is public"},
			wantBaseline: "{}\n",
		},
		{
			name:       "present",
			actions:    true,
			skopeo:     index,
			trivy:      &execx.Result{},
			baseline:   report(t, "amd64", digest, 3),
			wantCode:   1,
			wantStdout: []string{"compared with " + digest + "\n1 new, so blocking:\n" + line("CVE-1")},
			wantStderr: []string{"1 finding(s) the published image does not have"},
		},
		{
			// Trivy's own words for an image nobody publishes, which once
			// made the scan advisory: the registry has shown it, so this is
			// a scan that failed
			name:       "present-trivy-says-manifest-unknown",
			actions:    true,
			skopeo:     index,
			trivy:      &execx.Result{Stderr: recorded(t, "trivy-no-such-tag.txt"), Code: 1},
			wantCode:   1,
			wantStderr: []string{"MANIFEST_UNKNOWN", "could not scan " + published + ", so no finding can be told apart from one already published"},
		},
		{
			name:       "present-trivy-says-denied",
			actions:    true,
			skopeo:     index,
			trivy:      &execx.Result{Stderr: recorded(t, "trivy-no-such-package.txt"), Code: 1},
			wantCode:   1,
			wantStderr: []string{"could not scan " + published},
		},
		{
			name:       "registry-unreachable",
			actions:    true,
			skopeo:     execx.Result{Stderr: skopeoRecording(t, "skopeo-manifest-503.txt"), Code: 1},
			wantCode:   1,
			wantStderr: []string{"503 Service Unavailable", "could not tell whether " + published + " is published"},
		},
		{
			name:       "github-unreachable",
			actions:    true,
			skopeo:     refused,
			gh:         new(status(502, "Bad Gateway")),
			wantCode:   1,
			wantStderr: []string{"502", "could not tell whether " + published + " is published"},
		},
		{
			// CI-25(b): a public image the registry will not show is a
			// registry failing, not nothing published
			name:       "refused-though-public",
			actions:    true,
			skopeo:     refused,
			gh:         new(pkg("public")),
			wantCode:   1,
			wantStderr: []string{"public", "could not tell whether " + published + " is published"},
		},
		{
			name:       "github-refuses-the-token",
			actions:    true,
			skopeo:     refused,
			gh:         new(status(403, "You need at least read:packages scope to get a package.")),
			wantCode:   1,
			wantStderr: []string{"HTTP 403", "read:packages"},
		},
		{
			name:         "outside-actions-refused",
			skopeo:       refused,
			wantStdout:   []string{published + " was refused by ghcr.io, so all 1 finding(s) are advisory\n"},
			wantStderr:   []string{"WARNING: The scan is advisory because " + published + " was refused by ghcr.io", "outside GitHub Actions"},
			wantBaseline: "{}\n",
		},
		{
			name:       "outside-actions-present",
			skopeo:     index,
			trivy:      &execx.Result{},
			baseline:   report(t, "amd64", digest, 3, "CVE-1"),
			wantStdout: []string{"nothing new against what is published (1 advisory)\n"},
		},
		{
			name:       "outside-actions-unreachable",
			skopeo:     execx.Result{Stderr: skopeoRecording(t, "skopeo-manifest-503.txt"), Code: 1},
			wantCode:   1,
			wantStderr: []string{"503 Service Unavailable"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			layout, rep, base, sarif := filepath.Join(dir, "layout"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "r.sarif")
			scanArgs := []string{"--severity", "HIGH,CRITICAL", "--format", "json"}
			calls := []execx.Call{
				{Argv: append(append([]string{"trivy", "image", "--input", layout}, scanArgs...), "--output", rep)},
				{Argv: []string{"trivy", "convert", "--format", "sarif", "--output", sarif, rep}},
				{Argv: skopeoArgv, Result: tt.skopeo},
			}
			if tt.gh != nil {
				calls = append(calls, execx.Call{Argv: ghArgv, Result: *tt.gh})
			}
			if tt.trivy != nil {
				calls = append(calls, execx.Call{
					Argv: append(append([]string{
						"trivy", "image", "--image-src", "remote", "--platform", "linux/amd64", "--skip-db-update",
					}, scanArgs...), "--output", base, published),
					Result: *tt.trivy,
				})
			}
			runner := trivy{
				fake:    execx.NewFake(t, calls...),
				reports: map[string]string{rep: report(t, "amd64", "", 3, "CVE-1"), base: tt.baseline},
			}
			env := map[string]string{}
			if tt.actions {
				env["GITHUB_ACTIONS"] = "true"
			}
			getenv := func(key string) string { return env[key] }

			var stdout, stderr bytes.Buffer
			args := []string{"-layout", layout, "-report", rep, "-published", published, "-baseline", base, "-sarif", sarif}
			code := run(t.Context(), args, runner, getenv, &stdout, &stderr)
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
			if tt.wantBaseline != "" {
				got, err := os.ReadFile(base) //nolint:gosec // G304: the test's own temporary file
				if err != nil || string(got) != tt.wantBaseline {
					t.Errorf("baseline = %q (%v), want %q", got, err, tt.wantBaseline)
				}
			}
		})
	}
}

// TestUnshippedFor checks each answer the registry lookup can give, in
// GitHub Actions and outside it. A refusal nothing asked GitHub about is
// advisory only outside Actions, where nothing does ask: in Actions it is
// an error, which run exits 1 on, whoever made the lookup that gave it.
func TestUnshippedFor(t *testing.T) {
	t.Parallel()

	refused := fmt.Errorf("%w: ghcr.io refused to show %s: denied", registry.ErrRefused, published)
	private := fmt.Errorf("%w: GitHub gives it the visibility \"private\"", registry.ErrPrivate)
	unreadable := errors.New("could not read " + published + ": skopeo exit status 1")
	tests := []struct {
		name      string
		state     registry.State
		err       error
		inActions bool
		// wantReason is the advisory's reason, empty for none; wantErr
		// the error it returns, nil for none.
		wantReason string
		wantErr    error
	}{
		{name: "published", state: registry.Published, inActions: true},
		{name: "absent", state: registry.Absent, inActions: true, wantReason: "is not published yet"},
		{name: "private", err: private, inActions: true, wantReason: "is private"},
		{name: "refused-outside-actions", err: refused, wantReason: "was refused by ghcr.io"},
		{name: "refused-in-actions", err: refused, inActions: true, wantErr: registry.ErrRefused},
		{name: "unreadable", err: unreadable, inActions: true, wantErr: unreadable},
		{name: "unreadable-outside-actions", err: unreadable, wantErr: unreadable},
		{name: "no-state-and-no-error", inActions: true, wantErr: errors.New("the lookup answered State(0), and no error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := unshippedFor(tt.state, tt.err, tt.inActions, published)
			if tt.wantErr != nil {
				if err == nil || (!errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error()) {
					t.Errorf("unshippedFor() = %+v, %v; want the error %v", got, err, tt.wantErr)
				}
				if got != nil {
					t.Errorf("unshippedFor() = %+v with error %v, want no advisory", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unshippedFor() error = %v, want nil", err)
			}
			switch {
			case tt.wantReason == "" && got != nil:
				t.Errorf("unshippedFor() = %+v, want no advisory", got)
			case tt.wantReason != "" && (got == nil || got.reason != tt.wantReason):
				t.Errorf("unshippedFor() = %+v, want an advisory because %s %s", got, published, tt.wantReason)
			}
		})
	}
}

// TestOnlyGHGetsTheToken checks the runner the command runs with: gh gets
// the token in GH_TOKEN and GITHUB_TOKEN, as the job gives it, and trivy
// and skopeo get both empty, from stand-ins on PATH that print what they
// were given.
func TestOnlyGHGetsTheToken(t *testing.T) {
	bin := t.TempDir()
	for _, tool := range []string{"gh", "trivy", "skopeo"} {
		script := "#!/bin/sh\nprintf '%s:%s' \"${GH_TOKEN-unset}\" \"${GITHUB_TOKEN-unset}\"\n"
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the stand-in must be executable, and only by its owner
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN", "ghs_from_the_job")
	t.Setenv("GITHUB_TOKEN", "ghs_also_from_the_job")

	for tool, want := range map[string]string{
		"gh":     "ghs_from_the_job:ghs_also_from_the_job",
		"trivy":  ":",
		"skopeo": ":",
	} {
		res, err := tokenOnlyForGH{}.Run(t.Context(), tool)
		if err != nil || res.Code != 0 {
			t.Fatalf("%s: %v, exit %d: %s", tool, err, res.Code, res.Stderr)
		}
		if got := string(res.Stdout); got != want {
			t.Errorf("%s was given GH_TOKEN:GITHUB_TOKEN %q, want %q", tool, got, want)
		}
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
			execx.Call{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
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
			execx.Call{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
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

// TestRunBaselineStaysInItsDirectory (CI-24) checks that the empty
// baseline written when nothing is published is written inside its
// directory, as the summary is: a -baseline that is a symlink leading out
// of it fails the run, and the file it leads to is left as it was.
func TestRunBaselineStaysInItsDirectory(t *testing.T) {
	t.Parallel()

	dir, outside := t.TempDir(), t.TempDir()
	layout, rep, base, sarif := filepath.Join(dir, "layout"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "r.sarif")
	target := filepath.Join(outside, "elsewhere.json")
	if err := os.WriteFile(target, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, base); err != nil {
		t.Fatal(err)
	}
	scanArgs := []string{"--severity", "HIGH,CRITICAL", "--format", "json"}
	runner := trivy{
		fake: execx.NewFake(t,
			execx.Call{Argv: append(append([]string{"trivy", "image", "--input", layout}, scanArgs...), "--output", rep)},
			execx.Call{Argv: []string{"trivy", "convert", "--format", "sarif", "--output", sarif, rep}},
			execx.Call{Argv: skopeoArgv, Result: execx.Result{Stderr: skopeoRecording(t, "skopeo-no-such-package.txt"), Code: 1}},
		),
		reports: map[string]string{rep: report(t, "amd64", "", 1)},
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-layout", layout, "-report", rep, "-published", published, "-baseline", base, "-sarif", sarif}
	if code := run(t.Context(), args, runner, func(string) string { return "" }, &stdout, &stderr); code != 1 {
		t.Errorf("run() = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write the baseline") {
		t.Errorf("stderr = %q, want it to say the baseline could not be written", stderr.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "untouched\n" { //nolint:gosec // G304: the test's own temporary file
		t.Errorf("the file the symlink leads to holds %q (%v), want it untouched", got, err)
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
// engine matrix does, with ENGINE set, and skips without either tool.
func TestScanAgainstItself(t *testing.T) {
	t.Parallel()

	if os.Getenv("ENGINE") == "" {
		t.Skip("ENGINE is unset: the scan against the published fixture runs in the engine matrix")
	}
	for _, tool := range []string{"skopeo", "trivy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not on PATH")
		}
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
