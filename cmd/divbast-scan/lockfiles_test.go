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
	"github.com/divbast/ci/internal/pnpmlock"
	"github.com/divbast/ci/internal/scan"
)

// The lockfile the tests' images declare, where the recordings in
// internal/scan's testdata found it, and the label that declares it.
const (
	lockPath  = "usr/share/doc/app/pnpm-lock.yaml"
	lockLabel = "/" + lockPath
)

// fixtureLock is internal/pnpmlock's fixture, which pnpm 12 wrote: its
// testdata README says how. grype-lockfile.json is grype's scan of it.
func fixtureLock(t *testing.T) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join("..", "..", "internal", "pnpmlock", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile("pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// lockRunner answers as the real tools would, through a Fake that checks
// every argv, where {DIR} stands for the directory run makes in tmp for
// the files an image declares, its lockfiles and its SBOMs. A call that succeeds writes, for each -o FORMAT=PATH or
// --output PATH it names, the content scripted for PATH, {DIR} standing
// in; a skopeo copy that succeeds writes the published image into the
// layout it names. It keeps the lockfile each dir: scan found, by its
// root, and the file each sbom: scan read, by its path.
type lockRunner struct {
	t         *testing.T
	fake      *execx.Fake
	tmp       string
	files     map[string][]byte
	published func(dir string)

	dir  string
	seen map[string]string
}

func (l *lockRunner) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	prefix := filepath.Join(l.tmp, "divbast-scan-declared-")
	argv := slices.Clone(args)
	for i, a := range argv {
		if j := strings.Index(a, prefix); l.dir == "" && j >= 0 {
			rest := a[j:]
			if k := strings.Index(rest[len(prefix):], string(filepath.Separator)); k >= 0 {
				rest = rest[:len(prefix)+k]
			}
			l.dir = rest
		}
		if l.dir != "" {
			argv[i] = strings.ReplaceAll(a, l.dir, "{DIR}")
		}
		if root, ok := strings.CutPrefix(a, "dir:"); ok {
			data, err := os.ReadFile(filepath.Join(root, lockPath)) //nolint:gosec // G304: a path run made, read back
			if err != nil {
				l.t.Errorf("grype scanned %s, which holds no %s: %v", root, lockPath, err)
			}
			l.seen[argv[i]] = string(data)
		}
		if file, ok := strings.CutPrefix(a, "sbom:"); ok {
			data, err := os.ReadFile(file) //nolint:gosec // G304: a path run made, read back
			if err != nil {
				l.t.Errorf("grype scanned %s, which run did not write: %v", file, err)
			}
			l.seen[argv[i]] = string(data)
		}
	}
	res, err := l.fake.Run(ctx, name, argv...)
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
		scripted := path
		if l.dir != "" {
			scripted = strings.ReplaceAll(path, l.dir, "{DIR}")
		}
		if content, ok := l.files[scripted]; ok && path != "" {
			if err := os.WriteFile(path, content, 0o600); err != nil {
				return res, err
			}
		}
	}
	if name == "skopeo" && len(args) > 0 && args[0] == "copy" {
		l.published(strings.TrimPrefix(args[len(args)-1], "oci:"))
	}
	return res, nil
}

// copyArgv is skopeo copying the pinned published image's arm64 image
// into the layout run makes for it.
var copyArgv = []string{
	"skopeo", "copy", "--quiet", "--src-no-creds", "--override-os", "linux", "--override-arch", "arm64",
	"docker://" + digest, "oci:{DIR}/published-layout",
}

func TestRunLockfiles(t *testing.T) {
	t.Parallel()

	lock := fixtureLock(t)
	dhiReport, dhiCDX, dhiSARIF := recorded(t, "grype-dhi.json"), recorded(t, "grype-dhi.cdx.json"), recorded(t, "grype-dhi.sarif")
	lockReport, lockCDX, lockSARIF := recorded(t, "grype-lockfile.json"), recorded(t, "grype-lockfile.cdx.json"), recorded(t, "grype-lockfile.sarif")
	probeHit := recorded(t, "grype-probe-dhi-13.json")
	index := &execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}
	refused := &execx.Result{Stderr: skopeoRecording(t, "skopeo-no-such-package.txt"), Code: 1}

	// The published lockfile without minimist's finding or lodash's two,
	// and with each package at an older version: all three are new
	pubLock, pubLockCDX := edited(t, lockReport, "GHSA-xvch-5gv4-984h", lockCDX, "minimist", "1.2.4")
	pubLock, pubLockCDX = edited(t, pubLock, "GHSA-35jh-r3h4-6jhm", pubLockCDX, "lodash", "4.17.19")
	pubLock, _ = edited(t, pubLock, "GHSA-r5fr-rjxr-66jc", pubLockCDX, "lodash", "4.17.19")
	// The lockfile's packages with minimist at 1.2.4
	_, olderMinimist := edited(t, lockReport, "", lockCDX, "minimist", "1.2.4")
	// The published lockfile without minimist's finding, at the same
	// version: already shipped by the version rule alone, which only the
	// published lockfile's packages show
	noMinimistFinding, _ := edited(t, lockReport, "GHSA-xvch-5gv4-984h", lockCDX, "", "")
	// A CycloneDX of the lockfile in which grype found no package
	noPackages := []byte(`{"components":[{"type":"file","name":"/` + lockPath + `"}]}`)
	// A second lockfile, declared beside the first
	const second = "srv/b/pnpm-lock.yaml"

	labelled := map[string]string{lockfileLabel: lockLabel}
	tests := []struct {
		name string
		// labels and files are the candidate's labels and its files
		// beside its os-release; nil, the label and the lockfile.
		labels map[string]string
		files  []imageFile
		// pubLabels are the published image's labels, and pubLock its
		// lockfile's grype report and CycloneDX; nil, no lockfile.
		// pubNoFile leaves the file out of the published image.
		pubLabels            map[string]string
		pubNoFile            bool
		pubReport, pubCDX    []byte
		candidateCDX         []byte
		skopeo               *execx.Result
		copyResult           *execx.Result
		wantCode             int
		wantStdout           []string
		notInStdout          []string
		wantStderr           []string
		notInStderr          []string
		wantSummary          []string
		wantRules, notInRule []string
	}{
		{
			// The published image carries the same lockfile: every finding
			// in it already published
			name:      "already-published",
			pubLabels: labelled, pubReport: lockReport, pubCDX: lockCDX,
			skopeo: index, copyResult: &execx.Result{},
			wantStdout: []string{
				"declares " + lockLabel + " in its " + lockfileLabel + " label, so grype scans them too, and their findings in build-only packages never block\n",
				"7 already published, so advisory:",
				"  GHSA-xvch-5gv4-984h CRITICAL minimist 1.2.5, fixed in 1.2.6, " + lockPath + "\n",
				"nothing new against what is published (7 advisory)",
			},
			wantSummary: []string{"| [GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h) | CRITICAL | `minimist` | 1.2.5 | 1.2.6 | " + lockPath + " |"},
			// The lockfile's HIGH and CRITICAL findings, in the image's one
			// run of grype's, and its MEDIUM ones not
			wantRules: []string{"GHSA-xvch-5gv4-984h-minimist", "GHSA-r5fr-rjxr-66jc-lodash", "DHI-fwcj-m32u-e4uq-6hzy-brotli"},
			notInRule: []string{"GHSA-29mw-wpgm-hmr9-lodash"},
		},
		{
			// The published lockfile had minimist at another affected
			// version: the same advisory, so already published, which only
			// the published lockfile's findings show
			name:      "bumped-within-affected",
			pubLabels: labelled, pubReport: lockReport, pubCDX: olderMinimist,
			skopeo: index, copyResult: &execx.Result{},
			wantStdout: []string{"nothing new against what is published (7 advisory)"},
		},
		{
			name:      "published-inventory-alone",
			pubLabels: labelled, pubReport: noMinimistFinding, pubCDX: lockCDX,
			skopeo: index, copyResult: &execx.Result{},
			wantStdout: []string{"nothing new against what is published (7 advisory)"},
		},
		{
			// minimist is a runtime dependency, and blocks; lodash only a
			// devDependency's, and is listed. The published image's own
			// node_modules has lodash with GHSA-35jh, so the lockfile's is
			// already published, as for any package of that name
			name:      "runtime-new-blocks",
			pubLabels: labelled, pubReport: pubLock, pubCDX: pubLockCDX,
			skopeo: index, copyResult: &execx.Result{},
			wantCode: 1,
			wantStdout: []string{
				"1 new, so blocking:\n  GHSA-xvch-5gv4-984h CRITICAL minimist 1.2.5, fixed in 1.2.6, " + lockPath + "\n",
				"1 new in a lockfile's build-only packages, so listed, not blocking:\n" +
					"  GHSA-r5fr-rjxr-66jc HIGH lodash 4.17.20, fixed in 4.18.0, " + lockPath + "\n",
				"5 already published, so advisory:",
				"  GHSA-35jh-r3h4-6jhm HIGH lodash 4.17.20, fixed in 4.17.21, " + lockPath + "\n",
			},
			wantStderr:  []string{"1 finding(s) the published image does not have"},
			wantSummary: []string{"**New in a lockfile's build-only packages, so listed, not blocking: 1**"},
		},
		{
			// Until a published image carries a lockfile, none of its
			// findings blocks
			name:   "published-carries-none",
			skopeo: index, copyResult: &execx.Result{},
			wantStdout: []string{
				digest + " carries no lockfile, so the findings in " + lockLabel + " are listed, not blocking, until a published image carries one",
				"0 new, so blocking:\n",
				"1 new in a lockfile the published image does not carry, so listed, not blocking:\n  GHSA-xvch-5gv4-984h CRITICAL minimist",
				"1 new in a lockfile's build-only packages, so listed, not blocking:\n  GHSA-r5fr-rjxr-66jc HIGH lodash",
				"nothing new against what is published (5 advisory, 2 in lockfiles listed, not blocking)",
			},
			wantSummary: []string{"**New in a lockfile the published image does not carry, so listed, not blocking: 1**"},
		},
		{
			// Nothing published: every finding an advisory, the lockfile's
			// runtime one with the image's, and nothing copied
			name:   "nothing-published",
			skopeo: refused,
			wantStdout: []string{
				"4 advisory: nothing readable to compare with:",
				"  GHSA-xvch-5gv4-984h CRITICAL minimist 1.2.5, fixed in 1.2.6, " + lockPath + "\n",
				"2 new in a lockfile's build-only packages, so listed, not blocking:",
				"so all 7 finding(s) are advisory",
			},
			notInStdout: []string{"published image does not carry"},
		},
		{
			name:         "no-package-found",
			candidateCDX: noPackages,
			wantCode:     1,
			wantStderr:   []string{"grype found no package in " + lockLabel + ", so a clean scan of it would prove nothing"},
		},
		{
			name:      "published-no-package-found",
			pubLabels: labelled, pubReport: lockReport, pubCDX: noPackages,
			skopeo: index, copyResult: &execx.Result{},
			wantCode:   1,
			wantStderr: []string{"could not tell which lockfiles " + digest + " carries", "grype found no package in " + lockLabel},
		},
		{
			name:   "copy-fails",
			skopeo: index, copyResult: &execx.Result{Stderr: skopeoRecording(t, "skopeo-manifest-503.txt"), Code: 1},
			wantCode:   1,
			wantStderr: []string{"could not tell which lockfiles " + digest + " carries", "could not copy " + digest, "503"},
		},
		{
			// The published image's own label is held to the candidate's
			// rules, and no error names the copy's temporary directory
			name:      "published-label-names-no-file",
			pubLabels: labelled, pubNoFile: true,
			skopeo: index, copyResult: &execx.Result{},
			wantCode: 1,
			wantStderr: []string{
				"could not tell which lockfiles " + digest + " carries",
				digest + " declares " + lockLabel + " in its " + lockfileLabel + " label, but holds no file there",
			},
			notInStderr: []string{"divbast-scan-declared-"},
		},
		{
			name:      "published-label-malformed",
			pubLabels: map[string]string{lockfileLabel: lockPath},
			skopeo:    index, copyResult: &execx.Result{},
			wantCode:    1,
			wantStderr:  []string{digest + "'s " + lockfileLabel + ` label names "` + lockPath + `"`},
			notInStderr: []string{"divbast-scan-declared-"},
		},
		{
			// Each lockfile must hold a package grype found, not only the
			// report as a whole
			name:       "two-lockfiles-one-empty",
			labels:     map[string]string{lockfileLabel: lockLabel + ",/" + second},
			files:      []imageFile{{name: lockPath, body: string(lock)}, {name: second, body: string(lock)}},
			wantCode:   1,
			wantStderr: []string{"grype found no package in /" + second + ", so a clean scan of it would prove nothing"},
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
				labels, extra = labelled, []imageFile{{name: lockPath, body: string(lock)}}
			}
			writeImage(t, p("layout"), dhiRelease, "arm64", labels, extra...)

			candidateCDX := lockCDX
			if tt.candidateCDX != nil {
				candidateCDX = tt.candidateCDX
			}
			files := map[string][]byte{
				p("report.json"): dhiReport, p("report.json.cdx.json"): dhiCDX, p("report.sarif"): dhiSARIF,
				p("report.json.lockfiles.json"): lockReport, p("report.json.lockfiles.cdx.json"): candidateCDX,
				"{DIR}/candidate.sarif": lockSARIF,
			}
			calls := []execx.Call{
				{Argv: []string{"grype", "-c", cfg, "db", "update"}},
				{Argv: []string{"grype", "-c", cfg, dhiProbe, "-o", "json"}, Result: execx.Result{Stdout: probeHit}},
				{Argv: []string{
					"grype", "-c", cfg, "oci-dir:" + p("layout"), "--platform", "linux/arm64",
					"-o", "json=" + p("report.json"), "-o", "cyclonedx-json=" + p("report.json.cdx.json"), "-o", "sarif=" + p("report.sarif"),
				}},
				{Argv: []string{
					"grype", "-c", cfg, "dir:{DIR}/candidate",
					"-o", "json=" + p("report.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("report.json.lockfiles.cdx.json"),
					"-o", "sarif={DIR}/candidate.sarif",
				}},
			}
			if tt.skopeo != nil {
				calls = append(calls, execx.Call{Argv: skopeoArgv, Result: *tt.skopeo})
			}
			if tt.copyResult != nil {
				calls = append(calls,
					execx.Call{Argv: []string{
						"grype", "-c", cfg, "registry:" + digest, "--platform", "linux/arm64",
						"-o", "json=" + p("baseline.json"), "-o", "cyclonedx-json=" + p("baseline.json.cdx.json"),
					}},
					execx.Call{Argv: copyArgv, Result: *tt.copyResult})
				files[p("baseline.json")], files[p("baseline.json.cdx.json")] = dhiReport, dhiCDX
			}
			if tt.pubReport != nil {
				calls = append(calls, execx.Call{Argv: []string{
					"grype", "-c", cfg, "dir:{DIR}/published",
					"-o", "json=" + p("baseline.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("baseline.json.lockfiles.cdx.json"),
				}})
				files[p("baseline.json.lockfiles.json")], files[p("baseline.json.lockfiles.cdx.json")] = tt.pubReport, tt.pubCDX
			}
			runner := &lockRunner{
				t: t, fake: execx.NewFake(t, calls...), tmp: tmp, files: files, seen: map[string]string{},
				published: func(layout string) {
					var extra []imageFile
					if tt.pubLabels != nil && !tt.pubNoFile {
						extra = append(extra, imageFile{name: lockPath, body: string(lock)})
					}
					writeImage(t, layout, dhiRelease, "arm64", tt.pubLabels, extra...)
				},
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
			// grype read the lockfile itself, at its path in the image
			if got := runner.seen["dir:{DIR}/candidate"]; got != string(lock) {
				t.Errorf("the candidate's lockfile scan found %d bytes at %s, want the image's %d", len(got), lockPath, len(lock))
			}
			if tt.pubReport != nil && runner.seen["dir:{DIR}/published"] != string(lock) {
				t.Errorf("the published lockfile scan did not find the published image's lockfile at %s", lockPath)
			}
			if len(tt.wantRules) > 0 {
				_, rules := sarifRuleIDs(t, p("report.sarif"))
				for _, want := range tt.wantRules {
					if !slices.Contains(rules, want) {
						t.Errorf("SARIF rules %q, want %s among them", rules, want)
					}
				}
				for _, not := range tt.notInRule {
					if slices.Contains(rules, not) {
						t.Errorf("SARIF rules %q, want no %s: it is MEDIUM", rules, not)
					}
				}
			}
			// The lockfiles' directory is gone, whatever the verdict
			if left, err := os.ReadDir(tmp); err != nil || len(left) > 0 {
				t.Errorf("run() left %v in its TMPDIR (error %v), want nothing", left, err)
			}
		})
	}
}

// sarifRuleIDs reads the SARIF at path: how many runs it holds, and every
// run's rules' IDs.
func sarifRuleIDs(t *testing.T, path string) (runs int, rules []string) {
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
		}
	}
	if err = json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Runs {
		for _, rule := range r.Tool.Driver.Rules {
			rules = append(rules, rule.ID)
		}
	}
	return len(s.Runs), rules
}

// TestRunLockfilesTrivy checks that an image Trivy scans has its lockfiles
// scanned by grype, configured and updated for them alone, and that
// grype's findings go beside Trivy's, its SARIF a run of its own.
func TestRunLockfilesTrivy(t *testing.T) {
	t.Parallel()
	lock := fixtureLock(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	tmp := p("tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := p("cache")
	cfg := filepath.Join(cache, "grype.yaml")
	labelled := map[string]string{lockfileLabel: lockLabel}
	writeImage(t, p("layout"), debianRelease, "arm64", labelled, imageFile{name: lockPath, body: string(lock)})

	pubLock, pubLockCDX := edited(t, recorded(t, "grype-lockfile.json"), "GHSA-xvch-5gv4-984h", recorded(t, "grype-lockfile.cdx.json"), "minimist", "1.2.4")
	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	trivySARIF := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"CVE-1"}]}},"results":[{"ruleId":"CVE-1"}]}]}`)
	files := map[string][]byte{
		p("report.json"):                []byte(report(t, "arm64", "", 3, "CVE-1")),
		p("report.sarif"):               trivySARIF,
		p("baseline.json"):              []byte(report(t, "arm64", digest, 3, "CVE-1")),
		p("report.json.lockfiles.json"): recorded(t, "grype-lockfile.json"), p("report.json.lockfiles.cdx.json"): recorded(t, "grype-lockfile.cdx.json"),
		"{DIR}/candidate.sarif":           recorded(t, "grype-lockfile.sarif"),
		p("baseline.json.lockfiles.json"): pubLock, p("baseline.json.lockfiles.cdx.json"): pubLockCDX,
	}
	calls := []execx.Call{
		{Argv: append(append([]string{"trivy", "image", "--input", p("layout")}, scanArgs...), "--output", p("report.json"))},
		{Argv: []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", p("report.sarif"), p("report.json")}},
		{Argv: []string{"grype", "-c", cfg, "db", "update"}},
		{Argv: []string{
			"grype", "-c", cfg, "dir:{DIR}/candidate",
			"-o", "json=" + p("report.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("report.json.lockfiles.cdx.json"),
			"-o", "sarif={DIR}/candidate.sarif",
		}},
		{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
		{Argv: append(append([]string{
			"trivy", "image", "--image-src", "remote", "--platform", "linux/arm64", "--skip-db-update",
		}, scanArgs...), "--output", p("baseline.json"), digest)},
		{Argv: copyArgv},
		{Argv: []string{
			"grype", "-c", cfg, "dir:{DIR}/published",
			"-o", "json=" + p("baseline.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("baseline.json.lockfiles.cdx.json"),
		}},
	}
	runner := &lockRunner{
		t: t, fake: execx.NewFake(t, calls...), tmp: tmp, files: files, seen: map[string]string{},
		published: func(layout string) {
			writeImage(t, layout, debianRelease, "arm64", labelled, imageFile{name: lockPath, body: string(lock)})
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
	if want := "1 new, so blocking:\n  GHSA-xvch-5gv4-984h CRITICAL minimist 1.2.5, fixed in 1.2.6, " + lockPath + "\n"; !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
	}
	runs, rules := sarifRuleIDs(t, p("report.sarif"))
	if runs != 2 || !slices.Contains(rules, "CVE-1") || !slices.Contains(rules, "GHSA-xvch-5gv4-984h-minimist") {
		t.Errorf("SARIF holds %d runs with rules %q; want Trivy's and grype's, each with its own", runs, rules)
	}
}

// TestRunLockfilesNoFindingsSARIF checks that the SARIF written for an
// image with lockfiles and no findings holds an array wherever SARIF
// needs one: grype writes no rules for such a lockfile, and code scanning
// refuses a null in their place.
func TestRunLockfilesNoFindingsSARIF(t *testing.T) {
	t.Parallel()
	lock := fixtureLock(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	tmp := p("tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := p("cache")
	cfg := filepath.Join(cache, "grype.yaml")
	labelled := map[string]string{lockfileLabel: lockLabel}
	writeImage(t, p("layout"), debianRelease, "arm64", labelled, imageFile{name: lockPath, body: string(lock)})

	// The lockfile's packages, and none of the findings
	var clean map[string]any
	if err := json.Unmarshal(recorded(t, "grype-lockfile.json"), &clean); err != nil {
		t.Fatal(err)
	}
	clean["matches"] = []any{}
	lockReport, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	lockCDX := recorded(t, "grype-lockfile.cdx.json")
	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	files := map[string][]byte{
		p("report.json"):                []byte(report(t, "arm64", "", 3)),
		p("report.sarif"):               []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[]}},"results":[]}]}`),
		p("baseline.json"):              []byte(report(t, "arm64", digest, 3)),
		p("report.json.lockfiles.json"): lockReport, p("report.json.lockfiles.cdx.json"): lockCDX,
		"{DIR}/candidate.sarif":           []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype"}},"results":[]}]}`),
		p("baseline.json.lockfiles.json"): lockReport, p("baseline.json.lockfiles.cdx.json"): lockCDX,
	}
	calls := []execx.Call{
		{Argv: append(append([]string{"trivy", "image", "--input", p("layout")}, scanArgs...), "--output", p("report.json"))},
		{Argv: []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", p("report.sarif"), p("report.json")}},
		{Argv: []string{"grype", "-c", cfg, "db", "update"}},
		{Argv: []string{
			"grype", "-c", cfg, "dir:{DIR}/candidate",
			"-o", "json=" + p("report.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("report.json.lockfiles.cdx.json"),
			"-o", "sarif={DIR}/candidate.sarif",
		}},
		{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
		{Argv: append(append([]string{
			"trivy", "image", "--image-src", "remote", "--platform", "linux/arm64", "--skip-db-update",
		}, scanArgs...), "--output", p("baseline.json"), digest)},
		{Argv: copyArgv},
		{Argv: []string{
			"grype", "-c", cfg, "dir:{DIR}/published",
			"-o", "json=" + p("baseline.json.lockfiles.json"), "-o", "cyclonedx-json=" + p("baseline.json.lockfiles.cdx.json"),
		}},
	}
	runner := &lockRunner{
		t: t, fake: execx.NewFake(t, calls...), tmp: tmp, files: files, seen: map[string]string{},
		published: func(layout string) {
			writeImage(t, layout, debianRelease, "arm64", labelled, imageFile{name: lockPath, body: string(lock)})
		},
	}
	args := []string{
		"-layout", p("layout"), "-report", p("report.json"), "-published", published,
		"-baseline", p("baseline.json"), "-sarif", p("report.sarif"), "-cache", cache,
	}
	env := map[string]string{"TMPDIR": tmp}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), args, runner, execx.OS{}, offline(t), func(key string) string { return env[key] }, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, want 0; stderr: %s", code, stderr.String())
	}
	data, err := os.ReadFile(p("report.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results any
			Tool    struct{ Driver struct{ Rules any } }
		}
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("SARIF holds %d runs, want Trivy's and grype's", len(doc.Runs))
	}
	for i, r := range doc.Runs {
		if _, ok := r.Results.([]any); !ok {
			t.Errorf("runs[%d].results = %v, want an array", i, r.Results)
		}
		if _, ok := r.Tool.Driver.Rules.([]any); !ok {
			t.Errorf("runs[%d].tool.driver.rules = %v, want an array", i, r.Tool.Driver.Rules)
		}
	}
}

// TestRunLockfileRefusals checks that a label the scan cannot follow, a
// lockfile it does not hold or cannot read, fails before any scanner runs.
func TestRunLockfileRefusals(t *testing.T) {
	t.Parallel()
	lock := string(fixtureLock(t))
	tests := []struct {
		name  string
		label string
		files []imageFile
		want  []string
	}{
		{"empty", "", nil, []string{lockfileLabel, "empty path"}},
		{"empty-entry", lockLabel + ",", []imageFile{{name: lockPath, body: lock}}, []string{"empty path"}},
		{"relative", lockPath, []imageFile{{name: lockPath, body: lock}}, []string{`"` + lockPath + `"`, "no clean absolute path"}},
		{"unclean", "/usr/share/doc/../doc/app/pnpm-lock.yaml", nil, []string{"no clean absolute path"}},
		{"not-pnpm", "/usr/share/doc/app/package-lock.json", nil, []string{"package-lock.json", "only pnpm's lockfiles"}},
		{"twice", lockLabel + ", " + lockLabel, []imageFile{{name: lockPath, body: lock}}, []string{"twice"}},
		{"absent", lockLabel, nil, []string{"declares " + lockLabel, "holds no file there"}},
		{"symlink", lockLabel, []imageFile{{name: lockPath, link: "../../../../src/pnpm-lock.yaml"}}, []string{"symlink", "declare the file itself"}},
		{
			"unreadable", lockLabel,
			[]imageFile{{name: lockPath, body: "lockfileVersion: '6.0'\n"}},
			[]string{"cannot tell the runtime packages of " + lockLabel, "lockfileVersion 6.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := func(name string) string { return filepath.Join(dir, name) }
			writeImage(t, p("layout"), dhiRelease, "arm64", map[string]string{lockfileLabel: tt.label}, tt.files...)
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

func TestDeclared(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		labels map[string]string
		want   []string
	}{
		{"no-labels", nil, nil},
		{"other-labels", map[string]string{"org.opencontainers.image.title": "x"}, nil},
		{"one", map[string]string{lockfileLabel: lockLabel}, []string{lockPath}},
		{
			"two-in-order",
			map[string]string{lockfileLabel: " /srv/b/pnpm-lock.yaml ,/srv/a/pnpm-lock.yaml"},
			[]string{"srv/b/pnpm-lock.yaml", "srv/a/pnpm-lock.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := declared(tt.labels, "image")
			if err != nil || !slices.Equal(got, tt.want) {
				t.Errorf("declared() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// unreadableConfig makes the image's config in the layout at dir no
// JSON, and names its platform, linux/arch, in the index, so that only a
// read of the config itself fails: the scan reads the architecture from
// the index, and the os-release from the layers.
func unreadableConfig(t *testing.T, dir, arch string) {
	t.Helper()
	read := func(name string, v any) {
		data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: the test's own layout
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, v); err != nil {
			t.Fatal(err)
		}
	}
	var index struct{ Manifests []map[string]any }
	read("index.json", &index)
	m := index.Manifests[0]
	m["platform"] = map[string]string{"os": "linux", "architecture": arch}
	digest, _ := m["digest"].(string)
	var manifest struct{ Config struct{ Digest string } }
	read(filepath.Join("blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), &manifest)
	config := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(manifest.Config.Digest, "sha256:"))
	if err := os.WriteFile(config, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{m}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "index.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunLockfileUnreadable checks that an image whose config cannot be
// read, or a declared lockfile past the scan's limit, fails before any
// scanner runs, and that an unread config is not said to declare
// lockfiles.
func TestRunLockfileUnreadable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		files     []imageFile
		breakIt   bool
		want, not []string
	}{
		{
			name:    "config",
			breakIt: true,
			want:    []string{"could not read ", "'s config, so nothing says which files it declares to the scan"},
			not:     []string{"the lockfiles the image declares"},
		},
		{
			name:  "past-the-limit",
			files: []imageFile{{name: lockPath, body: strings.Repeat("a", maxLockfile+1)}},
			want: []string{
				"could not read the lockfiles the image declares",
				"/" + lockPath + " is 67108865 bytes, more than the 67108864 the reader takes for it",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := func(name string) string { return filepath.Join(dir, name) }
			writeImage(t, p("layout"), dhiRelease, "arm64", map[string]string{lockfileLabel: lockLabel}, tt.files...)
			if tt.breakIt {
				unreadableConfig(t, p("layout"), "arm64")
			}
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
			for _, not := range tt.not {
				if strings.Contains(stderr.String(), not) {
					t.Errorf("stderr = %q, want it not to contain %q", stderr.String(), not)
				}
			}
		})
	}
}

// TestHeld checks which findings held marks: a lockfile's in a package it
// places outside every runtime graph, always, and its others only while
// the published image carries no lockfile; never one found anywhere but
// in a declared lockfile, even with a package of the same name.
func TestHeld(t *testing.T) {
	t.Parallel()
	lock, err := pnpmlock.Read(fixtureLock(t))
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]*pnpmlock.Lockfile{lockPath: lock}
	for _, uncarried := range []bool{false, true} {
		findings := []scan.Finding{
			{ID: "GHSA-d", Pkg: "lodash", Version: "4.17.20", Where: lockPath},
			{ID: "GHSA-r", Pkg: "minimist", Version: "1.2.5", Where: lockPath},
			{ID: "GHSA-n", Pkg: "lodash", Version: "4.17.20", Where: "app/node_modules/lodash/package.json"},
			{ID: "CVE-1", Pkg: "stdlib", Version: "v1.27.3", Where: "usr/local/bin/pisati"},
		}
		held(findings, read, uncarried)
		runtime := ""
		if uncarried {
			runtime = scan.Uncarried
		}
		want := []string{scan.BuildOnly, runtime, "", ""}
		for i, f := range findings {
			if f.Hold != want[i] {
				t.Errorf("held(uncarried %t) gave %s in %s the hold %q, want %q", uncarried, f.ID, f.Where, f.Hold, want[i])
			}
		}
	}
}
