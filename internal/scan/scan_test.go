// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

// testdata/README.md says how each file there was made.

const (
	fixtureDigest = "ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
	latest        = "ghcr.io/divbast/librespeed:latest"
)

// goJose is the one HIGH finding Trivy reports in the fixture.
var goJose = scan.Finding{
	ID:       "CVE-2026-116587",
	Pkg:      "github.com/go-jose/go-jose/v3",
	Version:  "v3.0.5",
	Severity: "HIGH",
	URL:      "https://avd.aquasec.com/nvd/cve-2026-116587",
	Where:    "usr/local/bin/frankenphp",
}

// readTestdata returns the file name in testdata.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot("testdata")
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

// parse returns the findings in the report name in testdata, or none for
// "", which stands for the {} written when nothing is published.
func parse(t *testing.T, name string) []scan.Finding {
	t.Helper()
	if name == "" {
		return nil
	}
	rep, err := scan.ParseTrivy(bytes.NewReader(readTestdata(t, name)))
	if err != nil {
		t.Fatalf("ParseTrivy(%s): %v", name, err)
	}
	return rep.Findings
}

func TestParseTrivyCountsPackages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		report       []byte
		wantFindings []scan.Finding
		wantPackages int
		wantArch     string
	}{
		{
			name:         "fixture",
			report:       readTestdata(t, "trivy-librespeed.json"),
			wantFindings: []scan.Finding{goJose},
			// 14 Debian packages and 178 modules in the FrankenPHP binary
			wantPackages: 192,
			wantArch:     "amd64",
		},
		{
			name:         "published-fixture",
			report:       readTestdata(t, "trivy-librespeed-published.json"),
			wantFindings: []scan.Finding{goJose},
			wantPackages: 192,
			wantArch:     "amd64",
		},
		{
			name:   "synthetic",
			report: readTestdata(t, "trivy-synthetic-candidate.json"),
			wantFindings: []scan.Finding{
				{
					ID: "CVE-2026-0001", Pkg: "libssl3t64", Version: "3.5.1-1", Fixed: "3.5.1-2", Severity: "CRITICAL",
					URL: "https://avd.aquasec.com/nvd/cve-2026-0001", Where: "debian package",
				},
				{ID: "CVE-2026-0002", Pkg: "zlib1g", Version: "1.3", Severity: "HIGH", Where: "debian package"},
				{
					ID: "CVE-2026-0003", Pkg: "std|lib", Version: "v1.27.3\nrc1", Fixed: "1.27.4, 1.28.1", Severity: "HIGH",
					URL: "https://example.test/a|b", Where: "usr/local/bin/a|b",
				},
				{ID: "CVE-2026-0001", Pkg: "stdlib", Version: "v1.27.3", Severity: "HIGH", Where: "usr/local/bin/a|b"},
			},
			wantPackages: 3,
			wantArch:     "arm64",
		},
		{
			// What the scan writes as the baseline when nothing is published
			name:   "empty",
			report: []byte("{}\n"),
		},
		{
			name:   "no-results",
			report: []byte(`{"Metadata":{"ImageConfig":{"architecture":"amd64"}},"Results":null}`),
			// A clean report that saw no packages, which the scan refuses
			wantArch: "amd64",
		},
		{
			name:         "packages-but-no-vulnerabilities",
			report:       []byte(`{"Results":[{"Target":"t","Class":"os-pkgs","Type":"debian","Packages":[{"ID":"a"},{"ID":"b"}]}]}`),
			wantPackages: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep, err := scan.ParseTrivy(bytes.NewReader(tt.report))
			if err != nil {
				t.Fatalf("ParseTrivy() error = %v", err)
			}
			if !slices.Equal(rep.Findings, tt.wantFindings) {
				t.Errorf("findings = %+v, want %+v", rep.Findings, tt.wantFindings)
			}
			if rep.Packages != tt.wantPackages {
				t.Errorf("packages = %d, want %d", rep.Packages, tt.wantPackages)
			}
			if rep.Arch != tt.wantArch {
				t.Errorf("arch = %q, want %q", rep.Arch, tt.wantArch)
			}
		})
	}
}

func TestParseTrivyRejects(t *testing.T) {
	t.Parallel()

	for name, report := range map[string]string{
		"empty-input":   "",
		"not-json":      "FATAL could not scan",
		"truncated":     `{"Results":[{"Target":"t"`,
		"trailing-data": `{} {}`,
		"wrong-shape":   `{"Results":{"Target":"t"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := scan.ParseTrivy(strings.NewReader(report)); err == nil {
				t.Errorf("ParseTrivy(%q) error = nil, want one", report)
			}
		})
	}
}

// TestParseTrivyRef checks what a report says it scanned: the image's
// first repository digest, or the name Trivy was given when it has none.
func TestParseTrivyRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		report []byte
		want   string
	}{
		{name: "published-by-digest", report: readTestdata(t, "trivy-librespeed-published.json"), want: fixtureDigest},
		// An OCI layout has no repository digest, only the name it was given
		{name: "layout", report: readTestdata(t, "trivy-librespeed.json"), want: "layout-amd64"},
		{
			name:   "first-digest",
			report: []byte(`{"ArtifactName":"ghcr.io/a/b:latest","Metadata":{"RepoDigests":["ghcr.io/a/b@sha256:01","ghcr.io/a/b@sha256:02"]}}`),
			want:   "ghcr.io/a/b@sha256:01",
		},
		{
			name:   "empty-digests",
			report: []byte(`{"ArtifactName":"ghcr.io/a/b:latest","Metadata":{"RepoDigests":[]}}`),
			want:   "ghcr.io/a/b:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rep, err := scan.ParseTrivy(bytes.NewReader(tt.report))
			if err != nil {
				t.Fatalf("ParseTrivy() error = %v", err)
			}
			if rep.Ref != tt.want {
				t.Errorf("ParseTrivy().Ref = %q, want %q", rep.Ref, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	a := scan.Finding{ID: "CVE-1", Pkg: "openssl", Version: "3.0.1", Severity: "HIGH"}
	// The same advisory in the same package at another affected version
	aBumped := scan.Finding{ID: "CVE-1", Pkg: "openssl", Version: "3.0.2", Severity: "CRITICAL", Fixed: "3.0.3"}
	// The same advisory in another package
	aElsewhere := scan.Finding{ID: "CVE-1", Pkg: "libssl3t64", Version: "3.0.1", Severity: "HIGH"}
	b := scan.Finding{ID: "CVE-2", Pkg: "zlib", Version: "1.3", Severity: "HIGH"}
	c := scan.Finding{ID: "CVE-3", Pkg: "stdlib", Version: "v1.27.3", Severity: "HIGH"}

	tests := []struct {
		name                 string
		candidate, published []scan.Finding
		want                 scan.Split
	}{
		{
			name:      "same-id-and-pkg-is-old",
			candidate: []scan.Finding{a},
			published: []scan.Finding{a},
			want:      scan.Split{Old: []scan.Finding{a}},
		},
		{
			name:      "same-id-and-pkg-at-another-version-is-old",
			candidate: []scan.Finding{aBumped},
			published: []scan.Finding{a},
			want:      scan.Split{Old: []scan.Finding{aBumped}},
		},
		{
			name:      "same-id-different-pkg-is-new",
			candidate: []scan.Finding{aElsewhere},
			published: []scan.Finding{a},
			want:      scan.Split{New: []scan.Finding{aElsewhere}},
		},
		{
			name:      "empty-published-is-all-new",
			candidate: []scan.Finding{a, b, c},
			want:      scan.Split{New: []scan.Finding{a, b, c}},
		},
		{
			name:      "candidate-order-kept",
			candidate: []scan.Finding{c, a, b, aElsewhere},
			published: []scan.Finding{b, a},
			want:      scan.Split{New: []scan.Finding{c, aElsewhere}, Old: []scan.Finding{a, b}},
		},
		{
			// jq's select keeps every candidate finding, duplicates too
			name:      "duplicates-kept",
			candidate: []scan.Finding{a, a, c, c},
			published: []scan.Finding{a},
			want:      scan.Split{New: []scan.Finding{c, c}, Old: []scan.Finding{a, a}},
		},
		{
			name:      "fixed-in-the-candidate",
			published: []scan.Finding{a, b},
		},
		{name: "nothing-anywhere"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := scan.Compare(tt.candidate, tt.published)
			if !slices.Equal(got.New, tt.want.New) {
				t.Errorf("New = %+v, want %+v", got.New, tt.want.New)
			}
			if !slices.Equal(got.Old, tt.want.Old) {
				t.Errorf("Old = %+v, want %+v", got.Old, tt.want.Old)
			}
		})
	}
}

// goldens are rendered by scan.sh's own jq from the same reports; see
// testdata/README.md.
var goldens = []struct {
	name, candidate, published   string
	arch, against                string
	verdict, heading, warning    string
	listingGolden, summaryGolden string
}{
	{
		name:          "blocking",
		candidate:     "trivy-librespeed.json",
		published:     "trivy-librespeed-published.json",
		arch:          "amd64",
		against:       fixtureDigest,
		verdict:       "new, so blocking",
		heading:       "New, so blocking",
		listingGolden: "listing.golden.txt",
		summaryGolden: "summary.golden.md",
	},
	{
		name:      "advisory",
		candidate: "trivy-librespeed.json",
		arch:      "amd64",
		against:   "nothing, because " + latest + " is not anonymously pullable",
		verdict:   "advisory: nothing published yet",
		heading:   "Advisory: nothing published yet",
		warning: "The scan is advisory because " + latest + " is not anonymously pullable: it is not published yet, " +
			"or it is private. It stays advisory until " + latest + " is public.",
		listingGolden: "listing-advisory.golden.txt",
		summaryGolden: "summary-advisory.golden.md",
	},
	{
		name:          "synthetic",
		candidate:     "trivy-synthetic-candidate.json",
		published:     "trivy-synthetic-published.json",
		arch:          "arm64",
		against:       "ghcr.io/divbast/x@sha256:00",
		verdict:       "new, so blocking",
		heading:       "New, so blocking",
		listingGolden: "listing-synthetic.golden.txt",
		summaryGolden: "summary-synthetic.golden.md",
	},
}

func TestSummaryGolden(t *testing.T) {
	t.Parallel()

	for _, tt := range goldens {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			split := scan.Compare(parse(t, tt.candidate), parse(t, tt.published))
			got := scan.Summary(tt.arch, tt.against, tt.heading, tt.warning, split)
			if want := string(readTestdata(t, tt.summaryGolden)); got != want {
				t.Errorf("Summary() differs from %s\n got: %q\nwant: %q", tt.summaryGolden, got, want)
			}
		})
	}
}

func TestListingGolden(t *testing.T) {
	t.Parallel()

	for _, tt := range goldens {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			split := scan.Compare(parse(t, tt.candidate), parse(t, tt.published))
			got := scan.Listing(tt.against, tt.verdict, split)
			if want := string(readTestdata(t, tt.listingGolden)); got != want {
				t.Errorf("Listing() differs from %s\n got: %q\nwant: %q", tt.listingGolden, got, want)
			}
		})
	}
}

func TestAdvisoryDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		file, image string
		want        bool
	}{
		// What a published image nobody can pull anonymously looks like,
		// for the image each was recorded against
		{file: "trivy-no-such-tag.txt", image: "ghcr.io/divbast/librespeed:no-such-tag", want: true},
		{file: "trivy-no-such-package.txt", image: "ghcr.io/divbast/no-such-package-t5:latest", want: true},
		{file: "trivy-name-unknown.txt", image: "public.ecr.aws/divbast/no-such-repo-t5:latest", want: true},
		// The repository is what counts, not the tag or digest asked for
		{file: "trivy-no-such-tag.txt", image: latest, want: true},
		{file: "trivy-no-such-tag.txt", image: fixtureDigest, want: true},
		{file: "trivy-no-such-package.txt", image: "ghcr.io/divbast/no-such-package-t5@sha256:00", want: true},
		// CI-25(a): a refusal of another repository's request, on the
		// same registry or another, says nothing of this image's
		{file: "trivy-no-such-package.txt", image: latest},
		{file: "trivy-no-such-tag.txt", image: "ghcr.io/divbast/libre:latest"},
		{file: "trivy-no-such-tag.txt", image: "ghcr.io/divbast/librespeed-dev:latest"},
		{file: "trivy-no-such-tag.txt", image: "ghcr.io/other/divbast/librespeed:latest"},
		{file: "trivy-name-unknown.txt", image: "ghcr.io/divbast/no-such-repo-t5:latest"},
		// What a registry that failed to answer looks like, which must never
		// pass for one with nothing published
		{file: "trivy-unauthorized.txt", image: "quay.io/divbast/no-such-repo-t5:latest"},
		{file: "trivy-no-such-host.txt", image: "no-such-host.invalid/divbast/librespeed:latest"},
		{file: "trivy-manifest-429.txt", image: latest},
		{file: "trivy-manifest-503.txt", image: latest},
	}

	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.image, func(t *testing.T) {
			t.Parallel()
			if got := scan.Unpullable(tt.image, readTestdata(t, tt.file)); got != tt.want {
				t.Errorf("Unpullable(%s, %s) = %t, want %t", tt.image, tt.file, got, tt.want)
			}
		})
	}

	// The code alone, outside the shape Trivy prints it in, is not a
	// refusal, nor is a refusal of another request of the same registry's
	for _, stderr := range []string{
		"", "DENIED", "MANIFEST_UNKNOWN: manifest unknown", "an image named ghcr.io/x/DENIED: 1",
		"remote error: GET https://ghcr.io/v2/divbast/librespeed: DENIED: 1",
		"remote error: GET https://ghcr.io/v2/aquasecurity/trivy-java-db/manifests/1: DENIED: denied",
		"remote error: GET https://ghcr.io/token?scope=repository%3Aaquasecurity%2Ftrivy-java-db%3Apull&service=ghcr.io: DENIED: denied",
		"remote error: GET https://ghcr.io/token?scope=repository%3Adivbast%2Flibrespeed%3Apush&service=ghcr.io: DENIED: denied",
	} {
		if scan.Unpullable(latest, []byte(stderr)) {
			t.Errorf("Unpullable(%s, %q) = true, want false", latest, stderr)
		}
	}
	// Nor is anything for a reference that names no repository
	for _, image := range []string{"", "librespeed", "ghcr.io/", "/divbast/librespeed"} {
		if scan.Unpullable(image, readTestdata(t, "trivy-no-such-tag.txt")) {
			t.Errorf("Unpullable(%q, trivy-no-such-tag.txt) = true, want false", image)
		}
	}
}

func TestTrivy(t *testing.T) {
	t.Parallel()

	logged := []byte("INFO\t[vuln] Vulnerability scanning is enabled\n")
	scanArgs := []string{"--severity", "HIGH,CRITICAL", "--format", "json"}
	layoutArgv := func(vex ...string) []string {
		argv := append([]string{"trivy", "image", "--input", "/w/layout"}, vex...)
		return append(append(argv, scanArgs...), "--output", "/w/report.json")
	}
	publishedArgv := func(arch string, vex ...string) []string {
		argv := append([]string{"trivy", "image", "--image-src", "remote", "--platform", "linux/" + arch, "--skip-db-update"}, vex...)
		return append(append(argv, scanArgs...), "--output", "/w/baseline.json", latest)
	}
	sarifArgv := []string{"trivy", "convert", "--format", "sarif", "--output", "/w/report.sarif", "/w/report.json"}

	tests := []struct {
		name    string
		vex     string
		call    execx.Call
		do      func(context.Context, scan.Trivy) error
		wantErr bool
		// wantIs, when set, is an error the returned one must wrap.
		wantIs error
		// wantLog is what must reach Log: Trivy's stderr, or nothing.
		wantLog []byte
	}{
		{
			name:    "layout",
			call:    execx.Call{Argv: layoutArgv(), Result: execx.Result{Stderr: logged}},
			do:      func(ctx context.Context, tr scan.Trivy) error { return tr.Layout(ctx, "/w/layout", "/w/report.json") },
			wantLog: logged,
		},
		{
			name:    "layout-vex",
			vex:     "baikal.openvex.json",
			call:    execx.Call{Argv: layoutArgv("--vex", "baikal.openvex.json"), Result: execx.Result{Stderr: logged}},
			do:      func(ctx context.Context, tr scan.Trivy) error { return tr.Layout(ctx, "/w/layout", "/w/report.json") },
			wantLog: logged,
		},
		{
			name:    "layout-fails",
			call:    execx.Call{Argv: layoutArgv(), Result: execx.Result{Stderr: []byte("FATAL no such layout\n"), Code: 1}},
			do:      func(ctx context.Context, tr scan.Trivy) error { return tr.Layout(ctx, "/w/layout", "/w/report.json") },
			wantErr: true,
			wantLog: []byte("FATAL no such layout\n"),
		},
		{
			name:    "trivy-missing",
			call:    execx.Call{Argv: layoutArgv(), Err: exec.ErrNotFound},
			do:      func(ctx context.Context, tr scan.Trivy) error { return tr.Layout(ctx, "/w/layout", "/w/report.json") },
			wantErr: true,
			wantIs:  exec.ErrNotFound,
		},
		{
			// Its log stays out of the way, as scan.sh kept it in a file
			name: "published",
			call: execx.Call{Argv: publishedArgv("arm64"), Result: execx.Result{Stderr: logged}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "arm64", "/w/baseline.json")
			},
		},
		{
			name: "published-vex",
			vex:  "baikal.openvex.json",
			call: execx.Call{Argv: publishedArgv("amd64", "--vex", "baikal.openvex.json")},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
		},
		{
			name: "published-unpullable",
			call: execx.Call{Argv: publishedArgv("amd64"), Result: execx.Result{Stderr: readTestdata(t, "trivy-no-such-tag.txt"), Code: 1}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
			wantErr: true,
			wantIs:  scan.ErrUnpullable,
		},
		{
			// CI-25(a): a refusal of another repository's request says
			// nothing of the published image's
			name: "published-another-repository-refused",
			call: execx.Call{Argv: publishedArgv("amd64"), Result: execx.Result{Stderr: readTestdata(t, "trivy-no-such-package.txt"), Code: 1}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
			wantErr: true,
			wantLog: readTestdata(t, "trivy-no-such-package.txt"),
		},
		{
			name: "published-rate-limited",
			call: execx.Call{Argv: publishedArgv("amd64"), Result: execx.Result{Stderr: readTestdata(t, "trivy-manifest-429.txt"), Code: 1}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
			wantErr: true,
			wantLog: readTestdata(t, "trivy-manifest-429.txt"),
		},
		{
			// A refusal Trivy printed but then exited 0 on is no refusal
			name: "published-refusal-text-but-success",
			call: execx.Call{Argv: publishedArgv("amd64"), Result: execx.Result{Stderr: readTestdata(t, "trivy-no-such-tag.txt")}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
		},
		{
			name: "published-trivy-missing",
			call: execx.Call{Argv: publishedArgv("amd64"), Err: exec.ErrNotFound},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
			wantErr: true,
			wantIs:  exec.ErrNotFound,
		},
		{
			name: "sarif",
			call: execx.Call{Argv: sarifArgv, Result: execx.Result{Stderr: logged}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.SARIF(ctx, "/w/report.json", "/w/report.sarif")
			},
			wantLog: logged,
		},
		{
			name: "sarif-fails",
			call: execx.Call{Argv: sarifArgv, Result: execx.Result{Stderr: []byte("FATAL bad report\n"), Code: 1}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.SARIF(ctx, "/w/report.json", "/w/report.sarif")
			},
			wantErr: true,
			wantLog: []byte("FATAL bad report\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log bytes.Buffer
			tr := scan.Trivy{Run: execx.NewFake(t, tt.call), VEX: tt.vex, Log: &log}
			err := tt.do(t.Context(), tr)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, want error %t", err, tt.wantErr)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error = %v, want one wrapping %v", err, tt.wantIs)
			}
			// A failure that read as unpullable would pass for nothing published
			if got, want := errors.Is(err, scan.ErrUnpullable), errors.Is(tt.wantIs, scan.ErrUnpullable); got != want {
				t.Errorf("errors.Is(%v, ErrUnpullable) = %t, want %t", err, got, want)
			}
			if !bytes.Equal(log.Bytes(), tt.wantLog) {
				t.Errorf("log = %q, want %q", log.Bytes(), tt.wantLog)
			}
		})
	}
}
