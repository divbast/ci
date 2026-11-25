// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// sameFindings reports whether a and b hold equal findings, in order:
// a Finding holds its aliases in a slice, so == cannot compare two.
func sameFindings(a, b []scan.Finding) bool {
	return slices.EqualFunc(a, b, func(x, y scan.Finding) bool { return reflect.DeepEqual(x, y) })
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
			if !sameFindings(rep.Findings, tt.wantFindings) {
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

func TestParseTrivyReadsOS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		report         string
		wantOS         string
		wantOSPackages int
		wantPackages   int
	}{
		{
			name: "debian",
			report: `{"Metadata":{"OS":{"Family":"debian","Name":"13.2"}},"Results":[` +
				`{"Class":"os-pkgs","Type":"debian","Packages":[{"ID":"a"},{"ID":"b"},{"ID":"c"}]}]}`,
			wantOS:         "debian 13.2",
			wantOSPackages: 3,
			wantPackages:   3,
		},
		{
			// An image whose OS Trivy did not recognise: the .NET packages
			// still count as packages
			name: "language-packages-only",
			report: `{"Results":[{"Class":"lang-pkgs","Type":"dotnet-core",` +
				`"Packages":[{"ID":"a"},{"ID":"b"},{"ID":"c"},{"ID":"d"},{"ID":"e"}]}]}`,
			wantPackages: 5,
		},
		{
			name: "os-with-language-packages",
			report: `{"Metadata":{"OS":{"Family":"debian","Name":"13.2"}},"Results":[` +
				`{"Class":"os-pkgs","Type":"debian","Packages":[{"ID":"a"}]},` +
				`{"Class":"lang-pkgs","Type":"gobinary","Packages":[{"ID":"b"},{"ID":"c"}]}]}`,
			wantOS:         "debian 13.2",
			wantOSPackages: 1,
			wantPackages:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep, err := scan.ParseTrivy(strings.NewReader(tt.report))
			if err != nil {
				t.Fatalf("ParseTrivy() error = %v", err)
			}
			if rep.OS != tt.wantOS {
				t.Errorf("OS = %q, want %q", rep.OS, tt.wantOS)
			}
			if rep.OSPackages != tt.wantOSPackages {
				t.Errorf("OSPackages = %d, want %d", rep.OSPackages, tt.wantOSPackages)
			}
			if rep.Packages != tt.wantPackages {
				t.Errorf("Packages = %d, want %d", rep.Packages, tt.wantPackages)
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
			got := scan.Compare(tt.candidate, tt.published, nil)
			if !sameFindings(got.New, tt.want.New) {
				t.Errorf("New = %+v, want %+v", got.New, tt.want.New)
			}
			if !sameFindings(got.Old, tt.want.Old) {
				t.Errorf("Old = %+v, want %+v", got.Old, tt.want.Old)
			}
		})
	}
}

func TestParseTrivyAliasesAndInventory(t *testing.T) {
	t.Parallel()
	// Trivy keeps a Debian package's epoch and revision apart in its list,
	// and joins them in a finding's InstalledVersion, as dpkg writes it
	report := `{"Metadata":{"OS":{"Family":"debian","Name":"13.2"}},"Results":[
		{"Target":"image (debian 13.2)","Class":"os-pkgs","Type":"debian",
		 "Packages":[
			{"ID":"zlib1g@1:1.3.dfsg-3","Name":"zlib1g","Version":"1.3.dfsg","Release":"3","Epoch":1},
			{"ID":"libbrotli1@1.1.0-1","Name":"libbrotli1","Version":"1.1.0","Release":"1"}],
		 "Vulnerabilities":[{"VulnerabilityID":"DHI-x","VendorIDs":["CVE-2026-1"],"PkgName":"libbrotli1",
			"InstalledVersion":"1.1.0-1","Severity":"HIGH"}]},
		{"Target":"usr/local/bin/app","Class":"lang-pkgs","Type":"gobinary",
		 "Packages":[{"ID":"stdlib@v1.27.3","Name":"stdlib","Version":"v1.27.3"},{"ID":"nameless"}]}]}`
	rep, err := scan.ParseTrivy(strings.NewReader(report))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Aliases != nil {
		t.Errorf("findings = %+v, want one with no aliases: Trivy's VendorIDs are bulletins, not aliases", rep.Findings)
	}
	wantInventory := []scan.Pkg{{"zlib1g", "1:1.3.dfsg-3"}, {"libbrotli1", "1.1.0-1"}, {"stdlib", "v1.27.3"}}
	if !slices.Equal(rep.Inventory, wantInventory) {
		t.Errorf("inventory = %+v, want %+v", rep.Inventory, wantInventory)
	}
	if rep.Family != "debian" {
		t.Errorf("family = %q, want debian", rep.Family)
	}
	if rep.Packages != 4 {
		t.Errorf("packages = %d, want 4: one with no name still counts", rep.Packages)
	}
}

// TestParseTrivyBulletinsAreNotAliases is two CVEs that one Debian
// security advisory fixes: Trivy lists the DSA as each one's VendorIDs,
// and one kernel DSA covers over a thousand CVEs. Read as aliases, the
// candidate's CVE would match the published image's other CVE, and a
// finding the published image lacks would pass as already shipped.
func TestParseTrivyBulletinsAreNotAliases(t *testing.T) {
	t.Parallel()
	report := func(id, version string) []scan.Finding {
		t.Helper()
		rep, err := scan.ParseTrivy(strings.NewReader(`{"Metadata":{"OS":{"Family":"debian","Name":"13.2"}},"Results":[
			{"Target":"image (debian 13.2)","Class":"os-pkgs","Type":"debian","Packages":[{"Name":"linux-libc-dev","Version":"` + version + `"}],
			 "Vulnerabilities":[{"VulnerabilityID":"` + id + `","VendorIDs":["DSA-6528-1"],"PkgName":"linux-libc-dev",
				"InstalledVersion":"` + version + `","FixedVersion":"6.12.111-1","Severity":"HIGH"}]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return rep.Findings
	}
	got := scan.Compare(report("CVE-2026-2", "6.12.100-1"), report("CVE-2026-1", "6.12.90-1"), nil)
	if len(got.New) != 1 || got.New[0].ID != "CVE-2026-2" {
		t.Errorf("Compare() = %+v, want CVE-2026-2 new: the published image lacks it", got)
	}
}

func TestCompareByAlias(t *testing.T) {
	t.Parallel()
	dhi := scan.Finding{ID: "DHI-x", Aliases: []string{"CVE-1"}, Pkg: "brotli", Version: "1.1.0-1", Severity: "HIGH"}
	tests := []struct {
		name      string
		candidate scan.Finding
		published scan.Finding
		old       bool
	}{
		{"candidate-alias-meets-published-id", dhi, scan.Finding{ID: "CVE-1", Pkg: "brotli"}, true},
		{"candidate-id-meets-published-alias", scan.Finding{ID: "CVE-1", Pkg: "brotli"}, dhi, true},
		{"aliases-meet", dhi, scan.Finding{ID: "DSA-9", Aliases: []string{"GHSA-a", "CVE-1"}, Pkg: "brotli"}, true},
		{"alias-in-another-package", dhi, scan.Finding{ID: "CVE-1", Pkg: "libbrotli1"}, false},
		{"no-shared-id", dhi, scan.Finding{ID: "CVE-2", Aliases: []string{"DHI-y"}, Pkg: "brotli"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := scan.Compare([]scan.Finding{tt.candidate}, []scan.Finding{tt.published}, nil)
			if old := len(got.Old) == 1; old != tt.old {
				t.Errorf("Compare() = %+v, want old %v", got, tt.old)
			}
		})
	}
}

func TestCompareByShippedVersion(t *testing.T) {
	t.Parallel()
	qemu := scan.Finding{ID: "DHI-y", Pkg: "qemu", Version: "9.2", Severity: "HIGH"}
	got := scan.Compare([]scan.Finding{qemu}, nil, []scan.Pkg{{"qemu", "9.2"}})
	if !sameFindings(got.Old, []scan.Finding{qemu}) || len(got.New) != 0 {
		t.Errorf("shipped at 9.2: Compare() = %+v, want it old", got)
	}
	got = scan.Compare([]scan.Finding{qemu}, nil, []scan.Pkg{{"qemu", "9.1"}})
	if !sameFindings(got.New, []scan.Finding{qemu}) || len(got.Old) != 0 {
		t.Errorf("shipped at 9.1: Compare() = %+v, want it new", got)
	}
	got = scan.Compare([]scan.Finding{qemu}, nil, []scan.Pkg{{"qemu-utils", "9.2"}})
	if !sameFindings(got.New, []scan.Finding{qemu}) {
		t.Errorf("another package at 9.2: Compare() = %+v, want it new", got)
	}
}

func TestCompareNewPackageBlocks(t *testing.T) {
	t.Parallel()
	f := scan.Finding{ID: "DHI-z", Aliases: []string{"CVE-3"}, Pkg: "libnew", Version: "1.0", Severity: "CRITICAL"}
	published := []scan.Finding{{ID: "CVE-3", Pkg: "libold", Version: "1.0"}}
	shipped := []scan.Pkg{{"libold", "1.0"}, {"zlib1g", "1:1.3.dfsg-3"}}
	got := scan.Compare([]scan.Finding{f}, published, shipped)
	if !sameFindings(got.New, []scan.Finding{f}) {
		t.Errorf("Compare() = %+v, want the new package's finding new", got)
	}
}

func TestCompareListsUnknown(t *testing.T) {
	t.Parallel()
	unknown := scan.Finding{ID: "DHI-u", Pkg: "qemu", Version: "11", Severity: "UNKNOWN"}
	high := scan.Finding{ID: "DHI-h", Pkg: "qemu", Version: "11", Severity: "HIGH"}
	oldUnknown := scan.Finding{ID: "DHI-o", Pkg: "curl", Version: "8", Severity: "UNKNOWN"}
	got := scan.Compare([]scan.Finding{unknown, high, oldUnknown}, []scan.Finding{oldUnknown}, nil)
	if !sameFindings(got.New, []scan.Finding{high}) || !sameFindings(got.Listed, []scan.Finding{unknown}) ||
		!sameFindings(got.Old, []scan.Finding{oldUnknown}) {
		t.Errorf("Compare() = %+v; want the HIGH new, the new UNKNOWN listed, the published one old", got)
	}
	listing := scan.Listing("x", "new, so blocking", &got)
	if !strings.Contains(listing, "1 new with no severity, so listed, not blocking:\n  DHI-u UNKNOWN qemu 11") {
		t.Errorf("Listing() = %q, want the UNKNOWN finding listed apart", listing)
	}
	summary := scan.Summary("amd64", "x", "New, so blocking", "", &got)
	if !strings.Contains(summary, "**New with no severity, so listed, not blocking: 1**") || !strings.Contains(summary, "DHI-u") {
		t.Errorf("Summary() = %q, want the UNKNOWN finding in a table of its own", summary)
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
			split := scan.Compare(parse(t, tt.candidate), parse(t, tt.published), nil)
			got := scan.Summary(tt.arch, tt.against, tt.heading, tt.warning, &split)
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
			split := scan.Compare(parse(t, tt.candidate), parse(t, tt.published), nil)
			got := scan.Listing(tt.against, tt.verdict, &split)
			if want := string(readTestdata(t, tt.listingGolden)); got != want {
				t.Errorf("Listing() differs from %s\n got: %q\nwant: %q", tt.listingGolden, got, want)
			}
		})
	}
}

// TestTrivyIgnoresCallerConfig runs the real trivy convert, which needs
// no database, from a directory holding a caller's .trivyignore and
// trivy.yaml, each of which would hide the fixture's one finding: Trivy
// reads both from its working directory unless told not to, and the scan
// runs from the caller's repository. The SARIF must still carry it.
// trivy image reads them the same way; TestTrivy pins that every call
// turns them off.
func TestTrivyIgnoresCallerConfig(t *testing.T) {
	// Not parallel: it changes the working directory
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Fatalf("trivy is not on PATH: %v", err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(report, readTestdata(t, "trivy-librespeed.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	caller := t.TempDir()
	for name, body := range map[string]string{
		".trivyignore": goJose.ID + "\n",
		"trivy.yaml":   "vulnerability:\n  ignore-unfixed: true\n",
	} {
		if err := os.WriteFile(filepath.Join(caller, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(caller)

	sarif := filepath.Join(t.TempDir(), "report.sarif")
	if err := (scan.Trivy{Run: execx.OS{}}).SARIF(t.Context(), report, sarif); err != nil {
		t.Fatalf("SARIF() error = %v", err)
	}
	data, err := os.ReadFile(sarif) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(goJose.ID)) {
		t.Errorf("the SARIF lacks %s: Trivy read the caller's .trivyignore or trivy.yaml", goJose.ID)
	}
}

func TestTrivy(t *testing.T) {
	t.Parallel()

	logged := []byte("INFO\t[vuln] Vulnerability scanning is enabled\n")
	scanArgs := []string{"--config", "", "--ignorefile", "", "--severity", "HIGH,CRITICAL", "--format", "json"}
	layoutArgv := func(vex ...string) []string {
		argv := append([]string{"trivy", "image", "--input", "/w/layout"}, vex...)
		return append(append(argv, scanArgs...), "--output", "/w/report.json")
	}
	publishedArgv := func(arch string, vex ...string) []string {
		argv := append([]string{"trivy", "image", "--image-src", "remote", "--platform", "linux/" + arch, "--skip-db-update"}, vex...)
		return append(append(argv, scanArgs...), "--output", "/w/baseline.json", latest)
	}
	sarifArgv := []string{"trivy", "convert", "--config", "", "--ignorefile", "", "--format", "sarif", "--output", "/w/report.sarif", "/w/report.json"}

	tests := []struct {
		name string
		// vex is Trivy's VEX, each document both scans apply, in order.
		vex     []string
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
			vex:     []string{"baikal.openvex.json"},
			call:    execx.Call{Argv: layoutArgv("--vex", "baikal.openvex.json"), Result: execx.Result{Stderr: logged}},
			do:      func(ctx context.Context, tr scan.Trivy) error { return tr.Layout(ctx, "/w/layout", "/w/report.json") },
			wantLog: logged,
		},
		{
			// Trivy takes any list, each a --vex of its own, in order.
			// divbast-scan gives it the app's own, as many as -vex names,
			// then the one document of Docker's for the final stage's base
			name: "layout-several-vex",
			vex:  []string{"openvex.json", "more.openvex.json", "/tmp/v/dhi-aspnetcore.vex.json"},
			call: execx.Call{
				Argv: layoutArgv("--vex", "openvex.json", "--vex", "more.openvex.json", "--vex", "/tmp/v/dhi-aspnetcore.vex.json"),
			},
			do: func(ctx context.Context, tr scan.Trivy) error { return tr.Layout(ctx, "/w/layout", "/w/report.json") },
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
			vex:  []string{"baikal.openvex.json"},
			call: execx.Call{Argv: publishedArgv("amd64", "--vex", "baikal.openvex.json")},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
		},
		{
			// The same list as the layout's scan, so the two compare
			name: "published-several-vex",
			vex:  []string{"openvex.json", "/tmp/v/dhi-aspnetcore.vex.json"},
			call: execx.Call{Argv: publishedArgv("arm64", "--vex", "openvex.json", "--vex", "/tmp/v/dhi-aspnetcore.vex.json")},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "arm64", "/w/baseline.json")
			},
		},
		{
			// Trivy saying the registry has no such image is a scan that
			// failed like any other: the caller asked the registry first
			name: "published-manifest-unknown",
			call: execx.Call{Argv: publishedArgv("amd64"), Result: execx.Result{Stderr: readTestdata(t, "trivy-no-such-tag.txt"), Code: 1}},
			do: func(ctx context.Context, tr scan.Trivy) error {
				return tr.Published(ctx, latest, "amd64", "/w/baseline.json")
			},
			wantErr: true,
			wantLog: readTestdata(t, "trivy-no-such-tag.txt"),
		},
		{
			name: "published-denied",
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
			// Trivy's messages on a scan that passed stay out of the way
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
			if !bytes.Equal(log.Bytes(), tt.wantLog) {
				t.Errorf("log = %q, want %q", log.Bytes(), tt.wantLog)
			}
		})
	}
}
