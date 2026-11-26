// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

func TestGrypeSBOM(t *testing.T) {
	t.Parallel()
	const cfg = "/ci/grype.yaml"
	dir := t.TempDir()
	report, cdx, sarif := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.cdx.json"), filepath.Join(dir, "r.sarif")
	file := "/w/root/usr/local/share/divbast/sbom.cdx.json"
	fake := execx.NewFake(t,
		execx.Call{Argv: []string{
			"grype", "-c", cfg, "sbom:" + file,
			"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx, "-o", "sarif=" + sarif,
			"--vex", "openvex.json",
		}},
		// No SARIF asked for, none written: the published side's
		execx.Call{Argv: []string{
			"grype", "-c", cfg, "sbom:" + file,
			"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx,
			"--vex", "openvex.json",
		}},
	)
	g := scan.Grype{Run: fake, VEX: []string{"openvex.json"}, Config: cfg}
	if err := g.SBOM(t.Context(), file, report, cdx, sarif); err != nil {
		t.Fatalf("SBOM() = %v", err)
	}
	if err := g.SBOM(t.Context(), file, report, cdx, ""); err != nil {
		t.Fatalf("SBOM() with no SARIF = %v", err)
	}
	if err := (scan.Grype{Run: execx.NewFake(t)}).SBOM(t.Context(), file, report, cdx, sarif); err == nil {
		t.Error("SBOM() with no Config: nil error")
	}
}

// sarifURIs reads every result's locations' URIs in the SARIF at path.
func sarifURIs(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI *string }
					}
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
			for _, l := range res.Locations {
				u := l.PhysicalLocation.ArtifactLocation.URI
				if u == nil {
					uris = append(uris, "<none>")
					continue
				}
				uris = append(uris, *u)
			}
		}
	}
	return uris
}

// TestLocateSARIF is grype's SARIF of an SBOM, which places no finding at
// any file: each is placed at the SBOM's own path in the image, and a
// result some other file already holds keeps it.
func TestLocateSARIF(t *testing.T) {
	t.Parallel()
	const at = "usr/local/share/divbast/sbom.cdx.json"
	sarif := filepath.Join(t.TempDir(), "r.sarif")
	data := readTestdata(t, "grype-sbom.sarif")
	// One result already placed, as grype places a lockfile's
	data = []byte(strings.Replace(string(data), `"uri": ""`, `"uri": "srv/app/pnpm-lock.yaml"`, 1))
	if err := os.WriteFile(sarif, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sarifURIs(t, sarif); len(got) != 3 || got[0] != "srv/app/pnpm-lock.yaml" || got[1] != "" {
		t.Fatalf("the fixture's URIs = %q, want one placed and two empty", got)
	}
	if err := scan.LocateSARIF(sarif, at); err != nil {
		t.Fatalf("LocateSARIF() = %v", err)
	}
	want := []string{"srv/app/pnpm-lock.yaml", at, at}
	if got := sarifURIs(t, sarif); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("URIs = %q, want %q", got, want)
	}
	requireSARIFArrays(t, sarif)

	// A SARIF that is not JSON is an error, not a file left as it was
	if err := os.WriteFile(sarif, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scan.LocateSARIF(sarif, at); err == nil {
		t.Error("LocateSARIF() of no JSON: nil error")
	}
}

// TestUncarriedSBOMListed is a finding in an SBOM the published image does
// not carry: listed under its own heading, never blocking.
func TestUncarriedSBOMListed(t *testing.T) {
	t.Parallel()
	f := scan.Finding{ID: "CVE-2022-30333", Pkg: "unrar", Version: "6.11", Fixed: "6.12", Severity: "HIGH", Where: "usr/local/share/divbast/sbom.cdx.json", Hold: scan.UncarriedSBOM}
	split := scan.Compare([]scan.Finding{f}, nil, nil)
	if len(split.New) != 0 || len(split.Held) != 1 {
		t.Fatalf("Compare() = %+v, want the finding held, not new", split)
	}
	listing := scan.Listing("x", "new, so blocking", &split)
	if want := "1 new in an SBOM the published image does not carry, so listed, not blocking:\n" +
		"  CVE-2022-30333 HIGH unrar 6.11, fixed in 6.12, usr/local/share/divbast/sbom.cdx.json\n"; !strings.Contains(listing, want) {
		t.Errorf("Listing() = %q, want it to contain %q", listing, want)
	}
}
