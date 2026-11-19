// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/divbast/ci/internal/osrelease"
	"github.com/divbast/ci/internal/scan"
)

// scanner reads one image model: Trivy for every image but one whose own
// os-release says ID=dhi, and grype for that. The published image is
// scanned by the candidate's scanner, so both sides of the comparison
// share one model and one database.
type scanner interface {
	// candidate scans the layout and returns its report, refused unless it
	// saw packages, and OS packages under the image's own model. It leaves
	// a SARIF only for a report it keeps.
	candidate(ctx context.Context) (scan.Report, error)
	// published scans image for linux/arch and returns its report, refused
	// unless it saw packages and OS packages.
	published(ctx context.Context, image, arch string) (scan.Report, error)
}

// trivyScanner scans with Trivy.
type trivyScanner struct {
	trivy                           scan.Trivy
	layout, report, sarif, baseline string
}

func (s *trivyScanner) candidate(ctx context.Context) (scan.Report, error) {
	if err := s.trivy.Layout(ctx, s.layout, s.report); err != nil {
		return scan.Report{}, fmt.Errorf("trivy could not scan %s: %w", s.layout, err)
	}
	data, err := readFile(s.report)
	if err != nil {
		return scan.Report{}, err
	}
	rep, err := scan.ParseTrivy(bytes.NewReader(data))
	if err != nil {
		return scan.Report{}, fmt.Errorf("%s: %w", s.report, err)
	}
	// A clean report from a scan that saw no packages means it never looked
	if rep.Packages == 0 {
		return scan.Report{}, fmt.Errorf("no packages in %s: the scan found nothing to scan, not nothing wrong", s.layout)
	}
	if blindToOS(&rep) {
		return scan.Report{}, fmt.Errorf("%s: %s", s.layout, noOS(&rep, "Trivy"))
	}
	if err = s.trivy.SARIF(ctx, s.report, s.sarif); err != nil {
		return scan.Report{}, fmt.Errorf("trivy could not convert %s to SARIF at %s: %w", s.report, s.sarif, err)
	}
	return rep, nil
}

func (s *trivyScanner) published(ctx context.Context, image, arch string) (scan.Report, error) {
	if err := s.trivy.Published(ctx, image, arch, s.baseline); err != nil {
		return scan.Report{}, fmt.Errorf("could not scan %s, so no finding can be told apart from one already published: %w", image, err)
	}
	data, err := readFile(s.baseline)
	if err != nil {
		return scan.Report{}, err
	}
	rep, err := scan.ParseTrivy(bytes.NewReader(data))
	if err != nil {
		return scan.Report{}, fmt.Errorf("%s: %w", s.baseline, err)
	}
	if err := shipsPackages(&rep, image, "Trivy"); err != nil {
		return scan.Report{}, err
	}
	return rep, nil
}

// grypeScanner scans with grype, for an image that says ID=dhi.
type grypeScanner struct {
	grype                           scan.Grype
	info                            osrelease.Info
	arch                            string
	layout, report, sarif, baseline string
	// db is the database the candidate's scan read, set by candidate.
	db string
}

// probes is, for each release of DHI's own model, keyed by its
// os-release's ID_LIKE and VERSION_ID, a package a record in DHI's
// namespace for that release is known to match, as a package URL with
// %s for the architecture. The probe proves grype's database holds DHI's
// advisories and that grype routes the release's packages to them; a
// release with no entry fails the scan. To add one, find a package with a
// live record, and a version it affects, with
//
//	grype db search --provider dhi --distro dhi-<VERSION_ID>
var probes = map[string]string{
	"debian 13": "pkg:deb/dhi/brotli@1.1.0-1?arch=%s&distro=dhi-13",
}

func (s *grypeScanner) candidate(ctx context.Context) (scan.Report, error) {
	if err := s.grype.UpdateDB(ctx); err != nil {
		return scan.Report{}, fmt.Errorf("grype could not update its vulnerability database: %w", err)
	}
	search := "grype db search --provider dhi --distro dhi-" + s.info.VersionID
	probe, ok := probes[s.info.IDLike+" "+s.info.VersionID]
	if !ok {
		return scan.Report{}, fmt.Errorf("%s says ID=dhi, ID_LIKE=%s, VERSION_ID=%s, and divbast-scan has no probe for that release, "+
			"so nothing would show grype's database holds DHI's advisories for it: add one to probes, a package a live record "+
			"matches, found with %s", s.layout, s.info.IDLike, s.info.VersionID, search)
	}
	purl := fmt.Sprintf(probe, s.arch)
	if err := s.grype.Probe(ctx, purl, "dhi:distro:dhi:"+s.info.VersionID); err != nil {
		return scan.Report{}, fmt.Errorf("grype's database failed the probe, so a clean report would prove nothing: %w. "+
			"If the record is gone, pick another package a live record matches, with %s", err, search)
	}
	cdx := s.report + ".cdx.json"
	if err := s.grype.Layout(ctx, s.layout, s.arch, s.report, cdx, s.sarif); err != nil {
		return scan.Report{}, s.withoutSARIF(fmt.Errorf("grype could not scan %s: %w", s.layout, err))
	}
	rep, err := parseGrypeFiles(s.report, cdx)
	if err == nil {
		err = s.sameModel(&rep)
	}
	// After the guards, as Trivy's, so code scanning sees only findings
	// under the image's own model
	if err == nil {
		err = s.grype.SARIF(s.report, s.sarif)
	}
	if err != nil {
		return scan.Report{}, s.withoutSARIF(err)
	}
	s.db = rep.DB
	return rep, nil
}

// sameModel refuses rep unless it saw packages, and OS packages, as the
// image says it is: distro dhi at its VERSION_ID, every OS package keyed
// under dhi, and no finding matched from Debian's or Alpine's advisories,
// which judge a DHI image's packages by another vendor's fixes.
func (s *grypeScanner) sameModel(rep *scan.Report) error {
	if rep.Packages == 0 {
		return fmt.Errorf("no packages in %s: the scan found nothing to scan, not nothing wrong", s.layout)
	}
	if blindToOS(rep) {
		return fmt.Errorf("%s: %s", s.layout, noOS(rep, "grype"))
	}
	var wrong []string
	if want := "dhi " + s.info.VersionID; rep.OS != want {
		wrong = append(wrong, "grype read it as "+rep.OS)
	}
	for _, p := range rep.OSPURLs {
		if purlNamespace(p) != "dhi" {
			wrong = append(wrong, "it keyed an OS package as "+p)
		}
	}
	for i := range rep.Findings {
		if f := &rep.Findings[i]; strings.HasPrefix(f.Namespace, "debian:") || strings.HasPrefix(f.Namespace, "alpine:") {
			wrong = append(wrong, "it matched "+f.ID+" from "+f.Namespace)
		}
	}
	if len(wrong) > 0 {
		more := ""
		if len(wrong) > 3 {
			more = fmt.Sprintf(", and %d more", len(wrong)-3)
			wrong = wrong[:3]
		}
		return fmt.Errorf("%s: the image says ID=dhi, VERSION_ID=%s, a Docker Hardened Image judged by Docker's own advisories, but %s%s: "+
			"the wrong model, so none of its findings is judged", s.layout, s.info.VersionID, strings.Join(wrong, "; "), more)
	}
	if !slices.Contains(rep.Providers, "dhi") {
		return fmt.Errorf("grype's database %s lists no dhi provider, so it holds none of DHI's advisories", rep.DB)
	}
	return nil
}

// purlNamespace is the namespace of the package URL p, such as dhi in
// pkg:deb/dhi/curl@8.14.1, or "" for none.
func purlNamespace(p string) string {
	_, rest, ok := strings.Cut(p, "/")
	if !ok {
		return ""
	}
	ns, _, ok := strings.Cut(rest, "/")
	if !ok {
		return ""
	}
	return ns
}

// withoutSARIF removes the SARIF grype wrote beside a report the scan
// refuses, and returns err: app-check.yml uploads the SARIF from main even
// when the scan fails, and a refused report's findings are not the image's.
func (s *grypeScanner) withoutSARIF(err error) error {
	if rmErr := os.Remove(s.sarif); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		return errors.Join(err, fmt.Errorf("remove the refused report's SARIF: %w", rmErr))
	}
	return err
}

func (s *grypeScanner) published(ctx context.Context, image, _ string) (scan.Report, error) {
	cdx := s.baseline + ".cdx.json"
	if err := s.grype.Published(ctx, image, s.arch, s.baseline, cdx); err != nil {
		return scan.Report{}, fmt.Errorf("could not scan %s, so no finding can be told apart from one already published: %w", image, err)
	}
	rep, err := parseGrypeFiles(s.baseline, cdx)
	if err != nil {
		return scan.Report{}, err
	}
	// No model guard: an image published before Docker's cutover reads as
	// Debian, and the comparison's version rule carries it across
	if err := shipsPackages(&rep, image, "grype"); err != nil {
		return scan.Report{}, err
	}
	if rep.DB == "" || rep.DB != s.db {
		return scan.Report{}, fmt.Errorf("the two scans read different vulnerability databases, %q and %q, "+
			"so a finding could read as new only because one database knows it", s.db, rep.DB)
	}
	if !slices.Contains(rep.Providers, "dhi") {
		return scan.Report{}, fmt.Errorf("grype's database %s lists no dhi provider for %s", rep.DB, image)
	}
	return rep, nil
}

// parseGrypeFiles reads grype's report at report and its CycloneDX at cdx.
func parseGrypeFiles(report, cdx string) (scan.Report, error) {
	r, err := readFile(report)
	if err != nil {
		return scan.Report{}, err
	}
	c, err := readFile(cdx)
	if err != nil {
		return scan.Report{}, err
	}
	rep, err := scan.ParseGrype(bytes.NewReader(r), bytes.NewReader(c))
	if err != nil {
		return scan.Report{}, fmt.Errorf("%s: %w", report, err)
	}
	return rep, nil
}

// shipsPackages refuses rep, scanner's report on the published image,
// when it saw no packages, or none of the OS's.
func shipsPackages(rep *scan.Report, image, scanner string) error {
	if rep.Packages == 0 {
		return fmt.Errorf("no packages in %s: the scan found nothing to scan, not nothing wrong", image)
	}
	if blindToOS(rep) {
		return fmt.Errorf("%s: %s", image, noOS(rep, scanner))
	}
	return nil
}

// grypeCache is the directory grype's configuration and database go in:
// dir, or, when it is "", divbast-scan's own in the user's cache
// directory, so a local scan keeps the database between runs. It makes it
// when missing.
func grypeCache(dir string) (string, error) {
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("find a cache directory for grype's database: %w", err)
		}
		dir = filepath.Join(base, name, "grype")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}
