// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package scan compares Trivy's findings in an image a build made with its
// findings in the image already published, so that only a HIGH or CRITICAL
// finding the published image lacks fails the build.
//
// A new advisory against something the published image already ships is
// not one a release can make worse. Blocking on it protects nobody and
// holds back whatever else the release fixes. Every other finding is still
// reported, as an advisory. "Already ships" is the same advisory, by any
// of its IDs, in the same package, or the same package at the same
// version: see [Compare].
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/divbast/ci/internal/execx"
)

// Finding is one vulnerability Trivy reports in one package: the
// advisory's ID, the package's name, the version installed, the version
// that fixes it or "" when none does, the severity, the advisory's page or
// "", and where it was found, which is "<type> package" for an OS package,
// such as "debian package", and the file it was found in otherwise.
// Aliases are the advisory's other IDs for the same vulnerability, where
// the scanner records them. Trivy records none: its VendorIDs are a
// vendor's bulletins, such as a Debian security advisory, and one
// bulletin fixes many vulnerabilities, so two different CVEs would share
// one. With Trivy on both sides of a comparison and one database, the
// IDs themselves agree.
type Finding struct {
	ID, Pkg, Version, Fixed, Severity, URL, Where string
	Aliases                                       []string
}

// Pkg is a package an image ships, by name and version, the version
// written as a finding's is.
type Pkg struct{ Name, Version string }

// Split is a candidate image's findings, parted into those the published
// image lacks, New, and those it has, Old.
type Split struct{ New, Old []Finding }

// Report is what a Trivy JSON report says: its findings, in Trivy's order;
// how many packages it saw; the image's architecture; and what it
// scanned, which is the image's first repository digest, naming exactly
// what was compared, or the name Trivy was given when it has none. A
// report that saw no packages is one whose scan never looked, whatever it
// found; deciding that is the caller's.
//
// OS is the operating system Trivy identified, as "<family> <name>", such
// as "debian 13.2", or "" when it identified none, and Family its family
// alone; OSPackages is how many of the packages are the OS's. An image
// whose OS Trivy does not know still has its language packages, so a
// report with no OS or no OS packages is blind to the OS, which Packages
// alone does not show.
//
// Inventory is every package the report lists by name, OS and language
// alike, with its version as a finding in it would give it.
type Report struct {
	Findings   []Finding
	Packages   int
	OS         string
	Family     string
	OSPackages int
	Arch       string
	Ref        string
	Inventory  []Pkg
}

// trivyJSON is what the scan reads of a Trivy JSON report.
type trivyJSON struct {
	ArtifactName string
	Metadata     struct {
		ImageConfig struct {
			Architecture string `json:"architecture"`
		}
		RepoDigests []string
		OS          struct{ Family, Name string }
	}
	Results []struct {
		Target, Class, Type string
		Packages            []struct {
			Name, Version, Release string
			Epoch                  int
		}
		Vulnerabilities []struct {
			VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, PrimaryURL string
		}
	}
}

// ParseTrivy reads a report trivy image --format json wrote.
func ParseTrivy(r io.Reader) (Report, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Report{}, fmt.Errorf("read the Trivy report: %w", err)
	}
	var raw trivyJSON
	if err = json.Unmarshal(data, &raw); err != nil {
		return Report{}, fmt.Errorf("parse the Trivy report: %w", err)
	}
	rep := Report{Arch: raw.Metadata.ImageConfig.Architecture, Ref: raw.ArtifactName}
	if len(raw.Metadata.RepoDigests) > 0 {
		rep.Ref = raw.Metadata.RepoDigests[0]
	}
	if os := raw.Metadata.OS; os.Family != "" {
		rep.OS = os.Family + " " + os.Name
		rep.Family = os.Family
	}
	for _, res := range raw.Results {
		rep.Packages += len(res.Packages)
		for _, p := range res.Packages {
			if p.Name != "" {
				rep.Inventory = append(rep.Inventory, Pkg{p.Name, trivyVersion(p.Epoch, p.Version, p.Release)})
			}
		}
		if res.Class == "os-pkgs" {
			rep.OSPackages += len(res.Packages)
		}
		where := res.Target
		if res.Class == "os-pkgs" {
			where = res.Type + " package"
		}
		for _, v := range res.Vulnerabilities {
			rep.Findings = append(rep.Findings, Finding{
				ID:       v.VulnerabilityID,
				Pkg:      v.PkgName,
				Version:  v.InstalledVersion,
				Fixed:    v.FixedVersion,
				Severity: v.Severity,
				URL:      v.PrimaryURL,
				Where:    where,
			})
		}
	}
	return rep, nil
}

// trivyVersion writes a package's version as Trivy writes a finding's
// InstalledVersion: [epoch:]version[-release], as dpkg and rpm do.
func trivyVersion(epoch int, version, release string) string {
	if release != "" {
		version += "-" + release
	}
	if epoch != 0 {
		version = strconv.Itoa(epoch) + ":" + version
	}
	return version
}

// key is what makes two findings the same one.
type key struct{ id, pkg string }

// ids is f's ID and its aliases.
func (f *Finding) ids() []string { return append([]string{f.ID}, f.Aliases...) }

// Compare parts candidate's findings by whether the published image
// already ships each, Old, or not, New. Both halves keep candidate's
// order, and its duplicates. A candidate finding is already shipped when:
//
//   - a published finding is in the same package, at any version, and
//     shares an ID with it, its own or an alias: a bump from one affected
//     version to another leaves the image no worse than what is out, and
//     one vulnerability may be filed under a vendor's ID and a CVE;
//   - or shipped, the published image's packages, holds its package at its
//     version: whatever the advisory, the image already ships what it is
//     against.
//
// With one scanner and one database on both sides, the second rule
// decides nothing the first does not: the same package at the same
// version draws the same findings. It bites only when the model changes
// between the published image and the candidate, as when a base image
// moves to its vendor's own advisories and every ID changes. A package
// new to the image, or at a new version, is still judged by its IDs.
func Compare(candidate, published []Finding, shipped []Pkg) Split {
	known := make(map[key]bool, len(published))
	for i := range published {
		f := &published[i]
		for _, id := range f.ids() {
			known[key{id, f.Pkg}] = true
		}
	}
	out := make(map[Pkg]bool, len(shipped))
	for _, p := range shipped {
		out[p] = true
	}
	var s Split
	for i := range candidate {
		f := &candidate[i]
		if out[Pkg{f.Pkg, f.Version}] || slices.ContainsFunc(f.ids(), func(id string) bool { return known[key{id, f.Pkg}] }) {
			s.Old = append(s.Old, *f)
		} else {
			s.New = append(s.New, *f)
		}
	}
	return s
}

// Trivy runs the scans the comparison needs.
type Trivy struct {
	// Run runs trivy.
	Run execx.Runner
	// VEX names the OpenVEX documents both scans apply, each given Trivy
	// as a --vex of its own, in order.
	VEX []string
	// Log is where Trivy's own messages go, which Layout and SARIF always
	// write there, and Published only when it fails. Nil drops them.
	Log io.Writer
}

// isolated turns off the two files Trivy reads from its working directory
// unless told otherwise, .trivyignore and trivy.yaml, for every call: the
// scan runs from the caller's repository, where either would decide what
// Trivy reports, hiding a finding from the verdict and from code scanning
// alike. An empty path turns each off.
var isolated = []string{"--config", "", "--ignorefile", ""}

func (t Trivy) scanArgs() []string {
	vex := make([]string, 0, 2*len(t.VEX))
	for _, doc := range t.VEX {
		vex = append(vex, "--vex", doc)
	}
	return slices.Concat(vex, isolated, []string{"--severity", "HIGH,CRITICAL", "--format", "json"})
}

// Layout scans the image in the OCI layout at layout, and writes the
// report to report.
func (t Trivy) Layout(ctx context.Context, layout, report string) error {
	return t.logged(ctx, slices.Concat([]string{"image", "--input", layout}, t.scanArgs(), []string{"--output", report})...)
}

// Published scans image as its registry serves it for linux/arch, and
// writes the report to report. It never updates the vulnerability
// database, so its findings come from the one Layout read: a finding only
// a newer database knows about would otherwise read as new. It reads the
// registry, never the local engine, whose copy may be stale.
//
// Whether image is published at all is the caller's to know first: any
// failure here is a scan that failed, whatever Trivy says about why.
func (t Trivy) Published(ctx context.Context, image, arch, report string) error {
	args := slices.Concat(
		[]string{"image", "--image-src", "remote", "--platform", "linux/" + arch, "--skip-db-update"},
		t.scanArgs(), []string{"--output", report, image},
	)
	res, err := t.Run.Run(ctx, "trivy", args...)
	if err != nil {
		return err
	}
	if res.Code == 0 {
		return nil
	}
	t.log(res.Stderr)
	return fmt.Errorf("trivy exit status %d", res.Code)
}

// SARIF converts the report at report to SARIF, for code scanning, at
// sarif.
func (t Trivy) SARIF(ctx context.Context, report, sarif string) error {
	return t.logged(ctx, slices.Concat([]string{"convert"}, isolated, []string{"--format", "sarif", "--output", sarif, report})...)
}

// logged runs trivy with args, and passes on what it says.
func (t Trivy) logged(ctx context.Context, args ...string) error {
	res, err := t.Run.Run(ctx, "trivy", args...)
	if err != nil {
		return err
	}
	t.log(res.Stderr)
	if res.Code != 0 {
		return fmt.Errorf("trivy exit status %d", res.Code)
	}
	return nil
}

func (t Trivy) log(msg []byte) {
	if t.Log == nil || len(msg) == 0 {
		return
	}
	// Trivy's messages are a courtesy: a log that cannot be written is
	// not a scan that failed.
	_, _ = t.Log.Write(msg)
}
