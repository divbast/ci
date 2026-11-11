// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package scan compares Trivy's findings in an image a build made with its
// findings in the image already published, so that only a HIGH or CRITICAL
// finding the published image lacks fails the build.
//
// A new advisory against something the published image already ships is
// not one a release can make worse. Blocking on it protects nobody and
// holds back whatever else the release fixes. Every other finding is still
// reported, as an advisory.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/divbast/ci/internal/execx"
)

// Finding is one vulnerability Trivy reports in one package: the
// advisory's ID, the package's name, the version installed, the version
// that fixes it or "" when none does, the severity, the advisory's page or
// "", and where it was found, which is "<type> package" for an OS package,
// such as "debian package", and the file it was found in otherwise.
type Finding struct{ ID, Pkg, Version, Fixed, Severity, URL, Where string }

// Split is a candidate image's findings, parted into those the published
// image lacks, New, and those it has, Old.
type Split struct{ New, Old []Finding }

// report is what the scan reads of a Trivy JSON report.
type report struct {
	ArtifactName string
	Metadata     struct {
		ImageConfig struct {
			Architecture string `json:"architecture"`
		}
		RepoDigests []string
	}
	Results []struct {
		Target, Class, Type string
		// Only how many there are is read.
		Packages        []struct{}
		Vulnerabilities []struct {
			VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, PrimaryURL string
		}
	}
}

func decode(r io.Reader) (report, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return report{}, fmt.Errorf("read the Trivy report: %w", err)
	}
	var rep report
	if err = json.Unmarshal(data, &rep); err != nil {
		return report{}, fmt.Errorf("parse the Trivy report: %w", err)
	}
	return rep, nil
}

// ParseTrivy reads a report trivy image --format json wrote, and returns
// its findings, in Trivy's order, how many packages it saw, and the
// image's architecture. A report that saw no packages is one whose scan
// never looked, whatever it found; deciding that is the caller's.
func ParseTrivy(r io.Reader) (findings []Finding, packages int, arch string, err error) {
	rep, err := decode(r)
	if err != nil {
		return nil, 0, "", err
	}
	for _, res := range rep.Results {
		packages += len(res.Packages)
		where := res.Target
		if res.Class == "os-pkgs" {
			where = res.Type + " package"
		}
		for _, v := range res.Vulnerabilities {
			findings = append(findings, Finding{
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
	return findings, packages, rep.Metadata.ImageConfig.Architecture, nil
}

// ImageRef returns what a Trivy report says it scanned: the image's first
// repository digest, which names exactly what was compared, or the name
// Trivy was given when it has none.
func ImageRef(r io.Reader) (string, error) {
	rep, err := decode(r)
	if err != nil {
		return "", err
	}
	if len(rep.Metadata.RepoDigests) > 0 {
		return rep.Metadata.RepoDigests[0], nil
	}
	return rep.ArtifactName, nil
}

// key is what makes two findings the same one.
type key struct{ id, pkg string }

// Compare parts candidate's findings by whether published has the same
// vulnerability in the same package, at any version: a bump from one
// affected version to another leaves the image no worse than what is out.
// Both halves keep candidate's order, and its duplicates.
func Compare(candidate, published []Finding) Split {
	known := make(map[key]bool, len(published))
	for _, f := range published {
		known[key{f.ID, f.Pkg}] = true
	}
	var s Split
	for _, f := range candidate {
		if known[key{f.ID, f.Pkg}] {
			s.Old = append(s.Old, f)
		} else {
			s.New = append(s.New, f)
		}
	}
	return s
}

// refusal is how Trivy reports a registry declining to show an image: a
// tag or a repository it does not have, or a pull it denies. ghcr.io
// denies an anonymous pull of a package that does not exist and of one
// that is private alike.
var refusal = regexp.MustCompile(`: (MANIFEST_UNKNOWN|NAME_UNKNOWN|DENIED): `)

// Unpullable reports whether stderr, from a trivy image --image-src remote
// that failed, says the registry declined to show the image, rather than
// that it failed to answer. A rate limit, an outage or an unreachable
// registry is never taken for an image nobody can pull.
func Unpullable(stderr []byte) bool {
	return refusal.Match(stderr)
}

// ErrUnpullable means the registry declined to show the published image to
// an anonymous client: nothing is published there yet, or it is private.
var ErrUnpullable = errors.New("not anonymously pullable")

// Trivy runs the scans the comparison needs.
type Trivy struct {
	Run execx.Runner
	// VEX, when set, names an OpenVEX document both scans apply.
	VEX string
	// Log is where Trivy's own messages go, which Layout and SARIF always
	// write there, and Published only when it fails other than by
	// ErrUnpullable. Nil drops them.
	Log io.Writer
}

func (t Trivy) scanArgs() []string {
	var vex []string
	if t.VEX != "" {
		vex = []string{"--vex", t.VEX}
	}
	return slices.Concat(vex, []string{"--severity", "HIGH,CRITICAL", "--format", "json"})
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
// When the registry declines to show image, the error wraps
// [ErrUnpullable].
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
	if Unpullable(res.Stderr) {
		return fmt.Errorf("%s: %w", image, ErrUnpullable)
	}
	t.log(res.Stderr)
	return fmt.Errorf("trivy exit status %d", res.Code)
}

// SARIF converts the report at report to SARIF, for code scanning, at
// sarif.
func (t Trivy) SARIF(ctx context.Context, report, sarif string) error {
	return t.logged(ctx, "convert", "--format", "sarif", "--output", sarif, report)
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
