// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/scan"
)

// sbomLabel is the image label that declares the SBOMs an image ships of
// what no image scan sees, such as a binary it builds from source:
// absolute paths in the image, separated by commas.
const sbomLabel = "io.github.divbast.scan.sboms"

// advisoryLabel is the image label that marks some of the SBOMs sbomLabel
// declares as advisory: the findings in them are listed and never block.
// It names them as sbomLabel does, and each must also be in sbomLabel.
// An image uses it for a payload it cannot patch, such as a signed bundle
// from upstream that carries its own copies of libraries.
const advisoryLabel = "io.github.divbast.scan.sboms.advisory"

// sbomSuffix ends the name of every SBOM the scan reads: CycloneDX JSON.
const sbomSuffix = ".cdx.json"

// maxSBOM bounds an SBOM the scan reads.
const maxSBOM = 16 << 20

// sboms is what an image's label declares: each SBOM's path in the image,
// without its leading slash, as the scan lists where a finding is, in the
// label's order, its content, and the components it names.
type sboms struct {
	paths      []string
	files      map[string][]byte
	components map[string][]scan.Pkg
}

// declaredSBOMs reads the SBOM label of the image whose labels are labels:
// none when it is not there. Each path must be absolute and clean, name a
// file whose name ends in .cdx.json, and come once; a label that names
// none, or one any other way, is an error. image names the image in the
// error.
func declaredSBOMs(labels map[string]string, image string) ([]string, error) {
	return declaredPaths(labels, sbomLabel, image, func(p string) string {
		if b := path.Base(p); b == sbomSuffix || !strings.HasSuffix(b, sbomSuffix) {
			return "the scan reads only CycloneDX JSON, from a file whose name ends in " + sbomSuffix
		}
		return ""
	})
}

// declaredAdvisorySBOMs reads the advisory label of the image whose labels
// are labels: the paths in it, without their leading slash, or none when
// it is not there. It names paths as sbomLabel does, and each must be one
// of sboms, the paths sbomLabel declares, without their leading slash;
// one that is not is refused, by name. image names the image in the
// error.
func declaredAdvisorySBOMs(labels map[string]string, image string, sboms []string) (map[string]bool, error) {
	paths, err := declaredPaths(labels, advisoryLabel, image, func(p string) string {
		if !slices.Contains(sboms, strings.TrimPrefix(p, "/")) {
			return "it is not in its " + sbomLabel + " label, so there is no SBOM there to mark"
		}
		return ""
	})
	if len(paths) == 0 || err != nil {
		return nil, err
	}
	advisory := make(map[string]bool, len(paths))
	for _, p := range paths {
		advisory[p] = true
	}
	return advisory, nil
}

// holdSBOMs holds the findings in an SBOM the image declares, each at its
// SBOM's path: those at a path in advisory with [scan.AdvisorySBOM], and,
// when uncarried, the rest with [scan.UncarriedSBOM]. The advisory mark
// stays for good, while an uncarried SBOM is held only until a published
// image carries one.
func holdSBOMs(findings []scan.Finding, advisory map[string]bool, uncarried bool) {
	for i := range findings {
		switch f := &findings[i]; {
		case advisory[f.Where]:
			f.Hold = scan.AdvisorySBOM
		case uncarried:
			f.Hold = scan.UncarriedSBOM
		}
	}
}

// readSBOMs reads paths, the SBOMs the linux/arch image in the OCI layout
// at layout declares, from its layers, and the components each names.
// Each must be a file there, CycloneDX JSON, naming at least one
// component, each with a name, a version, and a package URL or a CPE for
// grype to match it by. name is what the errors call the image.
func readSBOMs(ctx context.Context, zstd execx.StreamRunner, layout, arch, name string, paths []string) (sboms, error) {
	if len(paths) == 0 {
		return sboms{}, nil
	}
	files, err := readDeclared(ctx, zstd, layout, arch, name, sbomLabel, paths, maxSBOM)
	if err != nil {
		return sboms{}, err
	}
	b := sboms{paths: paths, files: files, components: make(map[string][]scan.Pkg, len(paths))}
	for _, p := range paths {
		if b.components[p], err = components(files[p]); err != nil {
			return sboms{}, fmt.Errorf("%s declares /%s in its %s label, but %w", name, p, sbomLabel, err)
		}
	}
	return b, nil
}

// cdxDocument is what the scan reads of a CycloneDX document: its format,
// and each top-level component's name, version and identifiers.
type cdxDocument struct {
	BOMFormat  string `json:"bomFormat"`
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
		CPE     string `json:"cpe"`
	} `json:"components"`
}

// components reads the components the CycloneDX JSON in data names. Its
// errors follow "but ", after the file they are about.
func components(data []byte) ([]scan.Pkg, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("it is not CycloneDX JSON: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("it is not CycloneDX JSON: it says bomFormat %q", doc.BOMFormat)
	}
	if len(doc.Components) == 0 {
		return nil, errors.New("it names no component, so a clean scan of it would prove nothing")
	}
	pkgs := make([]scan.Pkg, 0, len(doc.Components))
	for i, c := range doc.Components {
		switch {
		case c.Name == "":
			return nil, fmt.Errorf("its component %d has no name", i+1)
		case c.Version == "":
			return nil, fmt.Errorf("its component %d, %s, has no version", i+1, c.Name)
		case c.PURL == "" && c.CPE == "":
			return nil, fmt.Errorf("its component %d, %s %s, has neither a purl nor a cpe, so nothing can match it", i+1, c.Name, c.Version)
		}
		pkgs = append(pkgs, scan.Pkg{Name: c.Name, Version: c.Version})
	}
	return pkgs, nil
}

// scan writes b's SBOMs under root, each at its path in the image, and has
// g scan each, one grype run per SBOM, writing the nth's report to
// report.<n>.json and its CycloneDX to report.<n>.cdx.json, counting from
// 1 in the label's order. Each finding is placed at its SBOM's path, and
// the SBOMs' components are the report's packages. Unless sarif is "",
// each SBOM's HIGH and CRITICAL findings go into the SARIF at sarif, at
// the SBOM's path in the image, by way of a SARIF of its own beside root.
// An SBOM whose components grype's CycloneDX does not all name is
// refused: a scan that read fewer would prove nothing about the rest.
func (b sboms) scan(ctx context.Context, g scan.Grype, root, report, sarif string) (scan.Report, error) {
	if err := writeUnder(root, b.paths, b.files); err != nil {
		return scan.Report{}, fmt.Errorf("write the SBOMs %s for grype: %w", b, err)
	}
	var all scan.Report
	for i, p := range b.paths {
		out, cdx, part := fmt.Sprintf("%s.%d.json", report, i+1), fmt.Sprintf("%s.%d.cdx.json", report, i+1), ""
		if sarif != "" {
			part = fmt.Sprintf("%s.%d.sarif", root, i+1)
		}
		if err := g.SBOM(ctx, filepath.Join(root, filepath.FromSlash(p)), out, cdx, part); err != nil {
			return scan.Report{}, fmt.Errorf("grype could not scan the SBOM /%s: %w", p, err)
		}
		rep, err := parseGrypeFiles(out, cdx)
		if err == nil {
			err = b.readAll(p, cdx)
		}
		if err == nil && part != "" {
			err = locatedSARIF(g, out, part, p, sarif)
		}
		if err != nil {
			return scan.Report{}, err
		}
		for j := range rep.Findings {
			rep.Findings[j].Where = p
		}
		all.Findings = append(all.Findings, rep.Findings...)
		all.Inventory = append(all.Inventory, b.components[p]...)
	}
	return all, nil
}

// readAll refuses the scan of the SBOM at p unless grype's CycloneDX, at
// cdx, names every component the SBOM does, by name and version: grype
// writes a CycloneDX of what it read, where its report lists only what it
// matched.
func (b sboms) readAll(p, cdx string) error {
	data, err := readFile(cdx)
	if err != nil {
		return err
	}
	var doc cdxDocument
	if err = json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse grype's CycloneDX %s: %w", cdx, err)
	}
	read := make(map[scan.Pkg]bool, len(doc.Components))
	for _, c := range doc.Components {
		read[scan.Pkg{Name: c.Name, Version: c.Version}] = true
	}
	want := b.components[p]
	got := 0
	for _, c := range want {
		if read[c] {
			got++
		}
	}
	if got < len(want) {
		return fmt.Errorf("grype read %d of the %d components /%s names, so a clean scan of it would prove nothing", got, len(want), p)
	}
	return nil
}

// locatedSARIF keeps the HIGH and CRITICAL findings of report, grype's
// report on the SBOM at p, in its SARIF part, places them at p, and merges
// them into the SARIF at into.
func locatedSARIF(g scan.Grype, report, part, p, into string) error {
	err := g.SARIF(report, part)
	if err == nil {
		err = scan.LocateSARIF(part, p)
	}
	if err == nil {
		err = scan.MergeSARIF(into, part)
	}
	return err
}

// String lists b's paths, as the image names them.
func (b sboms) String() string {
	return "/" + strings.Join(b.paths, ", /")
}

// publishedSBOMs reads paths, the SBOMs the published image ref declares
// in its own label, from its copy for linux/arch in the OCI layout at
// layout, naming it ref in every error, never the copy's directory. It
// scans them with g under tmp, writing its reports beside baseline, and
// adds their findings to shipped and their components to inventory. It
// reports whether the image carries none.
func publishedSBOMs(ctx context.Context, zstd execx.StreamRunner, g scan.Grype,
	layout, ref, arch, tmp, baseline string, paths []string, shipped *[]scan.Finding, inventory *[]scan.Pkg,
) (uncarried bool, _ error) {
	if len(paths) == 0 {
		return true, nil
	}
	b, err := readSBOMs(ctx, zstd, layout, arch, ref, paths)
	if err != nil {
		return false, err
	}
	rep, err := b.scan(ctx, g, filepath.Join(tmp, "published-sboms"), baseline+".sboms", "")
	if err != nil {
		return false, err
	}
	*shipped = append(*shipped, rep.Findings...)
	*inventory = append(*inventory, rep.Inventory...)
	return false, nil
}
