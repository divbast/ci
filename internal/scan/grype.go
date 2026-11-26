// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/divbast/ci/internal/execx"
)

// Grype runs the scans the comparison needs for an image whose own
// os-release says ID=dhi: a Docker Hardened Image on Docker's own
// advisories, which Grype reads and Trivy does not.
//
// Every call names ci's own configuration, Config, which WriteConfig
// writes: Grype otherwise reads a .grype.yaml from its working directory,
// the caller's repository, where an ignore rule would hide a finding.
type Grype struct {
	// Run runs grype.
	Run execx.Runner
	// VEX names the OpenVEX documents both scans apply, each given grype
	// as a --vex of its own, in order.
	VEX []string
	// Log is where grype's own messages go, which Layout, UpdateDB and
	// Probe always write there, and Published only when it fails. Nil
	// drops them.
	Log io.Writer
	// Config is the configuration WriteConfig wrote. Every call needs it.
	Config string
}

// grypeConfig is the file WriteConfig writes.
const grypeConfig = "grype.yaml"

// errNoConfig is the error of a call made before WriteConfig.
var errNoConfig = errors.New("grype has no configuration of ci's to run with")

// WriteConfig writes ci's configuration for grype into dir, which must
// exist, and returns its path for Config. The vulnerability database
// lives in dir too, in db, so a dir kept between runs keeps it. grype
// asks after no newer release of itself, and never updates its database
// on its own: UpdateDB does, once, so that both scans read the same one.
// Its own checks of the database's age and checksum stay on.
func (Grype) WriteConfig(dir string) (path string, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	// A JSON string is a YAML one, quoted, whatever the path holds
	cache, err := json.Marshal(filepath.Join(dir, "db"))
	if err != nil {
		return "", err
	}
	text := "# Written by divbast-scan, which names it on every grype call.\n" +
		"check-for-app-update: false\n" +
		"db:\n" +
		"  cache-dir: " + string(cache) + "\n" +
		"  auto-update: false\n" +
		"  require-update-check: false\n"
	if err := root.WriteFile(grypeConfig, []byte(text), 0o600); err != nil {
		return "", err
	}
	return filepath.Join(dir, grypeConfig), nil
}

// args is grype's argv after its name: ci's configuration, then rest.
func (g Grype) args(rest ...string) ([]string, error) {
	if g.Config == "" {
		return nil, errNoConfig
	}
	return slices.Concat([]string{"-c", g.Config}, rest), nil
}

func (g Grype) vexArgs() []string {
	vex := make([]string, 0, 2*len(g.VEX))
	for _, doc := range g.VEX {
		vex = append(vex, "--vex", doc)
	}
	return vex
}

// UpdateDB updates grype's vulnerability database, once for both scans.
func (g Grype) UpdateDB(ctx context.Context) error {
	args, err := g.args("db", "update")
	if err != nil {
		return err
	}
	return g.logged(ctx, args...)
}

// Probe asks grype about purl, a package a record in the database's
// namespace is known to match, and fails unless a match comes from that
// namespace. A database without DHI's advisories, or a grype that no
// longer routes DHI's packages to them, reads every DHI image as clean;
// the probe shows neither is so, not that every package is covered.
func (g Grype) Probe(ctx context.Context, purl, namespace string) error {
	args, err := g.args(purl, "-o", "json")
	if err != nil {
		return err
	}
	res, err := g.Run.Run(ctx, "grype", args...)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		g.log(res.Stderr)
		return fmt.Errorf("grype exit status %d", res.Code)
	}
	var out struct {
		Matches []struct {
			Vulnerability struct{ ID, Namespace string }
		}
	}
	if err = json.Unmarshal(res.Stdout, &out); err != nil {
		return fmt.Errorf("parse grype's answer for %s: %w", purl, err)
	}
	var elsewhere []string
	for _, m := range out.Matches {
		if m.Vulnerability.Namespace == namespace {
			return nil
		}
		elsewhere = append(elsewhere, m.Vulnerability.ID+" from "+m.Vulnerability.Namespace)
	}
	if len(elsewhere) == 0 {
		return fmt.Errorf("grype's database holds no record for %s in %s", purl, namespace)
	}
	return fmt.Errorf("grype matched %s only outside %s: %s", purl, namespace, strings.Join(elsewhere, ", "))
}

// Layout scans the image for linux/arch in the OCI layout at layout, and
// writes its report to report, its CycloneDX to cdx, which lists every
// package where the report lists only those with findings, and its SARIF,
// for code scanning, to sarif, every finding in it until SARIF filters
// it.
func (g Grype) Layout(ctx context.Context, layout, arch, report, cdx, sarif string) error {
	args, err := g.args(slices.Concat([]string{
		"oci-dir:" + layout, "--platform", "linux/" + arch,
		"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx, "-o", "sarif=" + sarif,
	}, g.vexArgs())...)
	if err != nil {
		return err
	}
	return g.logged(ctx, args...)
}

// Dir scans the files under dir, where the scan wrote files an image
// declares, each at its path in the image, and writes the report to
// report, its CycloneDX to cdx, and its SARIF to sarif, unless sarif is "".
// grype reads a directory with its directory catalogers, which read
// lockfiles, where an image's catalogers read none.
func (g Grype) Dir(ctx context.Context, dir, report, cdx, sarif string) error {
	rest := []string{"dir:" + dir, "-o", "json=" + report, "-o", "cyclonedx-json=" + cdx}
	if sarif != "" {
		rest = append(rest, "-o", "sarif="+sarif)
	}
	args, err := g.args(slices.Concat(rest, g.vexArgs())...)
	if err != nil {
		return err
	}
	return g.logged(ctx, args...)
}

// SBOM scans the components the CycloneDX SBOM at file names, as grype
// reads an sbom: source, and writes the report to report, its CycloneDX to
// cdx, and its SARIF to sarif, unless sarif is "". No image or directory
// scan reads an SBOM: grype's catalogers pass over one in a tree.
func (g Grype) SBOM(ctx context.Context, file, report, cdx, sarif string) error {
	rest := []string{"sbom:" + file, "-o", "json=" + report, "-o", "cyclonedx-json=" + cdx}
	if sarif != "" {
		rest = append(rest, "-o", "sarif="+sarif)
	}
	args, err := g.args(slices.Concat(rest, g.vexArgs())...)
	if err != nil {
		return err
	}
	return g.logged(ctx, args...)
}

// SARIF rewrites the SARIF at sarif, from the Layout or Dir run that wrote
// the report at report, to hold the HIGH and CRITICAL findings alone, as
// the verdict counts them, for code scanning.
func (Grype) SARIF(report, sarif string) error { return filterSARIF(report, sarif) }

// Published scans image as its registry serves it for linux/arch, and
// writes the report to report and its CycloneDX to cdx, from the database
// Layout read: the configuration never updates it.
//
// Whether image is published at all is the caller's to know first: any
// failure here is a scan that failed, whatever grype says about why.
func (g Grype) Published(ctx context.Context, image, arch, report, cdx string) error {
	args, err := g.args(slices.Concat([]string{
		"registry:" + image, "--platform", "linux/" + arch,
		"-o", "json=" + report, "-o", "cyclonedx-json=" + cdx,
	}, g.vexArgs())...)
	if err != nil {
		return err
	}
	res, err := g.Run.Run(ctx, "grype", args...)
	if err != nil {
		return err
	}
	if res.Code == 0 {
		return nil
	}
	g.log(res.Stderr)
	return fmt.Errorf("grype exit status %d", res.Code)
}

// logged runs grype with args, and passes on what it says.
func (g Grype) logged(ctx context.Context, args ...string) error {
	res, err := g.Run.Run(ctx, "grype", args...)
	if err != nil {
		return err
	}
	g.log(res.Stderr)
	if res.Code != 0 {
		return fmt.Errorf("grype exit status %d", res.Code)
	}
	return nil
}

func (g Grype) log(msg []byte) {
	if g.Log == nil || len(msg) == 0 {
		return
	}
	// grype's messages are a courtesy: a log that cannot be written is
	// not a scan that failed.
	_, _ = g.Log.Write(msg)
}

// grypeJSON is what the scan reads of a report grype -o json writes.
type grypeJSON struct {
	Matches []struct {
		Vulnerability struct {
			ID, DataSource, Namespace, Severity string
			Fix                                 struct {
				Versions []string
				State    string
			}
		}
		RelatedVulnerabilities []struct{ ID string }
		Artifact               struct {
			Name, Version, Type string
			Locations           []struct{ Path string }
		}
	}
	Source struct {
		// An object for an image, and a string for a package URL
		Target json.RawMessage
	}
	Distro     struct{ Name, Version string }
	Descriptor struct {
		DB struct {
			Status    struct{ From string }
			Providers map[string]json.RawMessage
		}
	}
}

// cdxJSON is what the scan reads of the CycloneDX grype writes.
type cdxJSON struct {
	Components []struct {
		Type, Name, Version string
		PURL                string `json:"purl"`
		Properties          []struct{ Name, Value string }
	}
}

// cdxLocation is the CycloneDX property grype gives the file it found a
// package in.
const cdxLocation = "syft:location:0:path"

// osPURLTypes are the package URL types of an OS's packages.
var osPURLTypes = []string{"pkg:deb/", "pkg:rpm/", "pkg:apk/", "pkg:alpm/"}

// isOSType reports whether t, an artifact's type in grype's report, is an
// OS's packages.
func isOSType(t string) bool { return t == "deb" || t == "rpm" || t == "apk" || t == "alpm" }

// keptSeverity is the severity a finding of grype's severity sev is kept
// with, as the verdict counts it, and whether it is kept at all: HIGH and
// CRITICAL, and UNKNOWN for none, which the scan lists and never blocks
// on. Grype has no --severity of its own.
func keptSeverity(sev string) (string, bool) {
	switch s := strings.ToUpper(sev); s {
	case "CRITICAL", "HIGH":
		return s, true
	case "", "UNKNOWN":
		return "UNKNOWN", true
	}
	return "", false
}

// ParseGrype reads a report grype -o json wrote, and the CycloneDX of the
// same scan, which lists every package where the report lists only those
// with findings: HIGH, CRITICAL and UNKNOWN findings, each with its aliases
// and the namespace of its record, the OS grype identified, its packages,
// and how many of them each file holds, and the database it read.
func ParseGrype(report, cdx io.Reader) (Report, error) {
	var raw grypeJSON
	if err := decodeAll(report, &raw); err != nil {
		return Report{}, fmt.Errorf("parse the grype report: %w", err)
	}
	var bom cdxJSON
	if err := decodeAll(cdx, &bom); err != nil {
		return Report{}, fmt.Errorf("parse grype's CycloneDX: %w", err)
	}

	rep := Report{Family: raw.Distro.Name, DB: raw.Descriptor.DB.Status.From}
	if raw.Distro.Name != "" {
		rep.OS = raw.Distro.Name + " " + raw.Distro.Version
	}
	rep.Providers = slices.Sorted(maps.Keys(raw.Descriptor.DB.Providers))
	if t := bytes.TrimSpace(raw.Source.Target); len(t) > 0 && t[0] == '{' {
		var target struct {
			UserInput    string
			RepoDigests  []string
			Architecture string
		}
		if err := json.Unmarshal(t, &target); err != nil {
			return Report{}, fmt.Errorf("parse the grype report's source: %w", err)
		}
		rep.Arch, rep.Ref = target.Architecture, target.UserInput
		if len(target.RepoDigests) > 0 {
			rep.Ref = target.RepoDigests[0]
		}
	}

	for i := range raw.Matches {
		m := &raw.Matches[i]
		sev, ok := keptSeverity(m.Vulnerability.Severity)
		if !ok {
			continue
		}
		f := Finding{
			ID:        m.Vulnerability.ID,
			Pkg:       m.Artifact.Name,
			Version:   m.Artifact.Version,
			Severity:  sev,
			URL:       m.Vulnerability.DataSource,
			Namespace: m.Vulnerability.Namespace,
		}
		if m.Vulnerability.Fix.State == "fixed" {
			f.Fixed = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		switch {
		case isOSType(m.Artifact.Type):
			f.Where = cmp.Or(raw.Distro.Name, m.Artifact.Type) + " package"
		case len(m.Artifact.Locations) > 0:
			f.Where = strings.TrimPrefix(m.Artifact.Locations[0].Path, "/")
		}
		for _, r := range m.RelatedVulnerabilities {
			f.Aliases = append(f.Aliases, r.ID)
		}
		rep.Findings = append(rep.Findings, f)
	}

	for _, c := range bom.Components {
		if c.PURL == "" || c.Type == "operating-system" || c.Type == "file" {
			continue
		}
		rep.Packages++
		rep.Inventory = append(rep.Inventory, Pkg{c.Name, c.Version})
		for _, p := range c.Properties {
			if p.Name == cdxLocation {
				if rep.PackagesIn == nil {
					rep.PackagesIn = map[string]int{}
				}
				rep.PackagesIn[strings.TrimPrefix(p.Value, "/")]++
			}
		}
		if slices.ContainsFunc(osPURLTypes, func(p string) bool { return strings.HasPrefix(c.PURL, p) }) {
			rep.OSPackages++
			rep.OSPURLs = append(rep.OSPURLs, c.PURL)
		}
	}
	return rep, nil
}

// decodeAll decodes all of r, one JSON value, into v.
func decodeAll(r io.Reader, v any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// filterSARIF rewrites the SARIF at sarif, from the grype run that wrote
// the report at report, to hold the HIGH and CRITICAL findings alone, and
// the rules they name. grype names each result's rule <ID>-<package>, and
// writes one result per finding: a SARIF in which the kept findings' rules
// do not come out one for one fails, rather than reaching code scanning
// quietly empty.
func filterSARIF(report, sarif string) error {
	var raw grypeJSON
	if err := readJSONFile(report, &raw); err != nil {
		return fmt.Errorf("read the grype report: %w", err)
	}
	keep := map[string]int{}
	want := 0
	for i := range raw.Matches {
		m := &raw.Matches[i]
		if sev, ok := keptSeverity(m.Vulnerability.Severity); ok && sev != "UNKNOWN" {
			keep[m.Vulnerability.ID+"-"+m.Artifact.Name]++
			want++
		}
	}

	var doc map[string]any
	if err := readJSONFile(sarif, &doc); err != nil {
		return fmt.Errorf("read grype's SARIF: %w", err)
	}
	runs, _ := doc["runs"].([]any)
	got := 0
	for _, r := range runs {
		run, _ := r.(map[string]any)
		results, _ := run["results"].([]any)
		kept := []any{}
		used := map[string]bool{}
		for _, res := range results {
			id, _ := res.(map[string]any)["ruleId"].(string)
			if keep[id] > 0 {
				kept = append(kept, res)
				used[id] = true
			}
		}
		got += len(kept)
		run["results"] = kept
		if tool, ok := run["tool"].(map[string]any); ok {
			if driver, ok := tool["driver"].(map[string]any); ok {
				rules, _ := driver["rules"].([]any)
				// Not slices.Clone, which gives nil for nil, and nil is JSON null
				driver["rules"] = slices.DeleteFunc(append([]any{}, rules...), func(rule any) bool {
					id, _ := rule.(map[string]any)["id"].(string)
					return !used[id]
				})
			}
		}
	}
	if got != want {
		return fmt.Errorf("grype's SARIF %s holds %d results for the report's %d HIGH or CRITICAL findings: "+
			"its rules no longer read as <ID>-<package>, so code scanning would not see what the verdict counts", sarif, got, want)
	}
	data, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}
	return writeFileIn(sarif, data)
}

// LocateSARIF rewrites the SARIF at sarif to place each location of a
// result that names no file at uri. grype places no finding of an SBOM's
// at a file, as an SBOM names no file its components are in, so uri is
// the SBOM's own path in the image: code scanning then shows where the
// component is declared. A location that names a file keeps it.
func LocateSARIF(sarif, uri string) error {
	var doc map[string]any
	if err := readJSONFile(sarif, &doc); err != nil {
		return fmt.Errorf("read grype's SARIF: %w", err)
	}
	runs, _ := doc["runs"].([]any)
	for _, r := range runs {
		run, _ := r.(map[string]any)
		results, _ := run["results"].([]any)
		for _, res := range results {
			locations, _ := res.(map[string]any)["locations"].([]any)
			for _, l := range locations {
				physical, _ := l.(map[string]any)["physicalLocation"].(map[string]any)
				artifact, _ := physical["artifactLocation"].(map[string]any)
				if at, _ := artifact["uri"].(string); artifact != nil && at == "" {
					artifact["uri"] = uri
				}
			}
		}
	}
	data, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}
	return writeFileIn(sarif, data)
}

// MergeSARIF adds the runs of the SARIF at from to the SARIF at into. A
// run whose tool a run of into's names too goes into that run: its
// results after that run's own, and each of its rules the run lacks.
// Any other run goes beside into's. Code scanning refuses a file with two
// runs of one tool in one category, and the scan uploads one file for
// each architecture, so each tool keeps one run there.
func MergeSARIF(into, from string) error {
	var dst, src map[string]any
	if err := readJSONFile(into, &dst); err != nil {
		return fmt.Errorf("read the SARIF to merge into: %w", err)
	}
	if err := readJSONFile(from, &src); err != nil {
		return fmt.Errorf("read the SARIF to merge: %w", err)
	}
	runs, ok := dst["runs"].([]any)
	if !ok {
		return fmt.Errorf("%s holds no runs to merge into", into)
	}
	more, _ := src["runs"].([]any)
	for i, r := range runs {
		if _, ok := r.(map[string]any); !ok {
			return fmt.Errorf("run %d of %s is not a JSON object, so it is no SARIF run", i, into)
		}
	}
	for i, r := range more {
		if _, ok := r.(map[string]any); !ok {
			return fmt.Errorf("run %d of %s is not a JSON object, so it is no SARIF run", i, from)
		}
	}
	for _, r := range more {
		run, _ := r.(map[string]any)
		i := slices.IndexFunc(runs, func(x any) bool {
			other, _ := x.(map[string]any)
			return toolName(other) == toolName(run)
		})
		if i < 0 {
			runs = append(runs, run)
			continue
		}
		target, _ := runs[i].(map[string]any)
		results, _ := target["results"].([]any)
		added, _ := run["results"].([]any)
		target["results"] = append(results, added...)
		have := map[string]bool{}
		rules := driverOf(target)["rules"]
		kept, _ := rules.([]any)
		for _, rule := range kept {
			id, _ := rule.(map[string]any)["id"].(string)
			have[id] = true
		}
		newRules, _ := driverOf(run)["rules"].([]any)
		for _, rule := range newRules {
			if id, _ := rule.(map[string]any)["id"].(string); !have[id] {
				kept = append(kept, rule)
				have[id] = true
			}
		}
		if d := driverOf(target); d != nil {
			d["rules"] = kept
		}
	}
	for _, r := range runs {
		run, _ := r.(map[string]any)
		requireArrays(run)
	}
	dst["runs"] = runs
	data, err := json.MarshalIndent(dst, "", " ")
	if err != nil {
		return err
	}
	return writeFileIn(into, data)
}

// requireArrays gives a SARIF run an array for its results and for its
// tool.driver.rules where it has none, or has null. Code scanning refuses
// a run with null in either. A nil slice marshals to null, so it counts as
// none.
func requireArrays(run map[string]any) {
	if v, ok := run["results"].([]any); !ok || v == nil {
		run["results"] = []any{}
	}
	if d := driverOf(run); d != nil {
		if v, ok := d["rules"].([]any); !ok || v == nil {
			d["rules"] = []any{}
		}
	}
}

// driverOf is a SARIF run's tool.driver, or nil.
func driverOf(run map[string]any) map[string]any {
	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	return driver
}

// toolName is the name of a SARIF run's tool.
func toolName(run map[string]any) string {
	name, _ := driverOf(run)["name"].(string)
	return name
}

// readJSONFile decodes the JSON file at path, read through an [os.Root] on
// its directory, into v.
func readJSONFile(path string, v any) (err error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	data, err := dir.ReadFile(filepath.Base(path))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

// writeFileIn writes data to the file at path, through an [os.Root] on its
// directory.
func writeFileIn(path string, data []byte) (err error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	return dir.WriteFile(filepath.Base(path), data, 0o600)
}
