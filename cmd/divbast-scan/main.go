// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-scan fails a build on a HIGH or CRITICAL vulnerability
// in the image it made only when the image already published lacks it.
//
// Usage:
//
//	divbast-scan -layout DIR -report FILE -published IMAGE -baseline FILE -sarif FILE
//	    [-containerfile FILE] [-vex FILE]... [-cache DIR]
//
// A repository that checks divbast/ci out at .ci runs it from its own root
// as .ci/bin/divbast-scan, once `just ci-tools` has built it:
//
//	.ci/bin/divbast-scan -layout /tmp/image.tar.layout -report /tmp/image.tar.report.json \
//	    -published ghcr.io/divbast/librespeed:latest -baseline /tmp/image.tar.published.json \
//	    -sarif /tmp/image.tar.sarif -containerfile Containerfile
//
// DIR holds one linux image. Before any scan, the command reads its
// architecture and its own os-release, the zstd layers with the zstd
// command, and the os-release decides the scanner. An image that says
// ID=dhi, a Docker Hardened Image on Docker's own advisories, is scanned
// by grype, which reads that model; any other image by trivy, which reads
// a DHI image as plain Debian while it keeps /etc/debian_version. The
// published image is scanned by the same scanner, so both sides share one
// model and one vulnerability database.
//
// It scans the OCI layout in DIR, writing the JSON report to -report and
// its SARIF, for code scanning, to -sarif, once the report passes the
// checks below. It then scans IMAGE as the registry serves it, for the
// layout's architecture and from the same vulnerability database, writing
// that report to -baseline. A finding IMAGE has too is reported as an
// advisory: the same vulnerability, by any of its IDs, in the same package
// at any version, or any finding in a package IMAGE ships at that very
// version. A new finding with no severity, which DHI's advisories have, is
// listed and never blocks. -vex names an OpenVEX document both scans
// apply, the app's own; it may be given more than once. Every trivy call
// turns off the .trivyignore and trivy.yaml trivy would read from the
// working directory, the caller's repository, and every grype call names
// a configuration of the command's own instead of a .grype.yaml there;
// each runs with none of its TRIVY_ or GRYPE_ variables in its
// environment.
//
// For grype, -cache names the directory its configuration and its
// vulnerability database go in, by default divbast-scan's own in the
// user's cache directory, so a local scan keeps the database between runs,
// for an image that says ID=dhi and for any that declares lockfiles or
// SBOMs.
// It updates the database once, with grype db update, then asks it about a
// package a record in DHI's own namespace is known to match, for the
// image's ID_LIKE and VERSION_ID, and refuses to scan unless the match
// comes from there: a database without DHI's advisories reads every DHI
// image as clean. The two reports, beside -report and -baseline as
// .cdx.json, list every package, where grype's JSON lists only those with
// findings. A report from grype must say distro dhi at the image's
// VERSION_ID, key every OS package under dhi, and match nothing from
// Debian's or Alpine's advisories; both must name the same database, with
// the dhi provider in it. A report refused leaves no SARIF behind.
//
// -containerfile names the Containerfile the image was built from. When
// its final stage builds on a dhi.io image, a Docker Hardened Image (its
// last FROM's image, a build argument resolved to its default, or the
// base of the earlier stage that FROM names), Docker publishes an
// OpenVEX document of the vulnerabilities its Debian builds there are not
// affected by, which Trivy, reading them as Debian's own, would otherwise
// report. Before either scan, the command fetches it from the main branch
// of github.com/docker-hardened-images/advisories, with the Sigstore
// bundle beside it, as an anonymous client, and has cosign verify it
// against Docker's key, dhi-2.pub, which the command embeds:
//
//	cosign verify-blob --key dhi-2.pub --bundle dhi-<name>.vex.json.sig dhi-<name>.vex.json
//
// Each of the document's statements must then name that image, and no
// other, among its products, as each of Docker's does: Docker signs every
// image's document with the same key. Both scans then apply the verified
// document, after any -vex. One that cannot be fetched, is not verified,
// or is not that image's fails the scan, naming the image. A build
// stage's document is never fetched: its packages do not ship, and its
// document answers for its own image alone. A final stage on any other
// base, or on scratch, fetches nothing. The document and the key go in a
// temporary directory, in $TMPDIR, removed once the scans are done.
// Without -containerfile, no document of Docker's is applied.
//
// An image may declare, in its io.github.divbast.scan.lockfiles label, the
// lockfiles it ships of the packages that built it: absolute paths in the
// image, separated by commas, each a pnpm-lock.yaml of 64 MiB at most:
//
//	LABEL io.github.divbast.scan.lockfiles="/usr/share/doc/pisati/pnpm-lock.yaml"
//
// No image scan reads a lockfile, so grype scans each one the label
// declares, whichever scanner reads the image, as a directory scan would:
// from the image's layers, written at its path in a temporary directory in
// $TMPDIR, removed once the scans are done. Its report and CycloneDX go
// beside -report, as .lockfiles.json and .lockfiles.cdx.json, and its HIGH
// and CRITICAL findings into the SARIF, in grype's run. Its database is
// the image's scan's for an image that says ID=dhi; for any other, grype
// is configured in -cache, and its database updated once. A lockfile in
// which grype finds no package is refused.
//
// A lockfile's findings join the image's, and are judged as every finding
// is, but one can block only in the lockfile's runtime packages: those an
// importer's dependencies or optionalDependencies reach, in any of the
// file's documents. A finding in any other package the lockfile names, one
// only devDependencies reach, or pnpm's own, from pnpm 12's boot document,
// is listed and never blocks. So is every finding in a lockfile while
// IMAGE carries none. To tell, with lockfiles declared, the scan reads
// IMAGE by the digest the registry served, both for its scan and for a
// copy of its layers, which skopeo makes for the layout's architecture, as
// an anonymous client, into the temporary directory; the lockfiles
// IMAGE's own label declares are scanned as the candidate's are, their
// report beside -baseline. An image without the label is scanned as
// before, and nothing of IMAGE is copied.
//
// An image may also declare, in its io.github.divbast.scan.sboms label,
// CycloneDX SBOMs of what it ships that no image scan sees, such as a
// binary it builds from source: absolute paths in the image, separated by
// commas, each a file whose name ends in .cdx.json, of 16 MiB at most:
//
//	LABEL io.github.divbast.scan.sboms="/usr/local/share/divbast/sbom.cdx.json"
//
// Each component an SBOM names must have a name, a version, and a package
// URL or a CPE, which grype matches it by. grype scans each SBOM the label
// declares, whichever scanner reads the image, one run each, as an sbom:
// source: the file from the image's layers, written at its path in the
// temporary directory. The nth SBOM's report and CycloneDX go beside
// -report, as .sboms.<n>.json and .sboms.<n>.cdx.json, counting from 1 in
// the label's order, and its HIGH and CRITICAL findings into the SARIF, in
// grype's run, each at the SBOM's path in the image. An SBOM is refused
// when grype's CycloneDX does not name every component it does. Its
// findings join the image's, each at the SBOM's path, and are judged as
// every finding is, but while IMAGE carries no SBOM each is listed and
// never blocks. IMAGE is read and copied as for lockfiles, once for both,
// and the SBOMs its own label declares are scanned as the candidate's are,
// their reports beside -baseline.
//
// It lists every finding on stdout and, when GitHub Actions sets it,
// appends them as tables to $GITHUB_STEP_SUMMARY.
//
// Before it scans IMAGE, a ghcr.io image, it reads it as an anonymous
// client with skopeo, as users pull it. When the registry refuses, it asks
// the GitHub API why, through gh, whose token is GH_TOKEN, which must be
// able to read packages (a job's packages: read). While nothing is
// published there yet, because there is no such package, or no such tag
// in a public one, or while the package is private, nothing is already
// shipped to compare with, and every finding is an advisory. A private
// package would keep the scan advisory for as long as it stayed private,
// so neither is ever quiet: each is a warning on stderr, a GitHub Actions
// warning, and a callout on the summary page. A package GitHub lists as
// public that the registry refuses for any other reason is a registry
// failing, and fails the scan, as does a registry or an API that does not
// answer. Trivy is asked only to scan, and any failure of that scan fails
// it, whatever Trivy says about why.
//
// Outside GitHub Actions, without GITHUB_ACTIONS=true, it never asks
// GitHub: no token a person holds for divbast's recipes can read
// packages. A refusal is then an advisory too, with a warning that only
// CI can tell what it means.
//
// Only gh gets the token: trivy, grype, skopeo, cosign and zstd run with
// GH_TOKEN and GITHUB_TOKEN empty.
//
// Exit codes:
//
//	0  nothing IMAGE lacks but findings that never block, in a lockfile's
//	   build-only packages or in a lockfile while IMAGE carries none; or
//	   every finding is an advisory, because IMAGE is not published yet or
//	   is private, or, outside GitHub Actions, because the registry
//	   refused to show it
//	1  a finding IMAGE lacks that can block; a Containerfile that cannot
//	   be read, or that names an image unpinned; the final stage's dhi.io
//	   base's VEX document not fetched, not verified, or not that image's;
//	   a scan that failed or saw no packages; a report, of the layout or
//	   of IMAGE, that recognised no operating system or saw no OS package;
//	   a layout that is not one linux image, or whose os-release cannot be
//	   read; for an image that says ID=dhi, grype's database not updated,
//	   no probe for its release or the probe unanswered from DHI's
//	   namespace, a report under another model than dhi's, or the two
//	   reports from different databases or without the dhi provider;
//	   IMAGE not a ghcr.io image, unreadable, or refused though public for
//	   any reason but a missing tag; the GitHub API not answering, or
//	   refusing the token; an image config, the layout's or that of IMAGE's
//	   copy, that cannot be read; a lockfile label, either's, that names
//	   other than clean absolute paths to pnpm-lock.yaml files, or one
//	   twice, or a path the image holds no file at, or a symlink; a
//	   declared lockfile larger than 64 MiB, not in pnpm's v9 format as the
//	   scan reads it, or in which grype found no package; an SBOM label
//	   that names other than clean absolute paths to .cdx.json files, or
//	   one twice, or a path the image holds no file at, or a symlink; a
//	   declared SBOM larger than 16 MiB, not CycloneDX JSON, naming no
//	   component, or one without a name, a version, or a package URL or
//	   CPE, or one grype's CycloneDX does not name; for an image that
//	   declares lockfiles or SBOMs, grype's database not updated, their
//	   SARIF not filtered, placed or merged into the image's, or IMAGE not
//	   copied; or the summary not written
//	2  the command line is wrong
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/divbast/ci/internal/dhivex"
	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
	"github.com/divbast/ci/internal/osrelease"
	"github.com/divbast/ci/internal/registry"
	"github.com/divbast/ci/internal/scan"
	"github.com/divbast/ci/internal/verify"
)

const name = "divbast-scan"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], tokenOnlyForGH{}, execx.OS{Env: noToken}, dhivex.Source{}, os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// tokenOnlyForGH runs commands on the host, and only gh with the token
// the environment holds: every other command, trivy, grype, skopeo, cosign
// and zstd, gets GH_TOKEN and GITHUB_TOKEN empty. They read registries
// anonymously, and the scanners parse whatever an image holds. trivy and
// grype also run with none of their own variables, TRIVY_ and GRYPE_.
type tokenOnlyForGH struct{}

// Run implements [execx.Runner].
func (tokenOnlyForGH) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	switch name {
	case "gh":
		return execx.OS{}.Run(ctx, name, args...)
	case "trivy", "grype":
		// Each reads a variable for every setting it has, and the scan
		// job's steps inherit a caller's mise.toml [env]. Left out, not
		// emptied: grype reads an empty one as a value, false for a switch
		return execx.OS{Env: noToken, Without: []string{strings.ToUpper(name) + "_"}}.Run(ctx, name, args...)
	}
	return execx.OS{Env: noToken}.Run(ctx, name, args...)
}

// noToken is the environment every command but gh runs with.
var noToken = []string{"GH_TOKEN=", "GITHUB_TOKEN="}

// run is the command. r runs every command it runs but zstd, which zstd
// runs for the layout's zstd layers, and src is where DHI's VEX documents
// are fetched from.
func run(ctx context.Context, args []string, r execx.Runner, zstd execx.StreamRunner, src dhivex.Source, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	layout := flags.String("layout", "", "the OCI layout `DIR` of the image to scan")
	report := flags.String("report", "", "the `FILE` to write its report to")
	published := flags.String("published", "", "the published `IMAGE` to compare it with")
	baseline := flags.String("baseline", "", "the `FILE` to write the report on the published image to")
	sarif := flags.String("sarif", "", "the `FILE` to write the SARIF for code scanning to")
	var vex files
	flags.Var(&vex, "vex", "an OpenVEX `FILE` of the app's own both scans apply; repeat for more")
	containerfile := flags.String("containerfile", "", "the Containerfile `FILE` the image was built from, "+
		"whose final stage's base, when a dhi.io image, has its signed VEX document applied by both scans")
	cache := flags.String("cache", "", "the `DIR` grype keeps its configuration and vulnerability database in, "+
		"for an image that says ID=dhi or declares lockfiles or SBOMs (default: divbast-scan's own in the user's cache directory)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		complain(stderr, "unexpected argument %q", flags.Arg(0))
		flags.Usage()
		return 2
	}
	for _, required := range []struct {
		flag  string
		value *string
	}{{"layout", layout}, {"report", report}, {"published", published}, {"baseline", baseline}, {"sarif", sarif}} {
		if *required.value == "" {
			complain(stderr, "-%s is required", required.flag)
			flags.Usage()
			return 2
		}
	}

	docs := slices.Clone(vex)
	if *containerfile != "" {
		base, ok, err := finalBase(*containerfile)
		if err != nil {
			complain(stderr, "%s: cannot tell which image the final stage builds on, so nothing is scanned: %v", *containerfile, err)
			return 1
		}
		var dhi string
		done := func() {}
		if ok {
			dhi, done, err = dhiVEX(ctx, base, src, r, getenv("TMPDIR"), stdout, stderr)
		}
		if err != nil {
			complain(stderr, "could not apply DHI's signed VEX for the final stage's base, so nothing is scanned: %v", err)
			return 1
		}
		defer done()
		if dhi != "" {
			docs = append(docs, dhi)
		}
	}

	// What the image says it is decides which scanner reads it
	layoutArch, err := osrelease.Arch(*layout)
	if err != nil {
		complain(stderr, "cannot tell which image to scan: %v", err)
		return 1
	}
	info, hasOS, err := osrelease.Read(ctx, zstd, *layout, layoutArch)
	if err != nil {
		complain(stderr, "could not read the image's own os-release, so nothing says which model to scan it under: %v", err)
		return 1
	}
	lockPaths, bomPaths, err := declaredBy(*layout, layoutArch, *layout)
	if err != nil {
		complain(stderr, "nothing is scanned: %v", err)
		return 1
	}
	locks, err := readLockfiles(ctx, zstd, *layout, layoutArch, *layout, lockPaths)
	if err != nil {
		complain(stderr, "could not read the lockfiles the image declares, so nothing is scanned: %v", err)
		return 1
	}
	read, err := locks.runtime()
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	boms, err := readSBOMs(ctx, zstd, *layout, layoutArch, *layout, bomPaths)
	if err != nil {
		complain(stderr, "could not read the SBOMs the image declares, so nothing is scanned: %v", err)
		return 1
	}
	var sc scanner = &trivyScanner{
		trivy:  scan.Trivy{Run: r, VEX: docs, Log: stderr},
		layout: *layout, report: *report, sarif: *sarif, baseline: *baseline,
	}
	if hasOS && info.ID == "dhi" {
		g := scan.Grype{Run: r, VEX: docs, Log: stderr}
		var dir string
		dir, err = grypeCache(*cache)
		if err == nil {
			g.Config, err = g.WriteConfig(dir)
		}
		if err != nil {
			complain(stderr, "could not write grype's configuration: %v", err)
			return 1
		}
		if _, err = fmt.Fprintf(stdout, "%s says ID=dhi, Docker's own model, so grype scans it, against DHI's advisories\n", *layout); err != nil {
			complain(stderr, "write the scanner: %v", err)
			return 1
		}
		sc = &grypeScanner{
			grype: g, info: info, arch: layoutArch,
			layout: *layout, report: *report, sarif: *sarif, baseline: *baseline,
		}
	}
	candidate, err := sc.candidate(ctx)
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	arch := candidate.Arch
	if arch == "" {
		complain(stderr, "%s names no architecture, so nothing says which of %s to compare with", *report, *published)
		return 1
	}

	// The declared files' own scans, by grype whatever scans the image:
	// its directory catalogers read lockfiles, and its sbom: source reads
	// an SBOM, where an image's catalogers read neither
	var (
		g               scan.Grype
		tmp             string
		lockRep, bomRep scan.Report
	)
	declares := len(locks.paths) > 0 || len(boms.paths) > 0
	if len(locks.paths) > 0 {
		if _, err = fmt.Fprintf(stdout, "%s declares %s in its %s label, so grype scans them too, and their findings in build-only packages never block\n",
			*layout, locks, lockfileLabel); err != nil {
			complain(stderr, "write the lockfiles: %v", err)
			return 1
		}
	}
	if len(boms.paths) > 0 {
		if _, err = fmt.Fprintf(stdout, "%s declares %s in its %s label, so grype scans them too\n", *layout, boms, sbomLabel); err != nil {
			complain(stderr, "write the SBOMs: %v", err)
			return 1
		}
	}
	if declares {
		if tmp, err = os.MkdirTemp(getenv("TMPDIR"), name+"-declared-"); err != nil {
			complain(stderr, "make a directory for the files the image declares: %v", err)
			return 1
		}
		defer func() {
			if rerr := os.RemoveAll(tmp); rerr != nil {
				complain(stderr, "remove %s: %v", tmp, rerr)
			}
		}()
		if g, err = declaredGrype(ctx, sc, *cache, docs, r, stderr); err != nil {
			complain(stderr, "%v", err)
			return 1
		}
	}
	if len(locks.paths) > 0 {
		lockSARIF := filepath.Join(tmp, "candidate.sarif")
		lockRep, err = locks.scan(ctx, g, filepath.Join(tmp, "candidate"), *report+".lockfiles.json", *report+".lockfiles.cdx.json", lockSARIF)
		if err == nil {
			err = g.SARIF(*report+".lockfiles.json", lockSARIF)
		}
		if err == nil {
			err = scan.MergeSARIF(*sarif, lockSARIF)
		}
		if err != nil {
			complain(stderr, "%v", err)
			return 1
		}
	}
	if len(boms.paths) > 0 {
		if bomRep, err = boms.scan(ctx, g, filepath.Join(tmp, "candidate-sboms"), *report+".sboms", *sarif); err != nil {
			complain(stderr, "%v", err)
			return 1
		}
	}

	inActions := getenv("GITHUB_ACTIONS") == "true"
	lookup := registry.Lookup{Run: r, GH: ghapi.Client{Run: r}, RegistryOnly: !inActions}
	// With declared files, the published image is read twice, by its
	// scanner and for its layers, so both read it by the digest the
	// registry served
	ref := *published
	var state registry.State
	if declares {
		var pinned string
		if pinned, state, err = lookup.Pin(ctx, *published); pinned != "" {
			ref = pinned
		}
	} else {
		state, err = lookup.Presence(ctx, *published)
	}
	advisory, err := unshippedFor(state, err, inActions, *published)
	if err != nil {
		complain(stderr, "could not tell whether %s is published, so no finding can be told apart from one already published: %v", *published, err)
		return 1
	}

	var (
		shipped                       []scan.Finding
		inventory                     []scan.Pkg
		against, warning              string
		uncarriedLocks, uncarriedBOMs bool
	)
	if advisory == nil {
		var pub scan.Report
		if pub, err = sc.published(ctx, ref, arch); err != nil {
			complain(stderr, "%v", err)
			return 1
		}
		shipped, inventory, against = pub.Findings, pub.Inventory, pub.Ref
		if declares {
			if uncarriedLocks, uncarriedBOMs, err = publishedDeclared(ctx, lookup, zstd, g, locks, boms,
				ref, arch, tmp, *baseline, &shipped, &inventory, stdout); err != nil {
				complain(stderr, "%v", err)
				return 1
			}
		}
	} else {
		// With nothing published, nothing is already shipped, and a first
		// image could never pass a scan that blocks on what it inherits
		// from the FrankenPHP binary.
		if err = writeFile(*baseline, "{}\n"); err != nil {
			complain(stderr, "write the baseline: %v", err)
			return 1
		}
		against = "nothing, because " + *published + " " + advisory.reason
		warning = "The scan is advisory because " + *published + " " + advisory.reason + ": " + advisory.more
		complain(stderr, "WARNING: %s", warning)
		if inActions {
			if _, err = fmt.Fprintf(stdout, "::warning title=Scan is advisory::%s\n", warning); err != nil {
				complain(stderr, "write the warning: %v", err)
				return 1
			}
		}
	}

	held(lockRep.Findings, read, uncarriedLocks)
	if uncarriedBOMs {
		for i := range bomRep.Findings {
			bomRep.Findings[i].Hold = scan.UncarriedSBOM
		}
	}
	split := scan.Compare(slices.Concat(candidate.Findings, lockRep.Findings, bomRep.Findings), shipped, inventory)
	verdict, heading := "new, so blocking", "New, so blocking"
	if advisory != nil {
		verdict, heading = "advisory: "+advisory.heading, "Advisory: "+advisory.heading
	}
	if _, err = io.WriteString(stdout, scan.Listing(against, verdict, &split)); err != nil {
		complain(stderr, "write the findings: %v", err)
		return 1
	}
	if err = appendTo(getenv("GITHUB_STEP_SUMMARY"), scan.Summary(arch, against, heading, warning, &split)); err != nil {
		complain(stderr, "write the run summary: %v", err)
		return 1
	}

	switch {
	case advisory != nil:
		_, err = fmt.Fprintf(stdout, "%s %s, so all %d finding(s) are advisory\n", *published, advisory.reason, len(split.New)+len(split.Listed)+len(split.Held))
	case len(split.New) > 0:
		move := "Move what carries them"
		if len(vex) > 0 {
			move += ", or argue reachability in " + strings.Join(vex, " or ")
		}
		complain(stderr, "%d finding(s) the published image does not have. %s.", len(split.New), move)
		return 1
	default:
		counts := fmt.Sprintf("%d advisory", len(split.Old))
		if len(split.Listed) > 0 {
			counts += fmt.Sprintf(", %d listed with no severity", len(split.Listed))
		}
		inSBOMs := 0
		for i := range split.Held {
			if split.Held[i].Hold == scan.UncarriedSBOM {
				inSBOMs++
			}
		}
		if n := len(split.Held) - inSBOMs; n > 0 {
			counts += fmt.Sprintf(", %d in lockfiles listed, not blocking", n)
		}
		if inSBOMs > 0 {
			counts += fmt.Sprintf(", %d in SBOMs listed, not blocking", inSBOMs)
		}
		_, err = fmt.Fprintf(stdout, "nothing new against what is published (%s)\n", counts)
	}
	if err != nil {
		complain(stderr, "write the verdict: %v", err)
		return 1
	}
	return 0
}

// files is a flag that may be given more than once, each a file. An
// empty one names none, as an empty -vex always has.
type files []string

// String implements [flag.Value].
func (f *files) String() string { return strings.Join(*f, ", ") }

// Set implements [flag.Value].
func (f *files) Set(path string) error {
	if path != "" {
		*f = append(*f, path)
	}
	return nil
}

// finalBase reads the Containerfile at path, and returns the image its
// final stage builds on, as [verify.Base] does.
func finalBase(path string) (base verify.Ref, ok bool, err error) {
	data, err := readFile(path)
	if err != nil {
		return verify.Ref{}, false, err
	}
	return verify.Base(bytes.NewReader(data))
}

// dhiVEX, when base is a dhi.io image, fetches its VEX document from src,
// with dhi-2.pub beside it in a directory it makes in tmp, or the system's
// temporary directory when tmp is "", and has cosign, through r, verify
// it. It says on stdout what it applies, and returns the document's path,
// "" for none, and what removes the directory, which the caller runs once
// the scans are done; on an error, it leaves nothing behind.
func dhiVEX(ctx context.Context, base verify.Ref, src dhivex.Source, r execx.Runner, tmp string, stdout, stderr io.Writer) (doc string, done func(), err error) {
	image, ok, err := dhivex.Name(base)
	if err != nil || !ok {
		return "", func() {}, err
	}

	dir, err := os.MkdirTemp(tmp, name+"-")
	if err != nil {
		return "", nil, fmt.Errorf("make a directory for the document: %w", err)
	}
	// What a directory left behind holds is public, Docker's document and
	// key, so it is reported without changing the verdict.
	done = func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			complain(stderr, "remove %s: %v", dir, rerr)
		}
	}
	key, err := verify.WriteDHIKey(dir)
	if err == nil {
		doc, err = dhivex.Document(ctx, src, dhivex.Verifier{Cosign: r, Key: key, Log: stderr}, dir, image)
	}
	if err == nil {
		_, err = fmt.Fprintf(stdout, "applying the VEX document of %s%s, the final stage's base, verified against dhi-2.pub\n", verify.DHI, image)
	}
	if err != nil {
		done()
		return "", nil, err
	}
	return doc, done, nil
}

// unshipped says why nothing is shipped to compare with, so that every
// finding is an advisory: reason follows the image's name, heading
// follows "advisory: ", and more follows the reason in the warning.
type unshipped struct{ reason, heading, more string }

// unshippedFor turns what [registry.Lookup.Presence] answered for
// published, state and err, into why nothing is shipped to compare with:
// nil when published is published, and the scan compares with it. A
// refusal GitHub was not asked about, [registry.ErrRefused], is an
// advisory only outside GitHub Actions; in Actions it is an error, as is
// anything else that says neither, and an error fails the scan.
func unshippedFor(state registry.State, err error, inActions bool, published string) (*unshipped, error) {
	switch {
	case err == nil && state == registry.Published:
		return nil, nil
	case err == nil && state == registry.Absent:
		return &unshipped{
			reason: "is not published yet", heading: "nothing published yet",
			more: "nothing is shipped to compare with. It blocks on new findings once " + published + " is published.",
		}, nil
	case errors.Is(err, registry.ErrPrivate):
		return &unshipped{
			reason: "is private", heading: "nothing public yet",
			more: "no user can pull it, and nothing is shipped to compare with. It stays advisory until " + published + " is public.",
		}, nil
	case !inActions && errors.Is(err, registry.ErrRefused):
		return &unshipped{
			reason: "was refused by ghcr.io", heading: "nothing readable to compare with",
			more: "outside GitHub Actions nothing asks GitHub whether that means it is not published yet, is private, or is " +
				"public and failing to serve: the token a person gives the recipes cannot read packages. CI's scan asks, and decides.",
		}, nil
	case err == nil:
		return nil, fmt.Errorf("the lookup answered %v, and no error", state)
	default:
		return nil, err
	}
}

// noOS says why a report blind to the OS is refused, and what Trivy
// reported, since an OS it did not recognise and an OS it saw no packages
// of need different fixes. An image whose OS Trivy does not know still has
// its language packages, which count as packages, so only the OS says
// whether the scan looked at the rest.
func noOS(rep *scan.Report, scanner string) string {
	saw := "recognised no operating system and saw"
	if rep.OS != "" && rep.Family != "none" {
		saw = "recognised " + rep.OS + " but saw"
	}
	return fmt.Sprintf("%s %s %d OS packages, so the scan cannot see OS packages and nothing shows they are clean",
		scanner, saw, rep.OSPackages)
}

// blindToOS reports whether rep identified no OS or saw no OS package.
// Trivy names an OS it found no analyser for "none".
func blindToOS(rep *scan.Report) bool {
	return rep.OS == "" || rep.Family == "none" || rep.OSPackages == 0
}

// readFile reads the file at path, through an [os.Root] on its directory.
func readFile(path string) (data []byte, err error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	return dir.ReadFile(filepath.Base(path))
}

// writeFile writes text to the file at path, inside its directory as an
// [os.Root], as appendTo does.
func writeFile(path, text string) (err error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	return dir.WriteFile(filepath.Base(path), []byte(text), 0o600)
}

// appendTo appends text to the file at path, one of the files GitHub
// Actions names in the environment, and does nothing when path is empty.
// It opens the file inside its directory as an [os.Root], so that it
// writes that file and nothing a symlink would lead out of the directory.
func appendTo(path, text string) (err error) {
	if path == "" {
		return nil
	}
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	f, err := dir.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	_, err = f.WriteString(text)
	return err
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
