// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-scan fails a build on a HIGH or CRITICAL vulnerability
// in the image it made only when the image already published lacks it.
//
// Usage:
//
//	divbast-scan -layout DIR -report FILE -published IMAGE -baseline FILE -sarif FILE [-vex FILE]
//
// A repository that checks divbast/ci out at .ci runs it from its own root
// as .ci/bin/divbast-scan, once `just ci-tools` has built it:
//
//	.ci/bin/divbast-scan -layout /tmp/image.tar.layout -report /tmp/image.tar.report.json \
//	    -published ghcr.io/divbast/librespeed:latest -baseline /tmp/image.tar.published.json \
//	    -sarif /tmp/image.tar.sarif
//
// It scans the OCI layout in DIR with trivy, writing the JSON report to
// -report and its SARIF, for code scanning, to -sarif. It then scans IMAGE
// as the registry serves it, for the layout's architecture and from the
// same vulnerability database, writing that report to -baseline. A finding
// IMAGE has too, the same vulnerability in the same package at any
// version, is reported as an advisory. -vex names an OpenVEX document both
// scans apply.
//
// It lists every finding on stdout and, when GitHub Actions sets it,
// appends them as tables to $GITHUB_STEP_SUMMARY.
//
// Before it scans IMAGE, a ghcr.io image, it reads it as an anonymous
// client with skopeo, as users pull it. When the registry refuses, it asks
// the GitHub API why, through gh, whose token is GH_TOKEN, which must be
// able to read packages (a job's packages: read). While nothing is
// published there yet, or the package is private, nothing is already
// shipped to compare with, and every finding is an advisory. A private
// package would keep the scan advisory for as long as it stayed private,
// so neither is ever quiet: each is a warning on stderr, a GitHub Actions
// warning, and a callout on the summary page. A package GitHub lists as
// public that the registry will not show is a registry failing, and fails
// the scan, as does a registry or an API that does not answer. Trivy is
// asked only to scan, and any failure of that scan fails it, whatever
// Trivy says about why.
//
// Outside GitHub Actions, without GITHUB_ACTIONS=true, it never asks
// GitHub: no token a person holds for divbast's recipes can read
// packages. A refusal is then an advisory too, with a warning that only
// CI can tell what it means.
//
// Only gh gets the token: trivy and skopeo run with GH_TOKEN and
// GITHUB_TOKEN empty.
//
// Exit codes:
//
//	0  nothing IMAGE lacks; or every finding is an advisory, because IMAGE
//	   is not published yet or is private, or, outside GitHub Actions,
//	   because the registry refused to show it
//	1  a finding IMAGE lacks; a scan that failed or saw no packages; IMAGE
//	   not a ghcr.io image, unreadable, or refused though public; the
//	   GitHub API not answering, or refusing the token; or the summary not
//	   written
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
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
	"github.com/divbast/ci/internal/registry"
	"github.com/divbast/ci/internal/scan"
)

const name = "divbast-scan"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], tokenOnlyForGH{}, os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// tokenOnlyForGH runs commands on the host, and only gh with the token
// the environment holds: every other command, trivy and skopeo, gets
// GH_TOKEN and GITHUB_TOKEN empty. They read registries anonymously, and
// trivy parses whatever an image holds.
type tokenOnlyForGH struct{}

// Run implements [execx.Runner].
func (tokenOnlyForGH) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	if name == "gh" {
		return execx.OS{}.Run(ctx, name, args...)
	}
	return execx.OS{Env: []string{"GH_TOKEN=", "GITHUB_TOKEN="}}.Run(ctx, name, args...)
}

func run(ctx context.Context, args []string, r execx.Runner, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	layout := flags.String("layout", "", "the OCI layout `DIR` of the image to scan")
	report := flags.String("report", "", "the `FILE` to write its report to")
	published := flags.String("published", "", "the published `IMAGE` to compare it with")
	baseline := flags.String("baseline", "", "the `FILE` to write the report on the published image to")
	sarif := flags.String("sarif", "", "the `FILE` to write the SARIF for code scanning to")
	vex := flags.String("vex", "", "an OpenVEX `FILE` both scans apply, if any")
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

	trivy := scan.Trivy{Run: r, VEX: *vex, Log: stderr}
	if err := trivy.Layout(ctx, *layout, *report); err != nil {
		complain(stderr, "trivy could not scan %s: %v", *layout, err)
		return 1
	}
	data, err := readFile(*report)
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	candidate, err := scan.ParseTrivy(bytes.NewReader(data))
	if err != nil {
		complain(stderr, "%s: %v", *report, err)
		return 1
	}
	arch := candidate.Arch
	// A clean report from a scan that saw no packages means it never looked
	if candidate.Packages == 0 {
		complain(stderr, "no packages in %s: the scan found nothing to scan, not nothing wrong", *layout)
		return 1
	}
	if err = trivy.SARIF(ctx, *report, *sarif); err != nil {
		complain(stderr, "trivy could not convert %s to SARIF at %s: %v", *report, *sarif, err)
		return 1
	}
	if arch == "" {
		complain(stderr, "%s names no architecture, so nothing says which of %s to compare with", *report, *published)
		return 1
	}

	inActions := getenv("GITHUB_ACTIONS") == "true"
	lookup := registry.Lookup{Run: r, GH: ghapi.Client{Run: r}, RegistryOnly: !inActions}
	state, err := lookup.Presence(ctx, *published)
	advisory, err := unshippedFor(state, err, inActions, *published)
	if err != nil {
		complain(stderr, "could not tell whether %s is published, so no finding can be told apart from one already published: %v", *published, err)
		return 1
	}

	var (
		shipped          []scan.Finding
		against, warning string
	)
	if advisory == nil {
		if err = trivy.Published(ctx, *published, arch, *baseline); err != nil {
			complain(stderr, "could not scan %s, so no finding can be told apart from one already published: %v", *published, err)
			return 1
		}
		if shipped, against, err = readBaseline(*baseline, *published); err != nil {
			complain(stderr, "%v", err)
			return 1
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

	split := scan.Compare(candidate.Findings, shipped)
	verdict, heading := "new, so blocking", "New, so blocking"
	if advisory != nil {
		verdict, heading = "advisory: "+advisory.heading, "Advisory: "+advisory.heading
	}
	if _, err = io.WriteString(stdout, scan.Listing(against, verdict, split)); err != nil {
		complain(stderr, "write the findings: %v", err)
		return 1
	}
	if err = appendTo(getenv("GITHUB_STEP_SUMMARY"), scan.Summary(arch, against, heading, warning, split)); err != nil {
		complain(stderr, "write the run summary: %v", err)
		return 1
	}

	switch {
	case advisory != nil:
		_, err = fmt.Fprintf(stdout, "%s %s, so all %d finding(s) are advisory\n", *published, advisory.reason, len(split.New))
	case len(split.New) > 0:
		move := "Move what carries them"
		if *vex != "" {
			move += ", or argue reachability in " + *vex
		}
		complain(stderr, "%d finding(s) the published image does not have. %s.", len(split.New), move)
		return 1
	default:
		_, err = fmt.Fprintf(stdout, "nothing new against what is published (%d advisory)\n", len(split.Old))
	}
	if err != nil {
		complain(stderr, "write the verdict: %v", err)
		return 1
	}
	return 0
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

// readBaseline returns the findings in the report on the published image
// at path, and the image it names.
func readBaseline(path, image string) (shipped []scan.Finding, ref string, err error) {
	data, err := readFile(path)
	if err != nil {
		return nil, "", err
	}
	rep, err := scan.ParseTrivy(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if rep.Packages == 0 {
		return nil, "", fmt.Errorf("no packages in %s: the scan found nothing to scan, not nothing wrong", image)
	}
	return rep.Findings, rep.Ref, nil
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
