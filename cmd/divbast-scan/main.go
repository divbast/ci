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
// While IMAGE is not anonymously pullable, because nothing is published
// there yet or the package is private, nothing is already shipped to
// compare with, and every finding is an advisory. A private package would
// keep the scan advisory for as long as it stayed private, so that is
// never quiet: it is a warning on stderr, a GitHub Actions warning under
// GITHUB_ACTIONS=true, and a callout on the summary page.
//
// Exit codes:
//
//	0  nothing IMAGE lacks, or every finding is an advisory because IMAGE
//	   is not anonymously pullable
//	1  a finding IMAGE lacks; a scan that failed or saw no packages; IMAGE
//	   unreachable for any other reason; or the summary not written
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
	"github.com/divbast/ci/internal/scan"
)

const name = "divbast-scan"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], execx.OS{}, os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
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
	candidate, packages, arch, err := scan.ParseTrivy(bytes.NewReader(data))
	if err != nil {
		complain(stderr, "%s: %v", *report, err)
		return 1
	}
	// A clean report from a scan that saw no packages means it never looked
	if packages == 0 {
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

	var (
		shipped          []scan.Finding
		against, warning string
		unpullable       bool
	)
	err = trivy.Published(ctx, *published, arch, *baseline)
	switch {
	case err == nil:
		if shipped, against, err = readBaseline(*baseline, *published); err != nil {
			complain(stderr, "%v", err)
			return 1
		}
	case errors.Is(err, scan.ErrUnpullable):
		// With nothing published, nothing is already shipped, and a first
		// image could never pass a scan that blocks on what it inherits
		// from the FrankenPHP binary.
		if err = os.WriteFile(*baseline, []byte("{}\n"), 0o600); err != nil {
			complain(stderr, "write the baseline: %v", err)
			return 1
		}
		unpullable = true
		against = "nothing, because " + *published + " is not anonymously pullable"
		warning = "The scan is advisory because " + *published + " is not anonymously pullable: it is not published yet, " +
			"or it is private. It stays advisory until " + *published + " is public."
		complain(stderr, "WARNING: %s", warning)
		if getenv("GITHUB_ACTIONS") == "true" {
			if _, err = fmt.Fprintf(stdout, "::warning title=Scan is advisory::%s\n", warning); err != nil {
				complain(stderr, "write the warning: %v", err)
				return 1
			}
		}
	default:
		complain(stderr, "could not scan %s, so no finding can be told apart from one already published: %v", *published, err)
		return 1
	}

	split := scan.Compare(candidate, shipped)
	verdict, heading := "new, so blocking", "New, so blocking"
	if unpullable {
		verdict, heading = "advisory: nothing published yet", "Advisory: nothing published yet"
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
	case unpullable:
		_, err = fmt.Fprintf(stdout, "%s is not anonymously pullable, so all %d finding(s) are advisory\n", *published, len(split.New))
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

// readBaseline returns the findings in the report on the published image
// at path, and the image it names.
func readBaseline(path, image string) (shipped []scan.Finding, ref string, err error) {
	data, err := readFile(path)
	if err != nil {
		return nil, "", err
	}
	shipped, packages, _, err := scan.ParseTrivy(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if packages == 0 {
		return nil, "", fmt.Errorf("no packages in %s: the scan found nothing to scan, not nothing wrong", image)
	}
	if ref, err = scan.ImageRef(bytes.NewReader(data)); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return shipped, ref, nil
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
