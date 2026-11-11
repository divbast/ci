// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-release publishes a commit on main as the repository's
// next release: the next vX.Y.Z tag at that commit, and a GitHub release
// of it whose notes come from the commits since the last one.
//
// Usage:
//
//	divbast-release -sha SHA [-dry-run]
//
// It runs in a clone of the repository, and reads origin's main and
// release tags from origin itself. The clone must have every release tag
// origin has, since the version is counted from them. The version
// is the latest vX.Y.Z tag SHA descends from with its minor number raised,
// or its major number raised when any commit since carries a
// Breaking-change trailer in its trailer block. A repository with no
// release yet starts at v1.0.0. The notes list each Breaking-change
// trailer's text, then the subject of every commit since that tag.
//
// With -dry-run it prints the version, a blank line and the notes, and
// changes nothing. A dry run of a commit that is not origin's main says so
// on stderr, and still shows what its release would be.
//
// Otherwise it runs
//
//	gh release create VERSION --target SHA --title VERSION --notes-file -
//
// with the notes on stdin, so gh needs a token that can write the
// repository's contents, in GH_TOKEN, and the repository, in GH_REPO or
// as the clone's origin. It does nothing when a release tag already points
// at SHA, and refuses unless SHA is origin's main, since releasing an
// older commit after a newer one would give it the newer version. It
// never moves or deletes a tag.
//
// Exit codes:
//
//	0  released; or a release tag already points at SHA; or the dry run
//	   printed the release
//	1  refused or failed: SHA is not a commit here, or not origin's main;
//	   origin has a release tag the clone has not fetched; the next
//	   version's tag is taken by another commit; or git or gh failed;
//	   stderr says which
//	2  the command line is wrong
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/release"
)

const name = "divbast-release"

// fullSHA is the only form -sha takes: gh's --target and every comparison
// with origin's main need the whole commit SHA.
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], execx.OS{}, execx.OS{}, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, git execx.Runner, gh execx.StdinRunner, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	sha := flags.String("sha", "", "the full `SHA` of the commit on main to release")
	dryRun := flags.Bool("dry-run", false, "print the version and notes, and release nothing")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch {
	case flags.NArg() > 0:
		complain(stderr, "unexpected argument %q", flags.Arg(0))
		flags.Usage()
		return 2
	case *sha == "":
		complain(stderr, "-sha is required")
		flags.Usage()
		return 2
	case !fullSHA.MatchString(*sha):
		complain(stderr, "-sha must be a full 40-character commit SHA, not %q", *sha)
		return 2
	}

	plan, err := release.Prepare(ctx, git, *sha)
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	if plan.Released != "" {
		return say(stdout, stderr, "%s is already released as %s: nothing to do\n", plan.SHA, plan.Released)
	}

	if *dryRun {
		if plan.Tip != plan.SHA {
			complain(stderr, "%s is not the tip of origin's main (%q), so a real run would refuse it", plan.SHA, plan.Tip)
		}
		return say(stdout, stderr, "%s\n\n%s", plan.Version, release.Notes(plan.Commits))
	}

	out, err := release.Create(ctx, gh, &plan)
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	return say(stdout, stderr, "%sreleased %s at %s\n", out, plan.Version, plan.SHA)
}

// say writes to stdout, and returns the exit code: 0, or 1 when the write
// failed.
func say(stdout, stderr io.Writer, format string, args ...any) int {
	if _, err := fmt.Fprintf(stdout, format, args...); err != nil {
		complain(stderr, "write the result: %v", err)
		return 1
	}
	return 0
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
