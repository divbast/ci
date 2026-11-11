// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-publish-decision decides whether a run publishes the
// image it built, and never lets it move the published image backwards.
//
// Usage:
//
//	divbast-publish-decision -event EVENT -built SHA -published SHA [-content-change TEXT]
//
// EVENT is the run's github.event_name: push, schedule and
// workflow_dispatch may publish, and any other event is refused. -built
// is the commit the run built. -published is the commit the published
// image was built from, as divbast-published-revision prints it, and is
// empty when nothing is published yet; it must be given all the same, so
// a caller that forgets it cannot pass for a first publish.
// -content-change says what moved in the image with no commit to show for
// it, such as a library built from its branch's head.
//
// It runs in a clone of the repository with origin/main fetched, and
// prints its decision as "publish: why" or "skip: why". When GitHub
// Actions sets them, it also appends publish=true or publish=false to
// $GITHUB_OUTPUT and the decision to $GITHUB_STEP_SUMMARY. A refusal goes
// to the summary too, as "fail: why", so a red run says why in the same
// place.
//
// Exit codes:
//
//	0  decided, to publish or to skip
//	1  refused: an event that does not publish, a published commit that
//	   is not on main, a built commit that has diverged from it, or git
//	   unable to answer; or the decision could not be written
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
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/publish"
)

const name = "divbast-publish-decision"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], publish.ExecGit(execx.OS{}), os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, git publish.Git, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	event := flags.String("event", "", "the `EVENT` that started the run: push, schedule or workflow_dispatch")
	built := flags.String("built", "", "the `SHA` of the commit the run built")
	published := flags.String("published", "", "the `SHA` the published image was built from, empty if none")
	contentChange := flags.String("content-change", "", "what moved in the image's content with no new commit, if anything")
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
	given := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, required := range []string{"event", "built", "published"} {
		if !given[required] {
			complain(stderr, "-%s is required", required)
			flags.Usage()
			return 2
		}
	}

	decision, err := publish.Decide(ctx, git, publish.Event(*event), *built, *published, *contentChange)
	if err != nil {
		complain(stderr, "%v", err)
		if werr := appendTo(getenv("GITHUB_STEP_SUMMARY"), "fail: "+err.Error()); werr != nil {
			complain(stderr, "write the run summary: %v", werr)
		}
		return 1
	}

	if _, err = fmt.Fprintln(stdout, decision); err != nil {
		complain(stderr, "write the decision: %v", err)
		return 1
	}
	if err = appendTo(getenv("GITHUB_OUTPUT"), "publish="+strconv.FormatBool(decision.Publish)); err != nil {
		complain(stderr, "write the step output: %v", err)
		return 1
	}
	if err = appendTo(getenv("GITHUB_STEP_SUMMARY"), decision.String()); err != nil {
		complain(stderr, "write the run summary: %v", err)
		return 1
	}
	return 0
}

// appendTo appends line to the file at path, one of the files GitHub
// Actions names in the environment, and does nothing when path is empty.
// It opens the file inside its directory as an [os.Root], so that it
// writes that file and nothing a symlink would lead out of the directory.
func appendTo(path, line string) (err error) {
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
	_, err = fmt.Fprintln(f, line)
	return err
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
