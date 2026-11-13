// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-stall fails when a repository's updates have stopped
// flowing without anything failing loudly, so that a scheduled run goes
// red and GitHub emails someone.
//
// Usage:
//
//	divbast-stall open|stuck|renovate|slots
//	divbast-stall slots -content-gated
//
// The checks:
//
//	open      a Renovate pull request open more than OPEN_DAYS days
//	stuck     one red for more than STUCK_HOURS hours since it opened, or
//	          pending for more than that since its last push, which
//	          includes having no check run named "required" at all
//	renovate  no successful run of RENOVATE_WORKFLOW in RUN_HOURS hours,
//	          once the repository is older than that
//	slots     LOST_SLOTS or more daily slots, the scheduled runs of
//	          SLOT_WORKFLOW on main, that should have published main as
//	          PUBLISHED and did not; or PUBLISHED private
//
// slots -content-gated is for a slot workflow that publishes only when the
// image's content moved, as divbast-publish-decision -content-gated does:
// once the image is published, a slot run that succeeded is never lost,
// since it may have decided that nothing in the image had moved. With
// nothing published, every slot run publishes, so one that succeeded and
// left nothing published is lost all the same.
//
// It reads the repository's pull requests, runs and commits through gh,
// and PUBLISHED as an anonymous client through skopeo. The environment:
//
//	GH_REPO            the repository, as owner/name; always required
//	GH_TOKEN           gh's token: in a workflow, one that can read pull
//	                   requests, actions, checks, statuses and packages
//	OPEN_DAYS          open's limit, a whole number
//	STUCK_HOURS        stuck's limit
//	RUN_HOURS          renovate's limit
//	LOST_SLOTS         slots' limit
//	PUBLISHED          the image the slot publishes, such as
//	                   ghcr.io/divbast/librespeed:latest
//	SLOT_WORKFLOW      the slot's workflow file, build.yml if unset
//	SLOT_JOB           for slots -content-gated alone: the job in each slot
//	                   run that publishes PUBLISHED, as GitHub names it in
//	                   the run, whose conclusion counts rather than the
//	                   whole run's; unset, the run's
//	RENOVATE_WORKFLOW  Renovate's workflow file, renovate.yml if unset
//
// Each check reads only its own limit. It prints what it found on stdout:
// one line when nothing is stalled, or a headline and then what stalled,
// one per line.
//
// Exit codes:
//
//	0  nothing stalled
//	1  stalled
//	2  the command line or the environment is wrong, or GitHub or the
//	   registry could not say; stderr says which
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
	"github.com/divbast/ci/internal/registry"
	"github.com/divbast/ci/internal/stall"
)

const name = "divbast-stall"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, execx.OS{}, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, getenv func(string) string, r execx.Runner, stdout, stderr io.Writer) int {
	usage := func() {
		// As for complain: nowhere better to report a failed write.
		_, _ = fmt.Fprintf(stderr, "usage: %s open|stuck|renovate|slots\n       %s slots -content-gated\n", name, name)
	}
	// The check comes first, and its own flags after it.
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = usage
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() == 0 {
		complain(stderr, "want one check, not 0 arguments")
		usage()
		return 2
	}
	check := flags.Arg(0)
	checkFlags := flag.NewFlagSet(name+" "+check, flag.ContinueOnError)
	checkFlags.SetOutput(stderr)
	// The usage, then the check's own flags, which only slots has.
	checkFlags.Usage = func() {
		usage()
		checkFlags.PrintDefaults()
	}
	var gated *bool
	if check == "slots" {
		gated = checkFlags.Bool("content-gated", false, "once the image is published, never count a slot run that succeeded as lost")
	}
	if err := checkFlags.Parse(flags.Args()[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if checkFlags.NArg() > 0 {
		complain(stderr, "want one check, not %d arguments", 1+checkFlags.NArg())
		usage()
		return 2
	}

	env := environment{getenv: getenv}
	repo := env.required("GH_REPO")
	src := stall.GH{Run: r, Repo: repo}
	var c stall.Config
	var do func() (stall.Result, error)
	switch check {
	case "open":
		c.OpenDays = env.count("OPEN_DAYS")
		do = func() (stall.Result, error) { return stall.Open(ctx, src, &c) }
	case "stuck":
		c.StuckHours = env.count("STUCK_HOURS")
		do = func() (stall.Result, error) { return stall.Stuck(ctx, src, &c) }
	case "renovate":
		c.RunHours = env.count("RUN_HOURS")
		c.RenovateWorkflow = env.or("RENOVATE_WORKFLOW", "renovate.yml")
		do = func() (stall.Result, error) { return stall.Renovate(ctx, src, &c) }
	case "slots":
		c.LostSlots = env.count("LOST_SLOTS")
		c.Published = env.required("PUBLISHED")
		c.SlotWorkflow = env.or("SLOT_WORKFLOW", "build.yml")
		c.ContentGated = *gated
		c.SlotJob = env.or("SLOT_JOB", "")
		if c.SlotJob != "" && !c.ContentGated {
			env.err = errors.Join(env.err, errors.New("SLOT_JOB is set, but only slots -content-gated reads a slot run's conclusion"))
		}
		lookup := registry.Lookup{Run: r, GH: ghapi.Client{Run: r}}
		do = func() (stall.Result, error) { return stall.Slots(ctx, src, lookup, &c) }
	default:
		complain(stderr, "no such check: %q", check)
		usage()
		return 2
	}
	if env.err != nil {
		complain(stderr, "%v", env.err)
		return 2
	}

	res, err := do()
	if err != nil {
		complain(stderr, "%v", err)
		return 2
	}
	if err = report(stdout, res); err != nil {
		complain(stderr, "write what %s found: %v", check, err)
		return 2
	}
	if res.Stalled {
		return 1
	}
	return 0
}

// report writes res's headline, then each detail indented below it.
func report(w io.Writer, res stall.Result) error {
	if _, err := fmt.Fprintln(w, res.Headline); err != nil {
		return err
	}
	for _, d := range res.Details {
		if _, err := fmt.Fprintln(w, " ", d); err != nil {
			return err
		}
	}
	return nil
}

// environment reads variables, and keeps every problem it finds.
type environment struct {
	getenv func(string) string
	err    error
}

// required returns the variable key, which must be set.
func (e *environment) required(key string) string {
	v := e.getenv(key)
	if v == "" {
		e.err = errors.Join(e.err, fmt.Errorf("%s is not set", key))
	}
	return v
}

// count returns the variable key, which must be a whole number.
func (e *environment) count(key string) int {
	v := e.required(key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		e.err = errors.Join(e.err, fmt.Errorf("%s is %q, not a whole number", key, v))
	}
	return n
}

// or returns the variable key, or def if it is not set.
func (e *environment) or(key, def string) string {
	if v := e.getenv(key); v != "" {
		return v
	}
	return def
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
