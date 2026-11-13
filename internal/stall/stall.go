// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package stall finds the ways a repository's updates stop flowing without
// anything failing loudly: a Renovate pull request open too long, one red
// or pending too long, Renovate itself silent, and daily slots that should
// have published main and did not.
//
// Each check reads the time from [time.Now] and the repository through a
// [Source], and says what it found in a [Result].
package stall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/divbast/ci/internal/registry"
)

// Required is the name of the check a Renovate pull request waits on: the
// caller's own required job, the one check main's ruleset requires. A
// called workflow's check runs gain the caller job's name as a prefix, but
// a job of the caller's own keeps its name.
const Required = "required"

// grace is how late a daily slot run may start before its day counts as
// missed: GitHub starts scheduled runs hours late.
const grace = 12 * time.Hour

// Config is what the checks hold a repository to.
type Config struct {
	// OpenDays is how many days a Renovate pull request may stay open.
	OpenDays int
	// StuckHours is how many hours one may stay red, counted from its
	// opening, or pending, counted from its last push.
	StuckHours int
	// RunHours is how many hours Renovate may go without a successful run.
	RunHours int
	// LostSlots is how many lost daily slots make a stall.
	LostSlots int
	// Published is the image the daily slot publishes, such as
	// ghcr.io/divbast/librespeed:latest.
	Published string
	// SlotWorkflow is the workflow file whose scheduled runs on main are
	// the daily slots, such as build.yml.
	SlotWorkflow string
	// RenovateWorkflow is the workflow file that runs Renovate, such as
	// renovate.yml.
	RenovateWorkflow string
	// ContentGated says the slot workflow publishes only when the image's
	// content moved, as divbast-publish-decision's -content-gated does, so
	// that a slot run can succeed and leave an older commit published.
	ContentGated bool
}

// Result is what a check found.
type Result struct {
	// Stalled says the check found updates that stopped flowing.
	Stalled bool
	// Headline says what the check found, or that it found nothing.
	Headline string
	// Details are what it found, one per line: pull requests, runs and
	// days.
	Details []string
}

// PR is an open Renovate pull request.
type PR struct {
	Number int
	Title  string
	// Created is when it was opened.
	Created time.Time
	// Pushed is the committer date of its last commit.
	Pushed time.Time
	// Checks are the check runs and commit statuses on its last commit.
	Checks []Check
}

// Check is a check run or a commit status on a pull request.
type Check struct {
	// Name is a check run's name, or a commit status's context.
	Name string
	// Run is true for a check run, and false for a commit status.
	Run     bool
	Outcome Outcome
}

// Outcome is where a check stands.
type Outcome int

const (
	// Pending is a check still to finish: queued, running, or a commit
	// status expected or pending.
	Pending Outcome = iota + 1
	// Passed is a check that succeeded, or was skipped or neutral.
	Passed
	// Failed is a check that ended any other way: failed, cancelled, timed
	// out, or waiting for someone to act.
	Failed
)

// String returns "pending", "passed" or "failed".
func (o Outcome) String() string {
	switch o {
	case Pending:
		return "pending"
	case Passed:
		return "passed"
	case Failed:
		return "failed"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// Run is a run of the slot workflow.
type Run struct {
	// HeadSHA is the commit it built.
	HeadSHA string
	// Created is when GitHub started it.
	Created time.Time
	// Completed says it has finished, however it ended.
	Completed bool
	// Conclusion is how it ended, as GitHub puts it, such as "success",
	// "failure" or "cancelled", and "" until it has finished.
	Conclusion string
	URL        string
}

// Source answers what the checks ask about a repository.
type Source interface {
	// RenovatePRs returns Renovate's open pull requests.
	RenovatePRs(ctx context.Context) ([]PR, error)
	// LastSuccess returns when the newest successful run of workflow
	// started, and false if none has succeeded.
	LastSuccess(ctx context.Context, workflow string) (time.Time, bool, error)
	// SlotRuns returns the newest scheduled runs of workflow on main,
	// newest first.
	SlotRuns(ctx context.Context, workflow string) ([]Run, error)
	// MainSHA returns the commit main is at.
	MainSHA(ctx context.Context) (string, error)
	// Compare returns how head stands against base, as GitHub's compare
	// API puts it ("ahead", "behind", "identical" or "diverged"), and the
	// committer date of the first commit on head's line after base, or the
	// zero time if there is none.
	Compare(ctx context.Context, base, head string) (status string, firstCommit time.Time, err error)
	// RepoCreated returns when the repository was created.
	RepoCreated(ctx context.Context) (time.Time, error)
	// WorkflowCreated returns when the workflow in file, such as
	// build.yml, was created.
	WorkflowCreated(ctx context.Context, file string) (time.Time, error)
}

// Revisions reads the commit a published image was built from, as
// [registry.Lookup] does.
type Revisions interface {
	Revision(ctx context.Context, image string) (string, registry.State, error)
}

// Open finds Renovate pull requests open more than c.OpenDays days: an
// update that never goes green.
func Open(ctx context.Context, s Source, c *Config) (Result, error) {
	prs, err := s.RenovatePRs(ctx)
	if err != nil {
		return Result{}, err
	}
	limit := days(c.OpenDays)
	var old []string
	for _, pr := range prs {
		if time.Since(pr.Created) > limit {
			old = append(old, pr.line())
		}
	}
	if len(old) > 0 {
		return Result{Stalled: true, Headline: fmt.Sprintf("Open more than %d days:", c.OpenDays), Details: old}, nil
	}
	return Result{Headline: fmt.Sprintf("no Renovate pull request open more than %d days", c.OpenDays)}, nil
}

// Stuck finds Renovate pull requests red for more than c.StuckHours hours
// since they opened, or pending for more than that since their last push.
//
// Red counts from the opening, because every rebase re-runs CI and would
// otherwise reset the clock. A check still running, or CI that never
// started, counts from the last push: no [Required] check run at all
// counts as pending. Renovate waits on all of these for ever.
func Stuck(ctx context.Context, s Source, c *Config) (Result, error) {
	prs, err := s.RenovatePRs(ctx)
	if err != nil {
		return Result{}, err
	}
	limit := hours(c.StuckHours)
	var stuck []string
	for _, pr := range prs {
		red := time.Since(pr.Created) > limit && pr.has(Failed)
		pending := time.Since(pr.Pushed) > limit && (pr.has(Pending) || !pr.hasRequired())
		if red || pending {
			stuck = append(stuck, pr.line())
		}
	}
	if len(stuck) > 0 {
		return Result{Stalled: true, Headline: fmt.Sprintf("Not green for more than %d hours:", c.StuckHours), Details: stuck}, nil
	}
	return Result{Headline: fmt.Sprintf("no Renovate pull request red or pending more than %d hours", c.StuckHours)}, nil
}

// Renovate finds Renovate without a successful run in c.RunHours hours. A
// run whose job its `if` skipped ends as skipped, not success, so the
// App's own dashboard edits do not count. A repository younger than that
// has had no time to run Renovate yet, and is let off.
func Renovate(ctx context.Context, s Source, c *Config) (Result, error) {
	limit := hours(c.RunHours)
	silent := fmt.Sprintf("Renovate silent for more than %d hours:", c.RunHours)

	last, ok, err := s.LastSuccess(ctx, c.RenovateWorkflow)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		var created time.Time
		if created, err = s.RepoCreated(ctx); err != nil {
			return Result{}, err
		}
		if time.Since(created) <= limit {
			return Result{Headline: fmt.Sprintf("no successful Renovate run yet, in a repository created less than %d hours ago", c.RunHours)}, nil
		}
		return Result{Stalled: true, Headline: silent, Details: []string{"no successful Renovate run"}}, nil
	}
	if time.Since(last) > limit {
		return Result{Stalled: true, Headline: silent, Details: []string{"last successful Renovate run " + timestamp(last)}}, nil
	}
	return Result{Headline: fmt.Sprintf("Renovate succeeded within %d hours", c.RunHours)}, nil
}

// Slots finds daily slots that should have published main and did not,
// while c.Published names an older commit, or nothing.
//
// A finished slot run that built a commit ahead of the published one would
// have published it, so each such run is a lost slot, whether it failed,
// was cancelled or skipped; with nothing published, every finished run is.
// Content-gated, a run that succeeded is never lost: it published, or
// decided that nothing in the image had moved. One that failed, was
// cancelled or ended any other way is lost all the same.
//
// So is each day with no slot run at all, after 12 hours' grace, since
// GitHub starts them hours late. Those days count from the newest slot
// run, finished or not, or from when main stopped being what is
// published, whichever is later. With nothing published, main stopped
// being published when the slot workflow could first have run: the later
// of the repository's creation and the slot workflow's. One lost slot, an
// upstream outage say, already emails on its own as a red run.
//
// A private c.Published is a stall: no user can pull it. Any other
// failure to read it is an error.
func Slots(ctx context.Context, s Source, r Revisions, c *Config) (Result, error) {
	if c.Published == "" {
		return Result{}, errors.New("no published image to check the daily slots against")
	}
	revision, state, err := r.Revision(ctx, c.Published)
	if errors.Is(err, registry.ErrPrivate) {
		return Result{Stalled: true, Headline: c.Published + " is private, so no one can pull it:", Details: []string{err.Error()}}, nil
	}
	if err != nil {
		return Result{}, err
	}
	head, err := s.MainSHA(ctx)
	if err != nil {
		return Result{}, err
	}
	if state == registry.Published && revision == head {
		return Result{Headline: "main " + head + " is published"}, nil
	}

	runs, err := s.SlotRuns(ctx, c.SlotWorkflow)
	if err != nil {
		return Result{}, err
	}
	// When main stopped being what is published, and how it stands
	// against what is.
	var since time.Time
	standing := "ahead"
	if state == registry.Absent {
		since, err = firstSlot(ctx, s, c.SlotWorkflow)
	} else {
		standing, since, err = s.Compare(ctx, revision, head)
	}
	if err != nil {
		return Result{}, err
	}

	var details []string
	for i := range runs {
		run := &runs[i]
		if !run.Completed {
			continue
		}
		var lost bool
		if lost, err = isLost(ctx, s, c, run, state, revision, since); err != nil {
			return Result{}, err
		}
		if lost {
			details = append(details, "lost slot: "+run.URL+" built "+run.HeadSHA)
		}
	}
	lost := len(details)

	anchor := since
	if len(runs) > 0 && runs[0].Created.After(anchor) {
		anchor = runs[0].Created
	}
	// With no slot run ever, and nothing to say when main moved past the
	// published commit, as many days as make a stall.
	missed := c.LostSlots
	if !anchor.IsZero() {
		missed = max(0, int((time.Since(anchor)-grace)/(24*time.Hour)))
	}
	if missed > 0 {
		details = append(details, fmt.Sprintf("%d day(s) with no slot run since %s", missed, timestampOr(anchor, "ever")))
	}

	tag := tagOf(c.Published)
	shown := revision
	if state == registry.Absent {
		shown = "absent"
	}
	if lost+missed >= c.LostSlots {
		return Result{
			Stalled:  true,
			Headline: fmt.Sprintf("main %s is unpublished, %s is %s, and %d or more slots were lost:", head, tag, shown, c.LostSlots),
			Details:  details,
		}, nil
	}
	if state == registry.Absent {
		shown = "(absent)"
	}
	return Result{Headline: fmt.Sprintf("main %s %s %s %s, with %d lost slot(s), under %d", head, against(standing), tag, shown, lost+missed, c.LostSlots)}, nil
}

// firstSlot returns when the slot workflow could first have run: the later
// of the repository's creation and the workflow's, since a repository can
// be created long before its slot workflow lands, and no slot can run
// before either.
func firstSlot(ctx context.Context, s Source, workflow string) (time.Time, error) {
	repo, err := s.RepoCreated(ctx)
	if err != nil {
		return time.Time{}, err
	}
	created, err := s.WorkflowCreated(ctx, workflow)
	if err != nil {
		return time.Time{}, err
	}
	if created.After(repo) {
		return created, nil
	}
	return repo, nil
}

// against says how main stands against the published commit, from
// GitHub's compare status of main against it.
func against(status string) string {
	switch status {
	case "behind":
		return "is behind"
	case "diverged":
		return "has diverged from"
	case "identical":
		return "is identical to"
	default:
		return "is ahead of"
	}
}

// isLost says whether a finished slot run should have published and did
// not. Content-gated, a run that succeeded never is. Otherwise, with
// nothing published, any run since the slot could first run is; with a
// commit published, a run that built a commit ahead of it.
func isLost(ctx context.Context, s Source, c *Config, run *Run, state registry.State, revision string, since time.Time) (bool, error) {
	if c.ContentGated && run.Conclusion == "success" {
		return false, nil
	}
	if state == registry.Absent {
		return run.Created.After(since), nil
	}
	status, _, err := s.Compare(ctx, revision, run.HeadSHA)
	if err != nil {
		return false, fmt.Errorf("compare the slot run %s, which built %s, with %s: %w", run.URL, run.HeadSHA, revision, err)
	}
	return status == "ahead", nil
}

// line is how a pull request is listed: its number and title.
func (pr *PR) line() string {
	return fmt.Sprintf("#%d %s", pr.Number, pr.Title)
}

// has says whether any of the pull request's checks stands at o.
func (pr *PR) has(o Outcome) bool {
	return slices.ContainsFunc(pr.Checks, func(c Check) bool { return c.Outcome == o })
}

// hasRequired says whether the pull request has a [Required] check run.
func (pr *PR) hasRequired() bool {
	return slices.ContainsFunc(pr.Checks, func(c Check) bool { return c.Run && c.Name == Required })
}

// tagOf returns image's tag with its colon, such as ":latest", or the
// whole reference if it has none.
func tagOf(image string) string {
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[i:]
	}
	return image
}

func hours(n int) time.Duration { return time.Duration(n) * time.Hour }

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// timestamp writes t as GitHub does, in UTC.
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// timestampOr is timestamp, or none for the zero time.
func timestampOr(t time.Time, none string) string {
	if t.IsZero() {
		return none
	}
	return timestamp(t)
}
