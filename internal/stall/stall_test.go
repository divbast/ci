// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/registry"
	"github.com/divbast/ci/internal/stall"
)

// epoch is where a synctest bubble's clock starts, so every check below
// runs at this instant and every time in a table is written against it.
var epoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// ago is the time d before epoch.
func ago(d time.Duration) time.Time { return epoch.Add(-d) }

const (
	day   = 24 * time.Hour
	image = "ghcr.io/divbast/librespeed:latest"
)

// Commits: published is what :latest was built from, head is main, and
// built and older are commits slot runs built, ahead of and behind
// published.
var (
	published = strings.Repeat("1", 40)
	head      = strings.Repeat("2", 40)
	built     = strings.Repeat("3", 40)
	older     = strings.Repeat("4", 40)
)

var config = stall.Config{
	OpenDays:         14,
	StuckHours:       24,
	RunHours:         24,
	LostSlots:        2,
	StarvedDays:      7,
	Published:        image,
	SlotWorkflow:     "build.yml",
	RenovateWorkflow: "renovate.yml",
	StallWorkflow:    "stall.yml",
}

// comparison is what Compare answers for one base...head.
type comparison struct {
	status string
	first  time.Time
}

// source is a [stall.Source] that answers from its fields. Asked anything
// it has no answer for, it returns an error, so a check that asks what it
// should not fails its test.
type source struct {
	prs      []stall.PR
	success  time.Time // the last successful Renovate run; zero for none
	runs     []stall.Run
	main     string
	compares map[string]comparison // keyed by base...head
	created  time.Time
	workflow time.Time // when the slot workflow was created
	// jobs are each run's jobs, by run ID: each job's name and its
	// conclusion. A run with an empty map has no jobs.
	jobs map[int64]map[string]string
	// dashboards are the open Dependency Dashboards.
	dashboards []stall.Issue
	// edits are each dashboard's whole history, by its number, newest
	// first. DashboardHistory cuts it short as GitHub's does.
	edits      map[int][]stall.DashboardEdit
	historyErr error // returned by DashboardHistory when set
	// finished are the runs RunsSince lists, newest first, and attempts
	// each one's jobs, by run ID and attempt; previous is when the stall
	// workflow's run before this one was created, and current when this
	// one was, each zero for none, and workflowIDs are workflows' IDs by
	// file.
	finished          []stall.Run
	attempts          map[int64]map[int][]stall.Job
	previous, current time.Time
	workflowIDs       map[string]int64
	// listedSince is the time RunsSince was asked from, and read is each
	// run and attempt whose jobs were read, as "run/attempt".
	listedSince time.Time
	read        []string
	err         error // returned by every call when set
}

func (s *source) Dashboards(context.Context) ([]stall.Issue, error) {
	return s.dashboards, s.err
}

// DashboardHistory returns the dashboard's edits as [stall.GH] does:
// newest first, down to the newest edit made at or before since, so that a
// check asking from the wrong time reads the wrong edits.
func (s *source) DashboardHistory(_ context.Context, number int, since time.Time) ([]stall.DashboardEdit, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.historyErr != nil {
		return nil, s.historyErr
	}
	edits, ok := s.edits[number]
	if !ok {
		return nil, fmt.Errorf("asked for the history of dashboard #%d, which the test did not script", number)
	}
	for i, e := range edits {
		if !e.EditedAt.After(since) {
			return edits[:i+1], nil
		}
	}
	return edits, nil
}

func (s *source) RenovatePRs(context.Context) ([]stall.PR, error) {
	return s.prs, s.err
}

func (s *source) LastSuccess(_ context.Context, workflow string) (time.Time, bool, error) {
	if s.err != nil {
		return time.Time{}, false, s.err
	}
	if workflow != config.RenovateWorkflow {
		return time.Time{}, false, fmt.Errorf("asked about workflow %q", workflow)
	}
	return s.success, !s.success.IsZero(), nil
}

func (s *source) SlotRuns(_ context.Context, workflow string) ([]stall.Run, error) {
	if s.err != nil {
		return nil, s.err
	}
	if workflow != config.SlotWorkflow {
		return nil, fmt.Errorf("asked about workflow %q", workflow)
	}
	return s.runs, nil
}

func (s *source) Jobs(_ context.Context, run *stall.Run) ([]stall.Job, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.attempts != nil {
		return s.attemptJobs(run.ID, run.Attempt)
	}
	jobs, ok := s.jobs[run.ID]
	if !ok {
		return nil, fmt.Errorf("asked for the jobs of run %d, which the test did not script", run.ID)
	}
	out := make([]stall.Job, 0, len(jobs))
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		out = append(out, stall.Job{Name: name, Conclusion: jobs[name]})
	}
	return out, nil
}

// AttemptJobs returns an earlier attempt's jobs, and fails for the
// latest, which Jobs reads.
func (s *source) AttemptJobs(_ context.Context, run *stall.Run, attempt int) ([]stall.Job, error) {
	if s.err != nil {
		return nil, s.err
	}
	if attempt < 1 || attempt >= run.Attempt {
		return nil, fmt.Errorf("asked for attempt %d of run %d, whose latest is %d", attempt, run.ID, run.Attempt)
	}
	return s.attemptJobs(run.ID, attempt)
}

func (s *source) attemptJobs(id int64, attempt int) ([]stall.Job, error) {
	jobs, ok := s.attempts[id][attempt]
	if !ok {
		return nil, fmt.Errorf("asked for the jobs of run %d, attempt %d, which the test did not script", id, attempt)
	}
	s.read = append(s.read, fmt.Sprintf("%d/%d", id, attempt))
	return jobs, nil
}

// RunsSince returns the runs created at or after since, as [stall.GH]
// does, so that a check asking from the wrong time lists the wrong runs,
// and of those only the runs finished by now, by when they last changed,
// as gh lists only finished runs.
func (s *source) RunsSince(_ context.Context, since time.Time) ([]stall.Run, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.listedSince = since
	var out []stall.Run
	for i := range s.finished {
		if r := &s.finished[i]; !r.Created.Before(since) && !r.Updated.After(time.Now()) {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (s *source) PreviousRunStart(_ context.Context, workflow string) (previous, current time.Time, err error) {
	if s.err != nil {
		return time.Time{}, time.Time{}, s.err
	}
	if workflow != config.StallWorkflow {
		return time.Time{}, time.Time{}, fmt.Errorf("asked about workflow %q", workflow)
	}
	return s.previous, s.current, nil
}

func (s *source) WorkflowID(_ context.Context, file string) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	id, ok := s.workflowIDs[file]
	if !ok {
		return 0, fmt.Errorf("no workflow file %s", file)
	}
	return id, nil
}

func (s *source) MainSHA(context.Context) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.main == "" {
		return "", errors.New("asked for main, which the test did not script")
	}
	return s.main, nil
}

func (s *source) Compare(_ context.Context, base, head string) (string, time.Time, error) {
	if s.err != nil {
		return "", time.Time{}, s.err
	}
	c, ok := s.compares[base+"..."+head]
	if !ok {
		return "", time.Time{}, fmt.Errorf("asked to compare %s...%s, which the test did not script", base, head)
	}
	return c.status, c.first, nil
}

func (s *source) RepoCreated(context.Context) (time.Time, error) {
	if s.err != nil {
		return time.Time{}, s.err
	}
	if s.created.IsZero() {
		return time.Time{}, errors.New("asked when the repository was created, which the test did not script")
	}
	return s.created, nil
}

func (s *source) WorkflowCreated(_ context.Context, file string) (time.Time, error) {
	if s.err != nil {
		return time.Time{}, s.err
	}
	if file != config.SlotWorkflow {
		return time.Time{}, fmt.Errorf("asked when workflow %q was created", file)
	}
	if s.workflow.IsZero() {
		return time.Time{}, errors.New("asked when the slot workflow was created, which the test did not script")
	}
	return s.workflow, nil
}

// revisions is a [stall.Revisions] that answers for image alone.
type revisions struct {
	revision string
	state    registry.State
	err      error
}

func (r revisions) Revision(_ context.Context, img string) (string, registry.State, error) {
	if img != image {
		return "", 0, fmt.Errorf("asked about %s", img)
	}
	return r.revision, r.state, r.err
}

// atEpoch fails t unless the clock reads epoch, as it does at the start of
// a synctest bubble.
func atEpoch(t *testing.T) {
	t.Helper()
	if now := time.Now(); !now.Equal(epoch) {
		t.Fatalf("the clock reads %v, not %v", now, epoch)
	}
}

// checkResult fails t unless got is want.
func checkResult(t *testing.T, got, want stall.Result) {
	t.Helper()
	if got.Stalled != want.Stalled {
		t.Errorf("Stalled = %t, want %t", got.Stalled, want.Stalled)
	}
	if got.Headline != want.Headline {
		t.Errorf("Headline = %q\nwant       %q", got.Headline, want.Headline)
	}
	if !slices.Equal(got.Details, want.Details) {
		t.Errorf("Details = %q\nwant      %q", got.Details, want.Details)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		prs  []stall.PR
		want stall.Result
	}{
		{
			name: "old",
			prs: []stall.PR{
				{Number: 13, Title: "ci: update young", Created: ago(day)},
				{Number: 12, Title: "ci: update old", Created: ago(15 * day)},
			},
			want: stall.Result{
				Stalled:  true,
				Headline: "Open more than 14 days:",
				Details:  []string{"#12 ci: update old"},
			},
		},
		{
			name: "young",
			prs:  []stall.PR{{Number: 12, Title: "ci: update young", Created: ago(13 * day)}},
			want: stall.Result{Headline: "no Renovate pull request open more than 14 days"},
		},
		{
			// More than the limit, as the shell has it: exactly 14 days is
			// not yet too long.
			name: "exactly-the-limit",
			prs:  []stall.PR{{Number: 12, Title: "ci: update", Created: ago(14 * day)}},
			want: stall.Result{Headline: "no Renovate pull request open more than 14 days"},
		},
		{
			name: "none",
			want: stall.Result{Headline: "no Renovate pull request open more than 14 days"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				got, err := stall.Open(t.Context(), &source{prs: tt.prs}, &config)
				if err != nil {
					t.Fatal(err)
				}
				checkResult(t, got, tt.want)
			})
		})
	}
}

func TestStuck(t *testing.T) {
	t.Parallel()

	// The literal name, not stall.Required: callers name their job this.
	required := stall.Check{Name: "required", Run: true, Outcome: stall.Passed}
	lint := stall.Check{Name: "lint / lint", Run: true, Outcome: stall.Passed}
	failed := stall.Check{Name: "test / test (amd64, docker)", Run: true, Outcome: stall.Failed}
	pending := stall.Check{Name: "test / test (arm64, podman)", Run: true, Outcome: stall.Pending}
	stuck := []string{"#7 ci: update stuck"}
	const fine = "no Renovate pull request red or pending more than 24 hours"
	const notGreen = "Not green for more than 24 hours:"

	tests := []struct {
		name    string
		created time.Time
		pushed  time.Time
		checks  []stall.Check
		want    stall.Result
	}{
		{
			// CI never started, or started without the caller's required
			// job: Renovate waits on that for ever.
			name:    "no-required-check",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			checks:  []stall.Check{lint},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			// The check the shell looked for, before called workflows
			// prefixed every check run but the caller's own jobs.
			name:    "lint-is-not-required",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			checks:  []stall.Check{{Name: "lint", Run: true, Outcome: stall.Passed}},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			name:    "no-checks-at-all",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			// Red counts from the opening, since every rebase re-runs CI
			// and would otherwise reset the clock.
			name:    "failed",
			created: ago(30 * time.Hour),
			pushed:  ago(time.Hour),
			checks:  []stall.Check{required, lint, failed},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			name:    "failed-status",
			created: ago(30 * time.Hour),
			pushed:  ago(time.Hour),
			checks:  []stall.Check{required, {Name: "ci/external", Outcome: stall.Failed}},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			name:    "failed-young",
			created: ago(23 * time.Hour),
			pushed:  ago(23 * time.Hour),
			checks:  []stall.Check{required, failed},
			want:    stall.Result{Headline: fine},
		},
		{
			name:    "green",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			checks:  []stall.Check{lint, required},
			want:    stall.Result{Headline: fine},
		},
		{
			// Pending counts from the last push.
			name:    "pending-since-push",
			created: ago(3 * day),
			pushed:  ago(25 * time.Hour),
			checks:  []stall.Check{required, pending},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			// A rebase an hour ago re-ran CI, still running: not stuck,
			// however long ago the pull request opened.
			name:    "pending-after-rebase",
			created: ago(3 * day),
			pushed:  ago(time.Hour),
			checks:  []stall.Check{required, pending},
			want:    stall.Result{Headline: fine},
		},
		{
			name:    "no-required-check-after-rebase",
			created: ago(3 * day),
			pushed:  ago(time.Hour),
			checks:  []stall.Check{lint},
			want:    stall.Result{Headline: fine},
		},
		{
			name:    "pending-status",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			checks:  []stall.Check{required, {Name: "ci/external", Outcome: stall.Pending}},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			// A commit status by that name is not the caller's job.
			name:    "required-as-a-status",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			checks:  []stall.Check{lint, {Name: "required", Outcome: stall.Passed}},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
		{
			// Check runs of a called workflow gain the caller job's
			// prefix; only the caller's own job keeps the bare name.
			name:    "prefixed-required",
			created: ago(30 * time.Hour),
			pushed:  ago(30 * time.Hour),
			checks:  []stall.Check{{Name: "check / required", Run: true, Outcome: stall.Passed}},
			want:    stall.Result{Stalled: true, Headline: notGreen, Details: stuck},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				prs := []stall.PR{
					{Number: 8, Title: "ci: update fine", Created: ago(3 * day), Pushed: ago(time.Hour), Checks: []stall.Check{required}},
					{Number: 7, Title: "ci: update stuck", Created: tt.created, Pushed: tt.pushed, Checks: tt.checks},
				}
				got, err := stall.Stuck(t.Context(), &source{prs: prs}, &config)
				if err != nil {
					t.Fatal(err)
				}
				checkResult(t, got, tt.want)
			})
		})
	}
}

func TestRenovate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		src     source
		want    stall.Result
		wantErr bool
	}{
		{
			// A repository's first day: Renovate has not run yet.
			name: "first-day",
			src:  source{created: ago(2 * time.Hour)},
			want: stall.Result{Headline: "no successful Renovate run yet, in a repository created less than 24 hours ago"},
		},
		{
			name: "silent",
			src:  source{created: ago(3 * day)},
			want: stall.Result{
				Stalled:  true,
				Headline: "Renovate silent for more than 24 hours:",
				Details:  []string{"no successful Renovate run"},
			},
		},
		{
			name: "exactly-a-day-old",
			src:  source{created: ago(day)},
			want: stall.Result{Headline: "no successful Renovate run yet, in a repository created less than 24 hours ago"},
		},
		{
			// When Renovate has succeeded, the repository's age is not
			// asked: source has no creation time to give.
			name: "recent",
			src:  source{success: ago(time.Hour)},
			want: stall.Result{Headline: "Renovate succeeded within 24 hours"},
		},
		{
			name: "stale",
			src:  source{success: ago(25 * time.Hour)},
			want: stall.Result{
				Stalled:  true,
				Headline: "Renovate silent for more than 24 hours:",
				Details:  []string{"last successful Renovate run 1999-12-30T23:00:00Z"},
			},
		},
		{
			name:    "error",
			src:     source{err: errors.New("gh broke")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				got, err := stall.Renovate(t.Context(), &tt.src, &config)
				if tt.wantErr {
					if err == nil {
						t.Fatalf("Renovate() = %+v, want an error", got)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				checkResult(t, got, tt.want)
			})
		})
	}
}

func TestSlots(t *testing.T) {
	t.Parallel()

	errRegistry := errors.New("could not read " + image)
	const url1 = "https://github.com/divbast/librespeed-oci-image/actions/runs/1"
	const url2 = "https://github.com/divbast/librespeed-oci-image/actions/runs/2"
	const url3 = "https://github.com/divbast/librespeed-oci-image/actions/runs/3"
	ahead := comparison{status: "ahead"}
	lost := func(url, sha string) string { return "lost slot: " + url + " built " + sha }
	unpublished := "main " + head + " is unpublished, :latest is " + published + ", and 2 or more slots were lost:"

	tests := []struct {
		name string
		src  source
		revs revisions
		// gated is the check's content-gated, and job the slot job it
		// reads.
		gated   bool
		job     string
		want    stall.Result
		wantErr error
	}{
		{
			// Nothing published, no slot run yet, in a repository three
			// hours old.
			name: "first-day",
			src:  source{main: head, created: ago(3 * time.Hour), workflow: ago(3 * time.Hour)},
			revs: revisions{state: registry.Absent},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest (absent), with 0 lost slot(s), under 2"},
		},
		{
			// Nothing published three days after the repository was
			// created, and no slot run since.
			name: "absent-days",
			src:  source{main: head, created: ago(3 * day), workflow: ago(3 * day)},
			revs: revisions{state: registry.Absent},
			want: stall.Result{
				Stalled:  true,
				Headline: "main " + head + " is unpublished, :latest is absent, and 2 or more slots were lost:",
				Details:  []string{"2 day(s) with no slot run since 1999-12-29T00:00:00Z"},
			},
		},
		{
			// With nothing published, every finished slot run should have
			// published, so each is lost. One is under the limit.
			name: "absent-one-lost",
			src: source{
				main:     head,
				created:  ago(2 * day),
				workflow: ago(2 * day),
				runs:     []stall.Run{{HeadSHA: built, Created: ago(20 * time.Hour), Completed: true, URL: url1}},
			},
			revs: revisions{state: registry.Absent},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest (absent), with 1 lost slot(s), under 2"},
		},
		{
			name: "absent-two-lost",
			src: source{
				main:     head,
				created:  ago(3 * day),
				workflow: ago(3 * day),
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, URL: url2},
					{HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, URL: url1},
				},
			},
			revs: revisions{state: registry.Absent},
			want: stall.Result{
				Stalled:  true,
				Headline: "main " + head + " is unpublished, :latest is absent, and 2 or more slots were lost:",
				Details:  []string{lost(url2, head), lost(url1, built)},
			},
		},
		{
			// Published by hand, then a merge two hours ago, before any
			// slot has run: no slot has been lost yet.
			name: "merge-before-first-slot",
			src: source{
				main:     head,
				compares: map[string]comparison{published + "..." + head: {status: "ahead", first: ago(2 * time.Hour)}},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			name: "two-lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, URL: url2},
					{HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, URL: url1},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Stalled: true, Headline: unpublished, Details: []string{lost(url2, head), lost(url1, built)}},
		},
		{
			// A run still going is not lost, nor one that built a commit
			// at or behind the published one. The newest run, finished or
			// not, still counts as a slot run for the days missed.
			name: "not-lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(time.Hour), URL: url2},
					{HeadSHA: older, Created: ago(25 * time.Hour), Completed: true, URL: url1},
					{HeadSHA: published, Created: ago(49 * time.Hour), Completed: true, URL: url1},
				},
				compares: map[string]comparison{
					published + "..." + head:      {status: "ahead", first: ago(5 * day)},
					published + "..." + older:     {status: "behind"},
					published + "..." + published: {status: "identical"},
				},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			// The newest slot run was three and a half days ago, and main
			// moved past :latest before it.
			name: "missed-days",
			src: source{
				main: head,
				runs: []stall.Run{{HeadSHA: published, Created: ago(84 * time.Hour), Completed: true, URL: url1}},
				compares: map[string]comparison{
					published + "..." + head:      {status: "ahead", first: ago(5 * day)},
					published + "..." + published: {status: "identical"},
				},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{
				Stalled:  true,
				Headline: unpublished,
				Details:  []string{"3 day(s) with no slot run since 1999-12-28T12:00:00Z"},
			},
		},
		{
			// Days with no slot run count only from when main moved past
			// :latest.
			name: "missed-days-since-the-merge",
			src: source{
				main: head,
				runs: []stall.Run{{HeadSHA: published, Created: ago(84 * time.Hour), Completed: true, URL: url1}},
				compares: map[string]comparison{
					published + "..." + head:      {status: "ahead", first: ago(36 * time.Hour)},
					published + "..." + published: {status: "identical"},
				},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 1 lost slot(s), under 2"},
		},
		{
			name: "lost-and-missed",
			src: source{
				main: head,
				runs: []stall.Run{{HeadSHA: built, Created: ago(2 * day), Completed: true, URL: url1}},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{
				Stalled:  true,
				Headline: unpublished,
				Details:  []string{lost(url1, built), "1 day(s) with no slot run since 1999-12-30T00:00:00Z"},
			},
		},
		{
			// With nothing published, the days with no slot run count from
			// the newest slot run, even one still going, when it is later
			// than the slot workflow's first chance to run. It is not lost,
			// since it has not finished.
			name: "absent-running-newest",
			src: source{
				main:     head,
				created:  ago(3 * day),
				workflow: ago(3 * day),
				runs:     []stall.Run{{HeadSHA: head, Created: ago(time.Hour), URL: url1}},
			},
			revs: revisions{state: registry.Absent},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest (absent), with 0 lost slot(s), under 2"},
		},
		{
			// The slot workflow landed three days after the repository was
			// created, a day and a half ago: one day without a slot run,
			// counted from the workflow, not three from the repository.
			name: "absent-workflow-later",
			src:  source{main: head, created: ago(108 * time.Hour), workflow: ago(36 * time.Hour)},
			revs: revisions{state: registry.Absent},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest (absent), with 1 lost slot(s), under 2"},
		},
		{
			// And were GitHub to date the workflow before the repository,
			// the days would still count from the repository.
			name: "absent-repo-later",
			src:  source{main: head, created: ago(36 * time.Hour), workflow: ago(108 * time.Hour)},
			revs: revisions{state: registry.Absent},
			want: stall.Result{Headline: "main " + head + " is ahead of :latest (absent), with 1 lost slot(s), under 2"},
		},
		{
			// Content-gated, a slot run that succeeded worked, whether it
			// published or decided that nothing in the image had moved.
			name: "gated_success_not_lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "success", URL: url2},
					{HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "success", URL: url1},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			want:  stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			// The same runs, not content-gated, are lost, as they always
			// were: a run ahead of :latest that succeeded and left it
			// there did not publish.
			name: "ungated_success_lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "success", URL: url2},
					{HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "success", URL: url1},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Stalled: true, Headline: unpublished, Details: []string{lost(url2, head), lost(url1, built)}},
		},
		{
			// Content-gated, a run that failed, was cancelled or ended any
			// other way but success is lost as ever.
			name: "gated_failure_lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "failure", URL: url3},
					{HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "cancelled", URL: url2},
					{HeadSHA: built, Created: ago(68 * time.Hour), Completed: true, Conclusion: "timed_out", URL: url1},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(4 * day)},
					published + "..." + built: ahead,
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			want:  stall.Result{Stalled: true, Headline: unpublished, Details: []string{lost(url3, head), lost(url2, built), lost(url1, built)}},
		},
		{
			// With nothing published, every run publishes, gated or not,
			// so a run that succeeded and left nothing published failed
			// to publish, and is lost.
			name: "gated_absent_success_lost",
			src: source{
				main:     head,
				created:  ago(3 * day),
				workflow: ago(3 * day),
				runs: []stall.Run{
					{HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "success", URL: url2},
					{HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "success", URL: url1},
				},
			},
			revs:  revisions{state: registry.Absent},
			gated: true,
			want: stall.Result{
				Stalled:  true,
				Headline: "main " + head + " is unpublished, :latest is absent, and 2 or more slots were lost:",
				Details:  []string{lost(url2, head), lost(url1, built)},
			},
		},
		{
			// And so is each day with no slot run at all.
			name: "gated_missed_days",
			src: source{
				main: head,
				runs: []stall.Run{{HeadSHA: head, Created: ago(84 * time.Hour), Completed: true, Conclusion: "success", URL: url1}},
				compares: map[string]comparison{
					published + "..." + head: {status: "ahead", first: ago(5 * day)},
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			want: stall.Result{
				Stalled:  true,
				Headline: unpublished,
				Details:  []string{"3 day(s) with no slot run since 1999-12-28T12:00:00Z"},
			},
		},
		{
			// Content-gated and reading its own job, a slot run that went
			// red for another app's build, while this app's publish job
			// succeeded, is not lost (backlog CI-7).
			name: "gated_job_red_run_own_job_green_not_lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{ID: 2, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "failure", URL: url2},
					{ID: 1, HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "failure", URL: url1},
				},
				jobs: map[int64]map[string]string{
					2: {"publish (baikal)": "success", "build (librespeed, amd64)": "failure", "publish (librespeed)": "failure"},
					1: {"publish (baikal)": "success", "publish (librespeed)": "failure"},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			job:   "publish (baikal)",
			want:  stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			// And its own job, skipped or failed, makes a run lost however
			// the run as a whole ended.
			name: "gated_job_own_job_not_green_lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{ID: 2, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "success", URL: url2},
					{ID: 1, HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "failure", URL: url1},
				},
				jobs: map[int64]map[string]string{
					2: {"publish (baikal)": "skipped", "publish (librespeed)": "success"},
					1: {"publish (baikal)": "failure", "publish (librespeed)": "success"},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			job:   "publish (baikal)",
			want:  stall.Result{Stalled: true, Headline: unpublished, Details: []string{lost(url2, head), lost(url1, built)}},
		},
		{
			// A run with no jobs at all, as one that never started has
			// none, ends as the run did.
			name: "gated_job_run_without_jobs",
			src: source{
				main: head,
				runs: []stall.Run{
					{ID: 3, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "startup_failure", URL: url3},
					{ID: 2, HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "success", URL: url2},
				},
				jobs: map[int64]map[string]string{3: {}, 2: {}},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			job:   "publish (baikal)",
			want:  stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 1 lost slot(s), under 2"},
		},
		{
			// A run with jobs, none of them the one named: a name written
			// wrong is an error, not every run lost or none.
			name: "gated_job_unknown",
			src: source{
				main: head,
				runs: []stall.Run{{ID: 2, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "success", URL: url2}},
				jobs: map[int64]map[string]string{2: {"publish (librespeed)": "success"}},
				compares: map[string]comparison{
					published + "..." + head: {status: "ahead", first: ago(3 * day)},
				},
			},
			revs:    revisions{revision: published, state: registry.Published},
			gated:   true,
			job:     "publish (baikal)",
			wantErr: stall.ErrNoJob,
		},
		{
			// GitHub decides a job's if: before it expands the job's
			// matrix, so a run whose publish matrix it skipped, its lint
			// red say, lists the job once, under its unexpanded name. That
			// stands for this image's job, which did not succeed, so the
			// run is lost when ahead, as any other is.
			name: "gated_job_matrix_skipped_lost",
			src: source{
				main: head,
				runs: []stall.Run{
					{ID: 2, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "failure", URL: url2},
					{ID: 1, HeadSHA: built, Created: ago(44 * time.Hour), Completed: true, Conclusion: "success", URL: url1},
				},
				jobs: map[int64]map[string]string{
					2: {"lint / lint": "failure", "build (baikal, amd64)": "success", "publish (${{ matrix.app }})": "skipped"},
					1: {"publish (baikal)": "success", "publish (librespeed)": "success"},
				},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + built: ahead,
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			job:   "publish (baikal)",
			want:  stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 1 lost slot(s), under 2"},
		},
		{
			// A run of a commit not ahead of :latest is not lost, whatever
			// its job did, so its jobs are never read: the source here has
			// none scripted, and fails if asked.
			name: "gated_job_not_ahead_never_read",
			src: source{
				main: head,
				runs: []stall.Run{{ID: 4, HeadSHA: older, Created: ago(20 * time.Hour), Completed: true, Conclusion: "failure", URL: url1}},
				compares: map[string]comparison{
					published + "..." + head:  {status: "ahead", first: ago(3 * day)},
					published + "..." + older: {status: "behind"},
				},
			},
			revs:  revisions{revision: published, state: registry.Published},
			gated: true,
			job:   "publish (baikal)",
			want:  stall.Result{Headline: "main " + head + " is ahead of :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			// An unexpanded name stands only for the names it would expand
			// to: another job's, skipped, leaves a name written wrong an
			// error.
			name: "gated_job_other_matrix_skipped",
			src: source{
				main: head,
				runs: []stall.Run{{ID: 2, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "failure", URL: url2}},
				jobs: map[int64]map[string]string{2: {"build (${{ matrix.app }}, ${{ matrix.arch }})": "skipped"}},
				compares: map[string]comparison{
					published + "..." + head: {status: "ahead", first: ago(3 * day)},
				},
			},
			revs:    revisions{revision: published, state: registry.Published},
			gated:   true,
			job:     "publish (baikal)",
			wantErr: stall.ErrNoJob,
		},
		{
			// Main behind :latest, with no slot run and no commit to say
			// when main stopped being what is published: as many days as
			// make a stall.
			name: "published_behind_no_runs",
			src: source{
				main:     head,
				compares: map[string]comparison{published + "..." + head: {status: "behind"}},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{
				Stalled:  true,
				Headline: unpublished,
				Details:  []string{"2 day(s) with no slot run since ever"},
			},
		},
		{
			// The headline says how main stands against :latest.
			name: "published-behind",
			src: source{
				main:     head,
				runs:     []stall.Run{{HeadSHA: head, Created: ago(time.Hour), URL: url1}},
				compares: map[string]comparison{published + "..." + head: {status: "behind"}},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + head + " is behind :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			name: "published-diverged",
			src: source{
				main:     head,
				runs:     []stall.Run{{HeadSHA: head, Created: ago(time.Hour), URL: url1}},
				compares: map[string]comparison{published + "..." + head: {status: "diverged", first: ago(2 * time.Hour)}},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + head + " has diverged from :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			// Never so for two full SHAs, but said as GitHub says it.
			name: "published-identical",
			src: source{
				main:     head,
				runs:     []stall.Run{{HeadSHA: head, Created: ago(time.Hour), URL: url1}},
				compares: map[string]comparison{published + "..." + head: {status: "identical"}},
			},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + head + " is identical to :latest " + published + ", with 0 lost slot(s), under 2"},
		},
		{
			// Main is what :latest was built from: nothing else is asked.
			name: "published-main",
			src:  source{main: published},
			revs: revisions{revision: published, state: registry.Published},
			want: stall.Result{Headline: "main " + published + " is published"},
		},
		{
			name: "private",
			revs: revisions{err: fmt.Errorf("%w: GitHub gives it the visibility \"private\"", registry.ErrPrivate)},
			want: stall.Result{
				Stalled:  true,
				Headline: image + " is private, so no one can pull it:",
				Details:  []string{`package is private: GitHub gives it the visibility "private"`},
			},
		},
		{
			name:    "registry-error",
			revs:    revisions{err: errRegistry},
			wantErr: errRegistry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				c := config
				c.ContentGated = tt.gated
				c.SlotJob = tt.job
				got, err := stall.Slots(t.Context(), &tt.src, tt.revs, &c)
				if tt.wantErr != nil {
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("Slots() = %+v, %v; want an error wrapping %v", got, err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				checkResult(t, got, tt.want)
			})
		})
	}
}

// TestSlotJobErrors checks what a content-gated slot reading its own job
// says when a run ahead of :latest has jobs and no one job that is the
// one named or stands for it: every job the run has, so a name written
// wrong is found, and how many matched when more than one did.
func TestSlotJobErrors(t *testing.T) {
	t.Parallel()
	const url = "https://github.com/divbast/frankenphp/actions/runs/2"
	for _, tt := range []struct {
		name    string
		jobs    map[string]string
		wantErr error
		want    []string
	}{
		{
			name:    "written-wrong",
			jobs:    map[string]string{"publish (baikal)": "success", "publish (librespeed)": "success"},
			wantErr: stall.ErrNoJob,
			want:    []string{url, `"publish (baikl)"`, `"publish (baikal)"`, `"publish (librespeed)"`},
		},
		{
			name: "two",
			jobs: map[string]string{"publish (baikl)": "success", "publish (${{ matrix.app }})": "skipped"},
			want: []string{url, "2 jobs", `"publish (baikl)"`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				c := config
				c.ContentGated, c.SlotJob = true, "publish (baikl)"
				src := &source{
					main: head,
					runs: []stall.Run{{ID: 2, HeadSHA: head, Created: ago(20 * time.Hour), Completed: true, Conclusion: "failure", URL: url}},
					jobs: map[int64]map[string]string{2: tt.jobs},
					compares: map[string]comparison{
						published + "..." + head: {status: "ahead", first: ago(3 * day)},
					},
				}
				_, err := stall.Slots(t.Context(), src, revisions{revision: published, state: registry.Published}, &c)
				if err == nil || (tt.wantErr != nil && !errors.Is(err, tt.wantErr)) {
					t.Fatalf("Slots() error = %v, want one wrapping %v", err, tt.wantErr)
				}
				for _, w := range tt.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("Slots() error = %q, want it to say %q", err, w)
					}
				}
			})
		})
	}
}

// TestSlotsTag checks that the messages name the tag the slot publishes,
// which is not always :latest.
func TestSlotsTag(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		c := config
		c.Published = "ghcr.io/divbast/frankenphp:baikal"
		revs := revisionsFor{image: c.Published, state: registry.Absent}
		got, err := stall.Slots(t.Context(), &source{main: head, created: ago(time.Hour), workflow: ago(time.Hour)}, revs, &c)
		if err != nil {
			t.Fatal(err)
		}
		checkResult(t, got, stall.Result{Headline: "main " + head + " is ahead of :baikal (absent), with 0 lost slot(s), under 2"})
	})
}

// TestSlotsNothingToCheck checks that slots refuses to run without an
// image to check, rather than taking none for one never published.
func TestSlotsNothingToCheck(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		c := config
		c.Published = ""
		// Nothing scripted: nothing may be asked.
		got, err := stall.Slots(t.Context(), &source{}, revisions{state: registry.Absent}, &c)
		if err == nil || !strings.Contains(err.Error(), "no published image") {
			t.Fatalf("Slots() = %+v, %v; want an error saying there is no published image", got, err)
		}
	})
}

// revisionsFor is revisions answering for another image.
type revisionsFor struct {
	image string
	revisions
}

func (r revisionsFor) Revision(_ context.Context, img string) (string, registry.State, error) {
	if img != r.image {
		return "", 0, fmt.Errorf("asked about %s", img)
	}
	return r.revision, r.state, r.err
}

// TestErrors checks that every check passes on what it could not read,
// rather than taking it for a stall or for nothing found.
func TestErrors(t *testing.T) {
	t.Parallel()

	errSource := errors.New("gh broke")
	broken := &source{err: errSource}
	absent := revisions{state: registry.Absent}
	pub := revisions{revision: published, state: registry.Published}

	tests := []struct {
		name  string
		check func(ctx context.Context) (stall.Result, error)
	}{
		{"open", func(ctx context.Context) (stall.Result, error) { return stall.Open(ctx, broken, &config) }},
		{"stuck", func(ctx context.Context) (stall.Result, error) { return stall.Stuck(ctx, broken, &config) }},
		{"renovate", func(ctx context.Context) (stall.Result, error) { return stall.Renovate(ctx, broken, &config) }},
		{"slots-absent", func(ctx context.Context) (stall.Result, error) { return stall.Slots(ctx, broken, absent, &config) }},
		{"slots-published", func(ctx context.Context) (stall.Result, error) { return stall.Slots(ctx, broken, pub, &config) }},
		{"starved", func(ctx context.Context) (stall.Result, error) { return stall.Starved(ctx, broken, &config) }},
		{"flaky", func(ctx context.Context) (stall.Result, error) { return stall.Flaky(ctx, broken, &config) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				got, err := tt.check(t.Context())
				if !errors.Is(err, errSource) {
					t.Fatalf("got %+v, %v; want an error wrapping %v", got, err, errSource)
				}
			})
		})
	}
}

// TestSlotsCompareError checks that a run whose commit cannot be compared
// fails the check rather than being taken for lost or not.
func TestSlotsCompareError(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := source{
			main:     head,
			runs:     []stall.Run{{HeadSHA: built, Created: ago(time.Hour), Completed: true}},
			compares: map[string]comparison{published + "..." + head: {status: "ahead", first: ago(2 * time.Hour)}},
		}
		got, err := stall.Slots(t.Context(), &src, revisions{revision: published, state: registry.Published}, &config)
		if err == nil || !strings.Contains(err.Error(), built) {
			t.Fatalf("Slots() = %+v, %v; want an error naming %s", got, err, built)
		}
	})
}

// lookupSection is the section Renovate writes on a Dependency Dashboard
// on GitHub for lookups that failed, as its own tests pin it
// (dependency-dashboard.spec.ts), with each failure and file backticked.
func lookupSection(failures, files string) string {
	return "---\n\n> [!WARNING]\n> Renovate failed to look up the following dependencies: " + failures +
		".\n> \n> Files affected: " + files + "\n\n---\n\n"
}

// dashboard is the clean Dependency Dashboard from testdata with section
// where Renovate puts warnings, before the open pull requests.
func dashboard(t *testing.T, section string) string {
	t.Helper()
	body := string(testdata(t, "dashboard-clean.md"))
	if !strings.Contains(body, "## Open") {
		t.Fatal("the clean dashboard has no ## Open to put the section before")
	}
	return strings.Replace(body, "## Open", section+"## Open", 1)
}

const dashboardURL = "https://github.com/divbast/baikal-oci-image/issues/94"

// trivy is a lookup Renovate failed, as the dashboard lists it, and
// trivyFailed is the same as lookups reports it.
const (
	trivy       = "`Failed to look up github-tags package aquasecurity/trivy: no-result`"
	trivyFailed = "Failed to look up github-tags package aquasecurity/trivy: no-result"
)

// edit is an edit of a dashboard made d before epoch, leaving it with body.
func edit(d time.Duration, body string) stall.DashboardEdit {
	return stall.DashboardEdit{EditedAt: ago(d), Body: body}
}

// onDashboard is a source with one open Dependency Dashboard, #94, whose
// body is body and whose history is edits, newest first.
func onDashboard(body string, edits ...stall.DashboardEdit) *source {
	return &source{
		dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: body, URL: dashboardURL}},
		edits:      map[int][]stall.DashboardEdit{94: edits},
	}
}

func lookupsWith(t *testing.T, s *source) stall.Result {
	t.Helper()
	res, err := stall.Lookups(t.Context(), s, &config)
	if err != nil {
		t.Fatalf("Lookups() error = %v", err)
	}
	return res
}

// failedHeadline is the headline of a lookups stall on dashboard #94, and
// youngHeadline the passing one when #94 lists trivy, not yet seen listed
// for 24 hours.
const (
	failedHeadline = "Renovate failed lookups, by the Dependency Dashboard " + dashboardURL + ":"
	youngHeadline  = `no failed Renovate lookup listed for 24 hours on the Dependency Dashboard #94; not yet seen listed that long: "` + trivyFailed + `"`
)

func TestLookupsClean(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		// No history scripted: a dashboard with no failed lookup never
		// asks for it
		res := lookupsWith(t, &source{dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: dashboard(t, ""), URL: dashboardURL}}})
		checkResult(t, res, stall.Result{Headline: "no failed Renovate lookup on the Dependency Dashboard #94"})
	})
}

// TestLookupsPersistent reads a lookup the dashboard lists now, 2 hours
// ago and 25 hours ago: a lookup that stays broken stalls as it always
// has.
func TestLookupsPersistent(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, lookupSection(trivy, "`mise.toml`"))
		res := lookupsWith(t, onDashboard(body, edit(0, body), edit(2*time.Hour, body), edit(25*time.Hour, body)))
		checkResult(t, res, stall.Result{Stalled: true, Headline: failedHeadline, Details: []string{trivyFailed, "files affected: mise.toml"}})
	})
}

// TestLookupsTransient reads a lookup listed now and 3 hours ago, but not
// 25 hours ago: one that failed once, a registry briefly unreachable say,
// is named but does not stall.
func TestLookupsTransient(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, lookupSection(trivy, "`mise.toml`"))
		res := lookupsWith(t, onDashboard(body, edit(0, body), edit(3*time.Hour, body), edit(25*time.Hour, dashboard(t, ""))))
		checkResult(t, res, stall.Result{Headline: youngHeadline})
	})
}

// TestLookupsFlickered reads a lookup listed now and 25 hours ago, but
// not 10 hours ago: it cleared in between, so it has not been listed for
// 24 hours.
func TestLookupsFlickered(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, lookupSection(trivy, "`mise.toml`"))
		res := lookupsWith(t, onDashboard(body, edit(0, body), edit(10*time.Hour, dashboard(t, "")), edit(25*time.Hour, body)))
		checkResult(t, res, stall.Result{Headline: youngHeadline})
	})
}

// TestLookupsYoungDashboard reads a dashboard with no edit older than 24
// hours, made a second short of that with the lookup on it: its history
// cannot show the lookup listed for 24 hours. Nor can one GitHub kept
// too few edits of.
func TestLookupsYoungDashboard(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, lookupSection(trivy, "`mise.toml`"))
		res := lookupsWith(t, onDashboard(body, edit(0, body), edit(day-time.Second, body)))
		checkResult(t, res, stall.Result{Headline: youngHeadline})
	})
}

// TestLookupsFilesMoved reads a lookup listed for 25 hours whose files
// changed in that time: it is the same lookup, and the files it is in now
// are reported.
func TestLookupsFilesMoved(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, lookupSection(trivy, "`Containerfile`, `mise.toml`"))
		res := lookupsWith(t, onDashboard(body, edit(0, body), edit(25*time.Hour, dashboard(t, lookupSection(trivy, "`mise.toml`")))))
		checkResult(t, res, stall.Result{Stalled: true, Headline: failedHeadline, Details: []string{trivyFailed, "files affected: Containerfile, mise.toml"}})
	})
}

// TestLookupsOneOfTwo reads two lookups on one line, one listed for 25
// hours and one for 3: only the first is reported, with the line's
// files.
func TestLookupsOneOfTwo(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		grype := "`Failed to look up github-tags package anchore/grype: no-result`"
		body := dashboard(t, lookupSection(trivy+", "+grype, "`mise.toml`"))
		old := dashboard(t, lookupSection(trivy, "`mise.toml`"))
		res := lookupsWith(t, onDashboard(body, edit(0, body), edit(3*time.Hour, body), edit(25*time.Hour, old)))
		checkResult(t, res, stall.Result{Stalled: true, Headline: failedHeadline, Details: []string{trivyFailed, "files affected: mise.toml"}})
	})
}

func TestLookupsTwoItemsCRLF(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		// A web edit, ticking a box say, saves the body with CRLF until
		// Renovate's next rewrite: the lookups it lists are the same
		lf := dashboard(t, lookupSection(
			"`Failed to look up custom.lidarr-nightly package Lidarr/Lidarr: no-result`, "+
				"`Could not determine new digest for update (docker package dhi.io/aspnetcore)`",
			"`Containerfile`, `mise.toml`",
		))
		body := strings.ReplaceAll(lf, "\n", "\r\n")
		res := lookupsWith(t, onDashboard(body, edit(time.Hour, body), edit(25*time.Hour, lf)))
		checkResult(t, res, stall.Result{Stalled: true, Headline: failedHeadline, Details: []string{
			"Failed to look up custom.lidarr-nightly package Lidarr/Lidarr: no-result",
			"Could not determine new digest for update (docker package dhi.io/aspnetcore)",
			"files affected: Containerfile, mise.toml",
		}})
	})
}

func TestLookupsDeprecationsOnly(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		// Renovate's other warnings share the [!WARNING] heading, never the
		// sentence
		section := "## Deprecations / Replacements\n\n> [!WARNING]\n> The following dependencies are either deprecated " +
			"or have replacements available:\n\n| Datasource | Name | Replacement PR? |\n|---|---|---|\n| npm | `request` | unavailable |\n\n" +
			"## Repository Problems\n\nRenovate tried to run on this repository, but found these problems.\n\n" +
			" - WARN: Fallback to renovate.json file as a preset is deprecated, please use a default.json file instead.\n\n"
		res := lookupsWith(t, &source{dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: dashboard(t, section), URL: dashboardURL}}})
		if res.Stalled {
			t.Errorf("Lookups() = %+v, want not stalled: no lookup failed", res)
		}
	})
}

func TestLookupsUnparsable(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		// The sentence with nothing backticked: a format that drifted fails
		// closed, quoting the line, at once, with no history to read
		line := "> Renovate failed to look up the following dependencies: aquasecurity/trivy."
		body := dashboard(t, "---\n\n> [!WARNING]\n"+line+"\n\n---\n\n")
		res := lookupsWith(t, &source{dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: body, URL: dashboardURL}}})
		if !res.Stalled || len(res.Details) != 1 || !strings.Contains(res.Details[0], line) {
			t.Errorf("Lookups() = %+v, want stalled, quoting %q", res, line)
		}
	})
}

func TestLookupsNoDashboard(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		last := time.Date(2026, 11, 19, 0, 41, 21, 0, time.UTC)
		res := lookupsWith(t, &source{success: last})
		if !res.Stalled || res.Headline != "No open Dependency Dashboard by divbast-renovate, so failed lookups cannot be seen:" ||
			len(res.Details) != 1 || !strings.Contains(res.Details[0], "2026-11-19T00:41:21Z") {
			t.Errorf("Lookups() after a success = %+v, want stalled, naming the last success", res)
		}
		res = lookupsWith(t, &source{})
		if res.Stalled {
			t.Errorf("Lookups() before any success = %+v, want not stalled: the renovate check owns that", res)
		}
	})
}

func TestLookupsSourceFails(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		if _, err := stall.Lookups(t.Context(), &source{err: errors.New("gh: HTTP 502")}, &config); err == nil {
			t.Error("Lookups() error = nil, want gh's")
		}
	})
}

// TestLookupsHistoryFails checks that a dashboard listing a failed lookup
// whose history cannot be read fails the check, rather than being taken
// for a lookup listed for 24 hours or for less.
func TestLookupsHistoryFails(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		errHistory := errors.New("gh api graphql: HTTP 502")
		src := onDashboard(dashboard(t, lookupSection(trivy, "`mise.toml`")))
		src.historyErr = errHistory
		got, err := stall.Lookups(t.Context(), src, &config)
		if !errors.Is(err, errHistory) {
			t.Fatalf("Lookups() = %+v, %v; want an error wrapping %v", got, err, errHistory)
		}
	})
}

// TestLookupsUnreadableHistoryFails checks that a line that cannot be read
// stalls at once even when the history another lookup needs cannot be
// read either: the error is a detail of its own beside the line, not an
// error that hides it.
func TestLookupsUnreadableHistoryFails(t *testing.T) {
	t.Parallel()

	line := "> Renovate failed to look up the following dependencies: aquasecurity/trivy."
	unreadable := "---\n\n> [!WARNING]\n" + line + "\n\n"
	grype := lookupSection("`Failed to look up github-tags package anchore/grype: no-result`", "`mise.toml`")
	errHistory := errors.New("gh api graphql: HTTP 502")
	const otherURL = "https://github.com/divbast/baikal-oci-image/issues/95"

	tests := []struct {
		name       string
		dashboards []stall.Issue
		want       stall.Result
	}{
		{
			name:       "on-one-dashboard",
			dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: dashboard(t, unreadable+grype), URL: dashboardURL}},
			want: stall.Result{Stalled: true, Headline: failedHeadline, Details: []string{
				"unreadable: " + line, "could not read the history of #94: " + errHistory.Error(),
			}},
		},
		{
			name: "on-another-dashboard",
			dashboards: []stall.Issue{
				{Number: 94, Title: "Dependency Dashboard", Body: dashboard(t, grype), URL: dashboardURL},
				{Number: 95, Title: "Dependency Dashboard", Body: dashboard(t, unreadable), URL: otherURL},
			},
			want: stall.Result{
				Stalled:  true,
				Headline: "Renovate failed lookups, by the Dependency Dashboard " + dashboardURL + ", " + otherURL + ":",
				Details:  []string{"could not read the history of #94: " + errHistory.Error(), "unreadable: " + line},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				res := lookupsWith(t, &source{dashboards: tt.dashboards, historyErr: errHistory})
				checkResult(t, res, tt.want)
			})
		})
	}
}

// TestPersistent checks, edge by edge, when a lookup counts as listed for
// a day: in the body now, in every edit of the last day, and in the newest
// edit made at or before a day ago.
func TestPersistent(t *testing.T) {
	t.Parallel()

	grype := "`Failed to look up github-tags package anchore/grype: no-result`"
	listed := dashboard(t, lookupSection(trivy, "`mise.toml`"))
	clean := dashboard(t, "")

	tests := []struct {
		name    string
		current string
		edits   []stall.DashboardEdit
		want    bool
	}{
		{
			name:    "listed-throughout",
			current: listed,
			edits:   []stall.DashboardEdit{edit(0, listed), edit(2*time.Hour, listed), edit(25*time.Hour, listed)},
			want:    true,
		},
		{
			// At or before a day ago: an edit made exactly then stood for
			// the whole day
			name:    "edited-exactly-a-day-ago",
			current: listed,
			edits:   []stall.DashboardEdit{edit(day, listed)},
			want:    true,
		},
		{
			name:    "edited-a-second-short-of-a-day-ago",
			current: listed,
			edits:   []stall.DashboardEdit{edit(day-time.Second, listed)},
		},
		{
			name:    "gone-now",
			current: clean,
			edits:   []stall.DashboardEdit{edit(2*time.Hour, listed), edit(25*time.Hour, listed)},
		},
		{
			name:    "not-listed-a-day-ago",
			current: listed,
			edits:   []stall.DashboardEdit{edit(3*time.Hour, listed), edit(25*time.Hour, clean)},
		},
		{
			name:    "cleared-within-the-day",
			current: listed,
			edits:   []stall.DashboardEdit{edit(0, listed), edit(10*time.Hour, clean), edit(25*time.Hour, listed)},
		},
		{
			// Only the newest edit at or before a day ago says what stood
			// then
			name:    "cleared-before-the-day",
			current: listed,
			edits:   []stall.DashboardEdit{edit(25*time.Hour, listed), edit(30*time.Hour, clean)},
			want:    true,
		},
		{
			name:    "listed-before-but-not-a-day-ago",
			current: listed,
			edits:   []stall.DashboardEdit{edit(25*time.Hour, clean), edit(30*time.Hour, listed)},
		},
		{
			// Edits in any order: the newest made at or before a day ago
			// counts, wherever it stands
			name:    "out-of-order",
			current: listed,
			edits:   []stall.DashboardEdit{edit(30*time.Hour, clean), edit(0, listed), edit(25*time.Hour, listed)},
			want:    true,
		},
		{
			name:    "no-history",
			current: listed,
		},
		{
			// GitHub keeps the newest 99 edits: a history that ends inside
			// the day does not show what stood a day ago
			name:    "history-cut-short",
			current: listed,
			edits:   []stall.DashboardEdit{edit(0, listed), edit(12*time.Hour, listed), edit(23*time.Hour, listed)},
		},
		{
			name:    "files-moved",
			current: dashboard(t, lookupSection(trivy, "`Containerfile`")),
			edits:   []stall.DashboardEdit{edit(25*time.Hour, listed)},
			want:    true,
		},
		{
			name:    "listed-with-another",
			current: listed,
			edits:   []stall.DashboardEdit{edit(25*time.Hour, dashboard(t, lookupSection(grype+", "+trivy, "`mise.toml`")))},
			want:    true,
		},
		{
			// The files line names the lookup's files, not lookups
			name:    "a-file-named-like-it",
			current: listed,
			edits:   []stall.DashboardEdit{edit(25*time.Hour, dashboard(t, lookupSection(grype, trivy)))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stall.Persistent(trivyFailed, tt.current, tt.edits, epoch, day); got != tt.want {
				t.Errorf("persistent() = %t, want %t", got, tt.want)
			}
		})
	}
}

// pendingSection and scheduleSection are the sections Renovate 45 writes
// on a Dependency Dashboard for updates whose status checks are pending,
// its release age among them, and for updates their schedule holds back,
// as dependency-dashboard.ts writes them, with each of items a line.
func pendingSection(items ...string) string {
	return "## Pending Status Checks\n\nThe following updates await pending status checks. To force their creation now, click on a checkbox below.\n\n" +
		strings.Join(items, "\n") + "\n\n"
}

func scheduleSection(items ...string) string {
	return "## Awaiting Schedule\n\nThe following updates are awaiting their schedule. To get an update now, click on a checkbox below.\n\n" +
		strings.Join(items, "\n") + "\n\n"
}

// stylelint is the line on which a dashboard lists stylelint's update to
// version v as waiting on its status checks, and stylelintWaiting is the
// same update as starved names it, waiting since since.
func stylelint(v string) string {
	return " - [ ] <!-- unpend-branch=renovate/stylelint-18.x -->tools: update dependency stylelint to " + v
}

func stylelintWaiting(v, since string) string {
	return "tools: update dependency stylelint to " + v + " (since " + since + ")"
}

// pnpm is another update waiting on its status checks.
const pnpm = " - [ ] <!-- unpend-branch=renovate/pnpm -->tools: update pnpm to v12.23.0"

// pisatiWaiting are the updates pisati's dashboard, dashboard-pending.md,
// lists under Pending Status Checks: each one's branch, and its line with
// the comment and the link taken out.
var pisatiWaiting = []struct{ branch, text string }{
	{"renovate/axe-core-playwright-4.x", "tools: update dependency @axe-core/playwright to v4.14.1"},
	{"renovate/github.com-ncruces-go-sqlite3-0.x", "tools: update module github.com/ncruces/go-sqlite3 to v0.38.1"},
	{"renovate/github.com-pressly-goose-v3-3.x", "tools: update module github.com/pressly/goose/v3 to v3.30.2"},
	{"renovate/lucide-monorepo", "tools: update dependency lucide-static to v1.81.0"},
	{"renovate/stylelint-18.x", "tools: update dependency stylelint to v18.1.0"},
	{"renovate/vite-plus-monorepo", "tools: update dependency vite-plus to v1.8.0"},
	{"renovate/pnpm", "tools: update pnpm to v12.23.0"},
}

// starvedHeadline is the headline of a starved stall at 7 days, and
// notStarved the passing one on dashboard #94.
const (
	starvedHeadline = "Waiting on the Dependency Dashboard for more than 7 days:"
	notStarved      = "no update waiting more than 7 days on the Dependency Dashboard #94"
)

func starvedWith(t *testing.T, s *source) stall.Result {
	t.Helper()
	res, err := stall.Starved(t.Context(), s, &config)
	if err != nil {
		t.Fatalf("Starved() error = %v", err)
	}
	return res
}

// TestStarvedNone reads dashboards with no update waiting under Pending
// Status Checks or Awaiting Schedule, which never ask for their history:
// the source has none to give.
func TestStarvedNone(t *testing.T) {
	t.Parallel()

	approval := "## Pending Approval\n\nThe following branches are pending approval. To create them, click on a checkbox below.\n\n" +
		" - [ ] <!-- approve-branch=renovate/go-1.x -->tools: update go module directive to v1.27.4\n\n"

	tests := []struct {
		name, section string
	}{
		{"clean", ""},
		// Pending Approval waits on a person, whom the dashboard asks
		{"pending-approval", approval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				res := starvedWith(t, &source{dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: dashboard(t, tt.section), URL: dashboardURL}}})
				checkResult(t, res, stall.Result{Headline: notStarved})
			})
		})
	}
}

// TestStarvedYoung reads an update waiting no more than 7 days: since 6
// days ago, with the edit before that clean, and since exactly 7 days
// ago, which is not more than 7.
func TestStarvedYoung(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		waiting time.Duration
	}{
		{"six-days", 6 * day},
		{"exactly-seven-days", 7 * day},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				body := dashboard(t, pendingSection(stylelint("v18.1.0")))
				res := starvedWith(t, onDashboard(body, edit(0, body), edit(tt.waiting, body), edit(9*day, dashboard(t, ""))))
				checkResult(t, res, stall.Result{Headline: notStarved})
			})
		})
	}
}

// TestStarvedOld reads updates waiting more than 7 days, each named with
// the edit it has been listed since, whichever of the two sections lists
// it.
func TestStarvedOld(t *testing.T) {
	t.Parallel()

	clean := dashboard(t, "")
	waiting := dashboard(t, pendingSection(stylelint("v18.1.0")))
	pisati := string(testdata(t, "dashboard-pending.md"))
	pisatiDetails := make([]string, 0, len(pisatiWaiting))
	for _, w := range pisatiWaiting {
		pisatiDetails = append(pisatiDetails, w.text+" (since 1999-12-24T00:00:00Z)")
	}

	tests := []struct {
		name  string
		body  string
		edits []stall.DashboardEdit
		want  []string
	}{
		{
			name:  "pending-status-checks",
			body:  waiting,
			edits: []stall.DashboardEdit{edit(0, waiting), edit(3*day, waiting), edit(8*day, waiting), edit(10*day, clean)},
			want:  []string{stylelintWaiting("v18.1.0", "1999-12-24T00:00:00Z")},
		},
		{
			name: "awaiting-schedule",
			body: dashboard(t, scheduleSection(" - [ ] <!-- unschedule-branch=renovate/debian -->build: update debian Docker tag to v13.3")),
			edits: []stall.DashboardEdit{
				edit(time.Hour, dashboard(t, scheduleSection(" - [ ] <!-- unschedule-branch=renovate/debian -->build: update debian Docker tag to v13.3"))),
				edit(9*day, dashboard(t, scheduleSection(" - [ ] <!-- unschedule-branch=renovate/debian -->build: update debian Docker tag to v13.3"))),
			},
			want: []string{"build: update debian Docker tag to v13.3 (since 1999-12-23T00:00:00Z)"},
		},
		{
			// A second past 7 days is more than 7
			name:  "just-past",
			body:  waiting,
			edits: []stall.DashboardEdit{edit(0, waiting), edit(7*day+time.Second, waiting), edit(9*day, clean)},
			want:  []string{stylelintWaiting("v18.1.0", "1999-12-24T23:59:59Z")},
		},
		{
			// Renovate edits the dashboard only when its body changes, so the
			// newest edit older than the window stood throughout
			name:  "unedited",
			body:  waiting,
			edits: []stall.DashboardEdit{edit(10*day, waiting)},
			want:  []string{stylelintWaiting("v18.1.0", "1999-12-22T00:00:00Z")},
		},
		{
			// pnpm waits since 3 days ago, so only stylelint is named
			name: "one-of-two",
			body: dashboard(t, pendingSection(stylelint("v18.1.0"), pnpm)),
			edits: []stall.DashboardEdit{
				edit(0, dashboard(t, pendingSection(stylelint("v18.1.0"), pnpm))),
				edit(3*day, dashboard(t, pendingSection(stylelint("v18.1.0"), pnpm))),
				edit(8*day, waiting),
			},
			want: []string{stylelintWaiting("v18.1.0", "1999-12-24T00:00:00Z")},
		},
		{
			name:  "recorded",
			body:  pisati,
			edits: []stall.DashboardEdit{edit(0, pisati), edit(8*day, pisati)},
			want:  pisatiDetails,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				res := starvedWith(t, onDashboard(tt.body, tt.edits...))
				checkResult(t, res, stall.Result{Stalled: true, Headline: starvedHeadline, Details: tt.want})
			})
		})
	}
}

// TestStarvedTwoDashboards reads two open dashboards, each with an update
// waiting more than 7 days: both are named, in the dashboards' order.
func TestStarvedTwoDashboards(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		first := dashboard(t, pendingSection(stylelint("v18.1.0")))
		second := dashboard(t, pendingSection(pnpm))
		res := starvedWith(t, &source{
			dashboards: []stall.Issue{
				{Number: 94, Title: "Dependency Dashboard", Body: first, URL: dashboardURL},
				{Number: 95, Title: "Dependency Dashboard", Body: second, URL: "https://github.com/divbast/baikal-oci-image/issues/95"},
			},
			edits: map[int][]stall.DashboardEdit{94: {edit(9*day, first)}, 95: {edit(0, second), edit(8*day, second)}},
		})
		checkResult(t, res, stall.Result{Stalled: true, Headline: starvedHeadline, Details: []string{
			stylelintWaiting("v18.1.0", "1999-12-23T00:00:00Z"), "tools: update pnpm to v12.23.0 (since 1999-12-24T00:00:00Z)",
		}})
	})
}

// TestStarvedFlickerResets reads an update listed 8 days ago, gone 5 days
// ago, and listed again since: its clock starts again from its return.
func TestStarvedFlickerResets(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, pendingSection(stylelint("v18.1.0")))
		res := starvedWith(t, onDashboard(body, edit(0, body), edit(4*day, body), edit(5*day, dashboard(t, "")), edit(8*day, body), edit(10*day, body)))
		checkResult(t, res, stall.Result{Headline: notStarved})
	})
}

// TestStarvedNewVersionKeepsClock reads an update whose line changed while
// it waited: a newer version, a pull request opened, or a move from one
// section to the other. Its branch is the same, so it is the same update,
// still waiting, and the clock runs from when the branch was first listed.
// It is named by its line now.
func TestStarvedNewVersionKeepsClock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		now    string
		before []string // what the edits 4 and 8 days ago list
		want   string
	}{
		{
			name:   "new-version",
			now:    pendingSection(stylelint("v18.1.2")),
			before: []string{pendingSection(stylelint("v18.1.1")), pendingSection(stylelint("v18.1.0"))},
			want:   stylelintWaiting("v18.1.2", "1999-12-24T00:00:00Z"),
		},
		{
			name:   "pull-request-opened",
			now:    pendingSection(" - [ ] <!-- unpend-branch=renovate/stylelint-18.x -->[tools: update dependency stylelint to v18.1.0](../pull/14)"),
			before: []string{pendingSection(stylelint("v18.1.0")), pendingSection(stylelint("v18.1.0"))},
			want:   stylelintWaiting("v18.1.0", "1999-12-24T00:00:00Z"),
		},
		{
			// Its schedule opened, and now its release age holds it
			name: "schedule-then-status-checks",
			now:  pendingSection(stylelint("v18.1.0")),
			before: []string{
				pendingSection(stylelint("v18.1.0")),
				scheduleSection(" - [ ] <!-- unschedule-branch=renovate/stylelint-18.x -->tools: update dependency stylelint to v18.1.0"),
			},
			want: stylelintWaiting("v18.1.0", "1999-12-24T00:00:00Z"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				body := dashboard(t, tt.now)
				res := starvedWith(t, onDashboard(body,
					edit(0, body), edit(4*day, dashboard(t, tt.before[0])), edit(8*day, dashboard(t, tt.before[1])), edit(10*day, dashboard(t, ""))))
				checkResult(t, res, stall.Result{Stalled: true, Headline: starvedHeadline, Details: []string{tt.want}})
			})
		})
	}
}

// TestStarvedUnreadable reads sections it cannot read whole: a line under
// either heading that names no branch, and a heading with no update under
// it in Renovate's form. Each stalls at once, quoted, and needs no
// history; a section it can read beside one still has its history read.
func TestStarvedUnreadable(t *testing.T) {
	t.Parallel()

	const (
		noBranch      = " - [ ] tools: update dependency stylelint to v18.1.0"
		pendingEmpty  = "unreadable: ## Pending Status Checks: no update under it in Renovate's form"
		scheduleEmpty = "unreadable: ## Awaiting Schedule: no update under it in Renovate's form"
	)

	tests := []struct {
		name    string
		section string
		edits   []stall.DashboardEdit
		want    []string
	}{
		{
			name:    "no-branch",
			section: pendingSection(noBranch),
			want:    []string{"unreadable: " + strings.TrimSpace(noBranch), pendingEmpty},
		},
		{
			name:    "nothing-under-it",
			section: "## Awaiting Schedule\n\nThe following updates are awaiting their schedule. To get an update now, click on a checkbox below.\n\n",
			want:    []string{scheduleEmpty},
		},
		{
			// Renovate writes its bulk line only below two updates or more
			name:    "only-the-bulk-line",
			section: scheduleSection(" - [ ] <!-- create-all-awaiting-schedule-prs -->🔐 **Create all awaiting schedule PRs at once** 🔐"),
			want:    []string{scheduleEmpty},
		},
		{
			// Another list form: no line in it is an update
			name:    "another-form",
			section: pendingSection("* [ ] <!-- unpend-branch=renovate/stylelint-18.x -->tools: update dependency stylelint to v18.1.0"),
			want:    []string{pendingEmpty},
		},
		{
			name:    "beside-one-it-reads",
			section: pendingSection(stylelint("v18.1.0"), noBranch),
			edits:   []stall.DashboardEdit{edit(day, dashboard(t, pendingSection(stylelint("v18.1.0"), noBranch)))},
			want:    []string{"unreadable: " + strings.TrimSpace(noBranch)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				// Without edits scripted, a read of the history fails the test
				src := &source{dashboards: []stall.Issue{{Number: 94, Title: "Dependency Dashboard", Body: dashboard(t, tt.section), URL: dashboardURL}}}
				if tt.edits != nil {
					src.edits = map[int][]stall.DashboardEdit{94: tt.edits}
				}
				res := starvedWith(t, src)
				checkResult(t, res, stall.Result{Stalled: true, Headline: starvedHeadline, Details: tt.want})
			})
		})
	}
}

// TestStarvedHistoryShort reads a history that reaches back only 2 days,
// as GitHub's does for a dashboard edited 99 times since, with the update
// in its oldest edit: it counts from that edit, never earlier, so it does
// not stall.
func TestStarvedHistoryShort(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, pendingSection(stylelint("v18.1.0")))
		res := starvedWith(t, onDashboard(body, edit(0, body), edit(day, body), edit(2*day, body)))
		checkResult(t, res, stall.Result{Headline: notStarved})
	})
}

// TestStarvedHistoryWindow checks that starved asks for the history back
// to one day more than StarvedDays: the source answers from there, so an
// update listed since only within the window, or for longer, reads the
// edits that show it.
func TestStarvedHistoryWindow(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		body := dashboard(t, pendingSection(stylelint("v18.1.0")))
		src := &windowSource{source: onDashboard(body, edit(0, body), edit(9*day, body))}
		if _, err := stall.Starved(t.Context(), src, &config); err != nil {
			t.Fatalf("Starved() error = %v", err)
		}
		if want := ago(8 * day); !src.since.Equal(want) {
			t.Errorf("DashboardHistory asked since %v, want %v", src.since, want)
		}
	})
}

// windowSource is a source that keeps the since of its last history read.
type windowSource struct {
	*source
	since time.Time
}

func (w *windowSource) DashboardHistory(ctx context.Context, number int, since time.Time) ([]stall.DashboardEdit, error) {
	w.since = since
	return w.source.DashboardHistory(ctx, number, since)
}

func TestStarvedNoDashboard(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		last := time.Date(1999, 12, 31, 3, 0, 0, 0, time.UTC)
		res := starvedWith(t, &source{success: last})
		checkResult(t, res, stall.Result{
			Stalled:  true,
			Headline: "No open Dependency Dashboard by divbast-renovate, so updates waiting on it cannot be seen:",
			Details:  []string{`no open issue titled "Dependency Dashboard"; Renovate last succeeded 1999-12-31T03:00:00Z`},
		})
		res = starvedWith(t, &source{})
		checkResult(t, res, stall.Result{Headline: "no Dependency Dashboard yet, and no successful Renovate run to have made one"})
	})
}

// TestStarvedHistoryFails checks that a dashboard listing an update whose
// history cannot be read fails the check, rather than being taken for an
// update waiting any length of time; beside a section it cannot read,
// which stalls whatever the history says, the error is a detail.
func TestStarvedHistoryFails(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		errHistory := errors.New("gh api graphql: HTTP 502")
		src := onDashboard(dashboard(t, pendingSection(stylelint("v18.1.0"))))
		src.historyErr = errHistory
		got, err := stall.Starved(t.Context(), src, &config)
		if !errors.Is(err, errHistory) {
			t.Fatalf("Starved() = %+v, %v; want an error wrapping %v", got, err, errHistory)
		}

		noBranch := " - [ ] tools: update pnpm to v12.23.0"
		src = onDashboard(dashboard(t, scheduleSection(noBranch)+pendingSection(stylelint("v18.1.0"))))
		src.historyErr = errHistory
		res := starvedWith(t, src)
		checkResult(t, res, stall.Result{Stalled: true, Headline: starvedHeadline, Details: []string{
			"unreadable: " + strings.TrimSpace(noBranch),
			"unreadable: ## Awaiting Schedule: no update under it in Renovate's form",
			"could not read the history of #94: " + errHistory.Error(),
		}})
	})
}

// TestPendingUpdates checks what starved reads as an update waiting: each
// line under Pending Status Checks or Awaiting Schedule that names a
// branch, known by its branch and named by the line without its comment
// and link, and nothing else on the dashboard.
func TestPendingUpdates(t *testing.T) {
	t.Parallel()

	pisati := string(testdata(t, "dashboard-pending.md"))
	pisatiBranches := make([]string, 0, len(pisatiWaiting))
	pisatiTexts := make([]string, 0, len(pisatiWaiting))
	for _, w := range pisatiWaiting {
		pisatiBranches = append(pisatiBranches, w.branch)
		pisatiTexts = append(pisatiTexts, w.text)
	}
	debian := " - [ ] <!-- unschedule-branch=renovate/debian -->build: update debian Docker tag to v13.3"

	tests := []struct {
		name           string
		body           string
		branches, text []string
		unreadable     []string
	}{
		{name: "recorded", body: pisati, branches: pisatiBranches, text: pisatiTexts},
		{
			// A web edit saves the body with CRLF until Renovate's next rewrite
			name: "crlf", body: strings.ReplaceAll(pisati, "\n", "\r\n"), branches: pisatiBranches, text: pisatiTexts,
		},
		{name: "clean", body: dashboard(t, "")},
		{
			// The bulk line is no update
			name:     "bulk-line",
			body:     dashboard(t, scheduleSection(debian, pnpm, " - [ ] <!-- create-all-awaiting-schedule-prs -->🔐 **Create all awaiting schedule PRs at once** 🔐")),
			branches: []string{"renovate/debian", "renovate/pnpm"},
			text:     []string{"build: update debian Docker tag to v13.3", "tools: update pnpm to v12.23.0"},
		},
		{
			// dependencyDashboardCategory groups updates under ### headings
			name: "categories",
			body: dashboard(t, "## Pending Status Checks\n\nThe following updates await pending status checks. To force their creation now, click on a checkbox below.\n\n"+
				"### build\n\n"+debian+"\n\n### tools\n\n"+pnpm+"\n\n"),
			branches: []string{"renovate/debian", "renovate/pnpm"},
			text:     []string{"build: update debian Docker tag to v13.3", "tools: update pnpm to v12.23.0"},
		},
		{
			// Ticked, it waits still, until Renovate's next run acts on it
			name:     "ticked",
			body:     dashboard(t, pendingSection(" - [x] <!-- unpend-branch=renovate/pnpm -->tools: update pnpm to v12.23.0")),
			branches: []string{"renovate/pnpm"},
			text:     []string{"tools: update pnpm to v12.23.0"},
		},
		{
			// An update of more than one package names them after its title
			name:     "packages",
			body:     dashboard(t, pendingSection(" - [ ] <!-- unpend-branch=renovate/lucide-monorepo -->[tools: update lucide monorepo to v1.81.0](../pull/9) (`lucide`, `lucide-static`)")),
			branches: []string{"renovate/lucide-monorepo"},
			text:     []string{"tools: update lucide monorepo to v1.81.0 (`lucide`, `lucide-static`)"},
		},
		{
			// Renovate ends a security update's title with [SECURITY], a
			// bracket inside the link's text, which is shown whole
			name: "bracket-in-title",
			body: dashboard(t, pendingSection(" - [ ] <!-- unpend-branch=renovate/npm-axios-1.x -->"+
				"[fix(deps): update dependency axios to v1.13.5 [SECURITY]](../pull/31) (`axios`, `axios-retry`)")),
			branches: []string{"renovate/npm-axios-1.x"},
			text:     []string{"fix(deps): update dependency axios to v1.13.5 [SECURITY] (`axios`, `axios-retry`)"},
		},
		{
			// A line with nothing after its comment is named by its branch
			name:     "no-title",
			body:     dashboard(t, pendingSection(" - [ ] <!-- unpend-branch=renovate/pnpm -->")),
			branches: []string{"renovate/pnpm"},
			text:     []string{"renovate/pnpm"},
		},
		{
			name:     "listed-twice",
			body:     dashboard(t, pendingSection(pnpm)+scheduleSection(" - [ ] <!-- unschedule-branch=renovate/pnpm -->tools: update pnpm to v12.23.0")),
			branches: []string{"renovate/pnpm"},
			text:     []string{"tools: update pnpm to v12.23.0"},
		},
		{
			// The section ends at the next heading or rule: what follows is
			// Renovate's warnings, a footer, or another section's list
			name:     "ends-at-a-rule",
			body:     dashboard(t, pendingSection(pnpm)+"---\n\nThe footer\n\n - a footer's list\n\n"),
			branches: []string{"renovate/pnpm"},
			text:     []string{"tools: update pnpm to v12.23.0"},
		},
		{
			name:       "unreadable",
			body:       dashboard(t, pendingSection(pnpm, " - [ ] tools: update stylelint")),
			branches:   []string{"renovate/pnpm"},
			text:       []string{"tools: update pnpm to v12.23.0"},
			unreadable: []string{"- [ ] tools: update stylelint"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			branches, text, unreadable := stall.PendingUpdates(tt.body)
			if !slices.Equal(branches, tt.branches) {
				t.Errorf("branches = %q\nwant       %q", branches, tt.branches)
			}
			if !slices.Equal(text, tt.text) {
				t.Errorf("text = %q\nwant   %q", text, tt.text)
			}
			if !slices.Equal(unreadable, tt.unreadable) {
				t.Errorf("unreadable = %q\nwant         %q", unreadable, tt.unreadable)
			}
		})
	}
}

// Workflow IDs: the build's, a docs workflow's, and stall's and Renovate's,
// whose runs flaky passes over.
const (
	buildID int64 = iota + 1
	docsID
	stallID
	renovateID
)

// workflowIDs are the IDs of config's stall and Renovate workflows, by
// file.
var workflowIDs = map[string]int64{"stall.yml": stallID, "renovate.yml": renovateID}

// flakyRun is a finished run of the build workflow, numbered id, of commit
// sha, created at created, with its latest attempt and its conclusion.
func flakyRun(id int64, sha string, created time.Time, attempt int, conclusion string) stall.Run {
	return stall.Run{
		ID: id, HeadSHA: sha, Workflow: "build", WorkflowID: buildID, Event: "pull_request", Attempt: attempt,
		Created: created, Completed: true, Conclusion: conclusion,
		URL: fmt.Sprintf("https://github.com/divbast/librespeed-oci-image/actions/runs/%d", id),
	}
}

// job is a job named name that ended as conclusion at completed.
func job(name, conclusion string, completed time.Time) stall.Job {
	return stall.Job{Name: name, Conclusion: conclusion, Completed: completed}
}

// byAttempt is a run's jobs, by attempt, from the first.
func byAttempt(jobs ...[]stall.Job) map[int][]stall.Job {
	m := make(map[int][]stall.Job, len(jobs))
	for i, j := range jobs {
		m[i+1] = j
	}
	return m
}

// lastStall is when the stall workflow last ran before epoch, so the window
// starts there, and runs are listed from a day before it.
var lastStall = ago(20 * time.Hour)

// onRuns is a source that lists runs, each one's jobs by attempt in jobs,
// with the stall workflow last run at lastStall.
func onRuns(jobs map[int64]map[int][]stall.Job, runs ...stall.Run) *source {
	if jobs == nil {
		jobs = map[int64]map[int][]stall.Job{}
	}
	return &source{finished: runs, attempts: jobs, previous: lastStall, workflowIDs: workflowIDs}
}

// flakyHeadline is the headline of a flaky stall, and notFlaky the passing
// one, both with the window from lastStall.
const (
	flakyHeadline = "Passed and failed on the same commit since 1999-12-31T04:00:00Z:"
	notFlaky      = "no job passed and failed on the same commit since 1999-12-31T04:00:00Z"
)

func flakyWith(t *testing.T, s *source) stall.Result {
	t.Helper()
	res, err := stall.Flaky(t.Context(), s, &config)
	if err != nil {
		t.Fatalf("Flaky() error = %v", err)
	}
	return res
}

// TestFlakyNone reads runs that all passed, or all failed, or failed on one
// commit and passed on another: nothing passed and failed on one commit.
func TestFlakyNone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jobs map[int64]map[int][]stall.Job
		runs []stall.Run
	}{
		{
			name: "all-passed",
			runs: []stall.Run{flakyRun(2, built, ago(2*time.Hour), 1, "success"), flakyRun(1, built, ago(3*time.Hour), 1, "success")},
		},
		{
			name: "all-failed",
			jobs: map[int64]map[int][]stall.Job{
				2: byAttempt([]stall.Job{job("test (amd64)", "failure", ago(time.Hour)), job("test (arm64)", "failure", ago(time.Hour)), job("required", "failure", ago(time.Hour))}),
				1: byAttempt([]stall.Job{job("test (amd64)", "failure", ago(2*time.Hour)), job("test (arm64)", "failure", ago(2*time.Hour)), job("required", "failure", ago(2*time.Hour))}),
			},
			runs: []stall.Run{flakyRun(2, built, ago(2*time.Hour), 1, "failure"), flakyRun(1, built, ago(3*time.Hour), 1, "failure")},
		},
		{
			// Failed on one commit and passed on the next
			name: "other-commits",
			jobs: map[int64]map[int][]stall.Job{1: byAttempt([]stall.Job{job("build", "failure", ago(2*time.Hour))})},
			runs: []stall.Run{flakyRun(2, head, ago(2*time.Hour), 1, "success"), flakyRun(1, built, ago(3*time.Hour), 1, "failure")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				checkResult(t, flakyWith(t, onRuns(tt.jobs, tt.runs...)), stall.Result{Headline: notFlaky})
			})
		})
	}
}

// TestFlakyMatrixCell reads one run in which one cell of a matrix job
// failed and the other three passed: flaky, naming the cell.
func TestFlakyMatrixCell(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		at := ago(time.Hour)
		src := onRuns(map[int64]map[int][]stall.Job{1: byAttempt([]stall.Job{
			job("check / test (amd64, docker)", "failure", at),
			job("check / test (amd64, podman)", "success", at),
			job("check / test (arm64, docker)", "success", at),
			job("check / test (arm64, podman)", "success", at),
			job("check / lint", "success", at),
			job("required", "failure", at),
		})}, flakyRun(1, built, ago(2*time.Hour), 1, "failure"))
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{
			"build / check / test on 3333333: failed in (amd64, docker), passed in (amd64, podman), (arm64, docker), (arm64, podman)",
		}})
	})
}

// TestFlakyRerun reads one commit in two runs, the first failing and the
// second passing: flaky, naming each run.
func TestFlakyRerun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		first  []stall.Job
		second []stall.Job
		want   string
	}{
		{
			name:   "one-job",
			first:  []stall.Job{job("build", "failure", ago(3*time.Hour))},
			second: []stall.Job{job("build", "success", ago(time.Hour))},
			want:   "build / build on 3333333: failed in run 1, passed in run 2",
		},
		{
			name:   "matrix",
			first:  []stall.Job{job("test (amd64)", "failure", ago(3*time.Hour)), job("test (arm64)", "failure", ago(3*time.Hour))},
			second: []stall.Job{job("test (amd64)", "success", ago(time.Hour)), job("test (arm64)", "failure", ago(time.Hour))},
			// arm64 failing in both is no flake of its own: only the same
			// cell pairs across runs
			want: "build / test on 3333333: failed in (amd64) of run 1, passed in (amd64) of run 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				src := onRuns(map[int64]map[int][]stall.Job{1: byAttempt(tt.first), 2: byAttempt(tt.second)},
					flakyRun(2, built, ago(2*time.Hour), 1, "success"), flakyRun(1, built, ago(4*time.Hour), 1, "failure"))
				checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{tt.want}})
			})
		})
	}
}

// TestFlakyRerunAttempt reads one run re-run: an earlier attempt failed and
// the latest passed, which the latest's jobs alone do not show. A re-run of
// the failed jobs lists the others again in the next attempt, with the
// times and conclusions they had, and those are not named twice.
func TestFlakyRerunAttempt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		attempts [][]stall.Job
		want     string
	}{
		{
			name: "one-job",
			attempts: [][]stall.Job{
				{job("lint / lint", "failure", ago(3*time.Hour)), job("build", "success", ago(3*time.Hour))},
				{job("lint / lint", "success", ago(time.Hour)), job("build", "success", ago(3*time.Hour))},
			},
			want: "build / lint / lint on 3333333: failed in run 7 attempt 1, passed in run 7 attempt 2",
		},
		{
			// ci's own run 43785315672: its second attempt re-ran the one
			// failed cell, and lists the other three again
			name: "matrix-rerun-failed-jobs",
			attempts: [][]stall.Job{
				{
					job("test (amd64, docker)", "failure", ago(170*time.Minute)),
					job("test (amd64, podman)", "success", ago(171*time.Minute)),
					job("test (arm64, docker)", "success", ago(171*time.Minute)),
					job("test (arm64, podman)", "success", ago(172*time.Minute)),
					job("required", "failure", ago(169*time.Minute)),
				},
				{
					job("test (amd64, docker)", "success", ago(time.Hour)),
					job("test (amd64, podman)", "success", ago(171*time.Minute)),
					job("test (arm64, docker)", "success", ago(171*time.Minute)),
					job("test (arm64, podman)", "success", ago(172*time.Minute)),
					job("required", "success", ago(59*time.Minute)),
				},
			},
			want: "build / test on 3333333: failed in (amd64, docker) of attempt 1, passed in (amd64, podman) of attempt 1, " +
				"(arm64, docker) of attempt 1, (arm64, podman) of attempt 1, (amd64, docker) of attempt 2",
		},
		{
			name: "three-attempts",
			attempts: [][]stall.Job{
				{job("build", "failure", ago(3*time.Hour))},
				{job("build", "failure", ago(2*time.Hour))},
				{job("build", "success", ago(time.Hour))},
			},
			want: "build / build on 3333333: failed in run 7 attempt 1, run 7 attempt 2, passed in run 7 attempt 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				src := onRuns(map[int64]map[int][]stall.Job{7: byAttempt(tt.attempts...)},
					flakyRun(7, built, ago(4*time.Hour), len(tt.attempts), "success"))
				checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{tt.want}})
			})
		})
	}
}

// TestFlakyIgnoresCancelled reads a failed job beside its cancelled and
// skipped siblings, and beside the same job cancelled in another run:
// neither passed, so nothing is flaky.
func TestFlakyIgnoresCancelled(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := onRuns(map[int64]map[int][]stall.Job{
			1: byAttempt([]stall.Job{
				job("test (amd64)", "failure", ago(3*time.Hour)),
				job("test (arm64)", "cancelled", ago(3*time.Hour)),
				job("publish", "skipped", ago(3*time.Hour)),
			}),
			2: byAttempt([]stall.Job{
				job("test (amd64)", "cancelled", ago(time.Hour)),
				job("test (arm64)", "cancelled", ago(time.Hour)),
				job("publish", "skipped", ago(time.Hour)),
			}),
		}, flakyRun(2, built, ago(2*time.Hour), 1, "cancelled"), flakyRun(1, built, ago(4*time.Hour), 1, "failure"))
		checkResult(t, flakyWith(t, src), stall.Result{Headline: notFlaky})
	})
}

// TestFlakyIgnoresRequired reads the required job failing in one run and
// passing in the next, with every other job passing in both: required
// fails whenever a job it needs does, so it is no flake of its own.
func TestFlakyIgnoresRequired(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := onRuns(map[int64]map[int][]stall.Job{
			1: byAttempt([]stall.Job{job("lint / lint", "success", ago(3*time.Hour)), job("required", "failure", ago(3*time.Hour))}),
			2: byAttempt([]stall.Job{job("lint / lint", "success", ago(time.Hour)), job("required", "success", ago(time.Hour))}),
		}, flakyRun(2, built, ago(2*time.Hour), 1, "success"), flakyRun(1, built, ago(4*time.Hour), 1, "failure"))
		checkResult(t, flakyWith(t, src), stall.Result{Headline: notFlaky})
	})
}

// TestFlakySkipsStallAndRenovate reads runs of the stall and Renovate
// workflows, each failing once and passing once on main: both run on an
// unmoved main every day, and a red stall goes green once fixed, so their
// runs are passed over, and their jobs never read.
func TestFlakySkipsStallAndRenovate(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		of := func(r stall.Run, workflow string, id int64) stall.Run {
			r.Workflow, r.WorkflowID, r.Event = workflow, id, "schedule"
			return r
		}
		src := onRuns(nil,
			of(flakyRun(4, head, ago(time.Hour), 1, "success"), "renovate", renovateID),
			of(flakyRun(3, head, ago(2*time.Hour), 2, "failure"), "renovate", renovateID),
			of(flakyRun(2, head, ago(3*time.Hour), 1, "success"), "stall", stallID),
			of(flakyRun(1, head, ago(30*time.Hour), 1, "failure"), "stall", stallID),
		)
		checkResult(t, flakyWith(t, src), stall.Result{Headline: notFlaky})
		if len(src.read) > 0 {
			t.Errorf("read the jobs of %q, want none", src.read)
		}
	})
}

// TestFlakyFirstRun reads with no stall run before this one, so the window
// is the last 24 hours, and runs are listed from a day before that: a pair
// that finished within the 24 hours is flaky, and one before is not.
func TestFlakyFirstRun(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := onRuns(map[int64]map[int][]stall.Job{
			4: byAttempt([]stall.Job{job("build", "success", ago(21*time.Hour))}),
			3: byAttempt([]stall.Job{job("build", "failure", ago(22*time.Hour))}),
			2: byAttempt([]stall.Job{job("build", "success", ago(26*time.Hour))}),
			1: byAttempt([]stall.Job{job("build", "failure", ago(29*time.Hour))}),
		},
			flakyRun(4, built, ago(22*time.Hour), 1, "success"),
			flakyRun(3, built, ago(23*time.Hour), 1, "failure"),
			flakyRun(2, older, ago(27*time.Hour), 1, "success"),
			flakyRun(1, older, ago(30*time.Hour), 1, "failure"),
		)
		src.previous = time.Time{}
		checkResult(t, flakyWith(t, src), stall.Result{
			Stalled:  true,
			Headline: "Passed and failed on the same commit since 1999-12-31T00:00:00Z:",
			Details:  []string{"build / build on 3333333: failed in run 3, passed in run 4"},
		})
		if want := ago(48 * time.Hour); !src.listedSince.Equal(want) {
			t.Errorf("RunsSince asked since %v, want %v", src.listedSince, want)
		}
	})
}

// TestFlakyStraddlesWindow reads a failure that finished before the window
// and a pass on the same commit inside it, in two runs or in two attempts
// of one created before the window: flaky, reported on the day it ended.
func TestFlakyStraddlesWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jobs map[int64]map[int][]stall.Job
		runs []stall.Run
		want string
	}{
		{
			name: "two-runs",
			jobs: map[int64]map[int][]stall.Job{
				2: byAttempt([]stall.Job{job("build", "success", ago(time.Hour))}),
				1: byAttempt([]stall.Job{job("build", "failure", ago(29*time.Hour))}),
			},
			runs: []stall.Run{flakyRun(2, built, ago(2*time.Hour), 1, "success"), flakyRun(1, built, ago(30*time.Hour), 1, "failure")},
			want: "build / build on 3333333: failed in run 1, passed in run 2",
		},
		{
			name: "re-run",
			jobs: map[int64]map[int][]stall.Job{7: byAttempt(
				[]stall.Job{job("build", "failure", ago(29*time.Hour))},
				[]stall.Job{job("build", "success", ago(time.Hour))},
			)},
			runs: []stall.Run{flakyRun(7, built, ago(30*time.Hour), 2, "success")},
			want: "build / build on 3333333: failed in run 7 attempt 1, passed in run 7 attempt 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				src := onRuns(tt.jobs, tt.runs...)
				checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{tt.want}})
				if want := lastStall.Add(-day); !src.listedSince.Equal(want) {
					t.Errorf("RunsSince asked since %v, want %v", src.listedSince, want)
				}
			})
		})
	}
}

// TestFlakyBeforeWindow reads a failure and a pass on one commit that both
// finished before the window: the stall run before this one reported it,
// so this one does not.
func TestFlakyBeforeWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jobs map[int64]map[int][]stall.Job
		runs []stall.Run
	}{
		{
			name: "two-runs",
			jobs: map[int64]map[int][]stall.Job{
				2: byAttempt([]stall.Job{job("build", "success", ago(25*time.Hour))}),
				1: byAttempt([]stall.Job{job("build", "failure", ago(29*time.Hour))}),
			},
			runs: []stall.Run{flakyRun(2, built, ago(26*time.Hour), 1, "success"), flakyRun(1, built, ago(30*time.Hour), 1, "failure")},
		},
		{
			name: "re-run",
			jobs: map[int64]map[int][]stall.Job{7: byAttempt(
				[]stall.Job{job("build", "failure", ago(29*time.Hour))},
				[]stall.Job{job("build", "success", ago(21*time.Hour))},
			)},
			runs: []stall.Run{flakyRun(7, built, ago(30*time.Hour), 2, "success")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				checkResult(t, flakyWith(t, onRuns(tt.jobs, tt.runs...)), stall.Result{Headline: notFlaky})
			})
		})
	}
}

// TestFlakyReadsOnlyCandidates checks that jobs are read only for runs that
// could hold a flake: each run that failed, each run re-run, and each run
// of the same commit, workflow and event as one of those. A commit whose
// runs all passed at their first attempt has no failure, so its jobs are
// never read, and neither are a run of another workflow, or one another
// event started, on a commit with a failure.
func TestFlakyReadsOnlyCandidates(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		docs := flakyRun(4, built, ago(2*time.Hour), 1, "success")
		docs.Workflow, docs.WorkflowID = "docs", docsID
		push := flakyRun(7, built, ago(90*time.Minute), 1, "success")
		push.Event = "push"
		src := onRuns(map[int64]map[int][]stall.Job{
			2: byAttempt([]stall.Job{job("build", "failure", ago(3*time.Hour))}),
			3: byAttempt([]stall.Job{job("build", "success", ago(2*time.Hour))}),
			5: byAttempt([]stall.Job{job("build", "success", ago(4*time.Hour))}, []stall.Job{job("build", "success", ago(3*time.Hour))}),
		},
			flakyRun(6, head, ago(time.Hour), 1, "success"),
			push,
			flakyRun(5, older, ago(5*time.Hour), 2, "success"),
			docs,
			flakyRun(3, built, ago(3*time.Hour), 1, "success"),
			flakyRun(2, built, ago(4*time.Hour), 1, "failure"),
			flakyRun(1, head, ago(6*time.Hour), 1, "success"),
		)
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{
			"build / build on 3333333: failed in run 2, passed in run 3",
		}})
		if got, want := slices.Sorted(slices.Values(src.read)), []string{"2/1", "3/1", "5/1", "5/2"}; !slices.Equal(got, want) {
			t.Errorf("read the jobs of %q, want %q", got, want)
		}
	})
}

// TestFlakyNoSuchWorkflow checks that a stall or Renovate workflow file
// with no workflow fails the check, naming the file, rather than pass none
// of its runs over.
func TestFlakyNoSuchWorkflow(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"stall.yml", "renovate.yml"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				src := onRuns(nil, flakyRun(1, built, ago(time.Hour), 1, "success"))
				src.workflowIDs = maps.Clone(workflowIDs)
				delete(src.workflowIDs, file)
				got, err := stall.Flaky(t.Context(), src, &config)
				if err == nil || !strings.Contains(err.Error(), file) {
					t.Fatalf("Flaky() = %+v, %v; want an error naming %s", got, err, file)
				}
			})
		})
	}
}

// TestFlakyNoCompletion checks that a job that failed or passed with no
// time it finished fails the check, rather than be placed in or out of the
// window by a guess.
func TestFlakyNoCompletion(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := onRuns(map[int64]map[int][]stall.Job{1: byAttempt([]stall.Job{job("build", "failure", time.Time{})})},
			flakyRun(1, built, ago(time.Hour), 1, "failure"))
		got, err := stall.Flaky(t.Context(), src, &config)
		if err == nil || !strings.Contains(err.Error(), "build") || !strings.Contains(err.Error(), src.finished[0].URL) {
			t.Fatalf("Flaky() = %+v, %v; want an error naming the job and its run", got, err)
		}
	})
}

// TestFlakyOneValuePattern reads attempts in which every failing cell
// shares a matrix value that no passing cell has: one engine or one
// architecture failing, which is no flake, nor is the same failing again
// when re-run.
func TestFlakyOneValuePattern(t *testing.T) {
	t.Parallel()

	at := ago(time.Hour)
	tests := []struct {
		name     string
		attempts [][]stall.Job
	}{
		{
			name: "engine",
			attempts: [][]stall.Job{{
				job("test (amd64, podman)", "failure", at), job("test (arm64, podman)", "failure", at),
				job("test (amd64, docker)", "success", at), job("test (arm64, docker)", "success", at),
			}},
		},
		{
			name:     "arch",
			attempts: [][]stall.Job{{job("build (arm64)", "failure", at), job("build (amd64)", "success", at)}},
		},
		{
			name: "re-run-fails-again",
			attempts: [][]stall.Job{
				{
					job("test (amd64, podman)", "failure", ago(3*time.Hour)), job("test (arm64, podman)", "failure", ago(3*time.Hour)),
					job("test (amd64, docker)", "success", ago(3*time.Hour)), job("test (arm64, docker)", "success", ago(3*time.Hour)),
				},
				{
					job("test (amd64, podman)", "failure", at), job("test (arm64, podman)", "failure", at),
					job("test (amd64, docker)", "success", ago(3*time.Hour)), job("test (arm64, docker)", "success", ago(3*time.Hour)),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				src := onRuns(map[int64]map[int][]stall.Job{1: byAttempt(tt.attempts...)},
					flakyRun(1, built, ago(4*time.Hour), len(tt.attempts), "failure"))
				checkResult(t, flakyWith(t, src), stall.Result{Headline: notFlaky})
			})
		})
	}
}

// TestFlakySingleCellStillCounts reads one odd cell failing: each value of
// it, arm64 and podman, is in a cell that passed, so no one engine or
// architecture explains it, and it is a flake.
func TestFlakySingleCellStillCounts(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		at := ago(time.Hour)
		src := onRuns(map[int64]map[int][]stall.Job{1: byAttempt([]stall.Job{
			job("test (arm64, podman)", "failure", at),
			job("test (arm64, docker)", "success", at),
			job("test (amd64, podman)", "success", at),
		})}, flakyRun(1, built, ago(2*time.Hour), 1, "failure"))
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{
			"build / test on 3333333: failed in (arm64, podman), passed in (amd64, podman), (arm64, docker)",
		}})
	})
}

// TestFlakyOneValueButRerunPasses reads podman's cells alone failing, then
// passing when the failed jobs are re-run: the same cells failed and
// passed, so it is a flake, though the first attempt alone was not.
func TestFlakyOneValueButRerunPasses(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		first, rerun := ago(3*time.Hour), ago(time.Hour)
		docker := []stall.Job{job("test (amd64, docker)", "success", first), job("test (arm64, docker)", "success", first)}
		src := onRuns(map[int64]map[int][]stall.Job{7: byAttempt(
			append([]stall.Job{job("test (amd64, podman)", "failure", first), job("test (arm64, podman)", "failure", first)}, docker...),
			append([]stall.Job{job("test (amd64, podman)", "success", rerun), job("test (arm64, podman)", "success", rerun)}, docker...),
		)}, flakyRun(7, built, ago(4*time.Hour), 2, "success"))
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: flakyHeadline, Details: []string{
			"build / test on 3333333: failed in (amd64, podman) of attempt 1, (arm64, podman) of attempt 1, " +
				"passed in (amd64, podman) of attempt 2, (arm64, podman) of attempt 2",
		}})
	})
}

// TestFlakyAcrossEventsNotPaired reads a push run that passed and the daily
// slot that failed on the same commit: different events are not compared,
// since the slot's own red run reports what changed upstream.
func TestFlakyAcrossEventsNotPaired(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		push := flakyRun(1, built, ago(3*time.Hour), 2, "success")
		push.Event = "push"
		slot := flakyRun(2, built, ago(2*time.Hour), 1, "failure")
		slot.Event = "schedule"
		src := onRuns(map[int64]map[int][]stall.Job{
			1: byAttempt([]stall.Job{job("build", "success", ago(170*time.Minute))}, []stall.Job{job("build", "success", ago(150*time.Minute))}),
			2: byAttempt([]stall.Job{job("build", "failure", ago(time.Hour))}),
		}, slot, push)
		checkResult(t, flakyWith(t, src), stall.Result{Headline: notFlaky})
		if got, want := slices.Sorted(slices.Values(src.read)), []string{"1/1", "1/2", "2/1"}; !slices.Equal(got, want) {
			t.Errorf("read the jobs of %q, want %q", got, want)
		}
	})
}

// slotRun is a daily slot of main, numbered id: a finished scheduled run of
// the build workflow, created at created, that last changed at updated.
func slotRun(id int64, created time.Time, attempt int, conclusion string, updated time.Time) stall.Run {
	r := flakyRun(id, head, created, attempt, conclusion)
	r.Event, r.Updated = "schedule", updated
	return r
}

// dayOne is a source on which the slot of main failed and then passed when
// re-run, the day before epoch, with the stall run before epoch's a day
// earlier: the first of two stall runs, at epoch.
func dayOne() *source {
	src := onRuns(map[int64]map[int][]stall.Job{
		1: byAttempt([]stall.Job{job("build", "failure", ago(10*time.Hour))}, []stall.Job{job("build", "success", ago(8*time.Hour))}),
	}, slotRun(1, ago(11*time.Hour), 2, "success", ago(8*time.Hour)))
	src.previous, src.current = ago(day), epoch
	return src
}

// nextDay moves the bubble's clock and src on to the stall run a day after
// epoch, with run, the next slot, and its jobs.
func nextDay(src *source, run *stall.Run, jobs ...stall.Job) {
	time.Sleep(day)
	src.attempts[run.ID] = byAttempt(jobs)
	src.finished = append([]stall.Run{*run}, src.finished...)
	src.previous, src.current = epoch, epoch.Add(day)
}

// The headlines of the two stall runs that dayOne and nextDay make.
const (
	dayOneFlaky   = "Passed and failed on the same commit since 1999-12-31T00:00:00Z:"
	nextDayFlaky  = "Passed and failed on the same commit since 2000-01-01T00:00:00Z:"
	nextDayPassed = "no job passed and failed on the same commit since 2000-01-01T00:00:00Z"
)

// TestFlakyNextDaySlotNotRepeated reads the slot that failed and passed
// when re-run, reported by that day's stall run, and then the next day's
// slot of the same unmoved main, which passed: no new flake, so the next
// stall run reports nothing.
func TestFlakyNextDaySlotNotRepeated(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := dayOne()
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: dayOneFlaky, Details: []string{
			"build / build on 2222222: failed in run 1 attempt 1, passed in run 1 attempt 2",
		}})
		at := epoch.Add(12 * time.Hour)
		next := slotRun(2, epoch.Add(11*time.Hour), 1, "success", at)
		nextDay(src, &next, job("build", "success", at))
		checkResult(t, flakyWith(t, src), stall.Result{Headline: nextDayPassed})
	})
}

// TestFlakyNewFailureSameCommitReports reads the same, but the next day's
// slot failed again where it had passed: a new flake, which the next stall
// run reports.
func TestFlakyNewFailureSameCommitReports(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		src := dayOne()
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: dayOneFlaky, Details: []string{
			"build / build on 2222222: failed in run 1 attempt 1, passed in run 1 attempt 2",
		}})
		at := epoch.Add(12 * time.Hour)
		next := slotRun(2, epoch.Add(11*time.Hour), 1, "failure", at)
		nextDay(src, &next, job("build", "failure", at))
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: nextDayFlaky, Details: []string{
			"build / build on 2222222: failed in run 1 attempt 1, run 2, passed in run 1 attempt 2",
		}})
	})
}

// TestFlakyRunStillGoingAtListing reads a run whose flaky cells finished
// before a stall run listed the runs, while the run itself, its publish
// job, was still going, so that stall run did not list it. Its latest
// attempt's jobs count from when the run finished, so the next stall run
// reports it.
func TestFlakyRunStillGoingAtListing(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		finished := epoch.Add(30 * time.Minute)
		run := flakyRun(3, built, ago(2*time.Hour), 1, "failure")
		run.Updated = finished
		src := onRuns(map[int64]map[int][]stall.Job{3: byAttempt([]stall.Job{
			job("test (amd64, docker)", "failure", ago(90*time.Minute)),
			job("test (amd64, podman)", "success", ago(80*time.Minute)),
			job("test (arm64, docker)", "success", ago(80*time.Minute)),
			job("publish", "skipped", finished),
		})}, run)
		src.previous, src.current = ago(day), epoch
		checkResult(t, flakyWith(t, src), stall.Result{Headline: "no job passed and failed on the same commit since 1999-12-31T00:00:00Z"})

		time.Sleep(day)
		src.previous, src.current = epoch, epoch.Add(day)
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: nextDayFlaky, Details: []string{
			"build / test on 3333333: failed in (amd64, docker), passed in (amd64, podman), (arm64, docker)",
		}})
	})
}

// TestFlakyWindowEndsAtThisRun reads a flake that ended after this stall
// run was created but before it listed the runs: the window ends at its
// creation, so this run leaves it to the next, which reports it, once.
func TestFlakyWindowEndsAtThisRun(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		failed := flakyRun(1, built, ago(10*time.Minute), 1, "failure")
		failed.Updated = ago(4 * time.Minute)
		passed := flakyRun(2, built, ago(3*time.Minute), 1, "success")
		passed.Updated = ago(2 * time.Minute)
		src := onRuns(map[int64]map[int][]stall.Job{
			1: byAttempt([]stall.Job{job("build", "failure", ago(4*time.Minute))}),
			2: byAttempt([]stall.Job{job("build", "success", ago(2*time.Minute))}),
		}, passed, failed)
		created := ago(5 * time.Minute)
		src.previous, src.current = ago(day), created
		checkResult(t, flakyWith(t, src), stall.Result{Headline: "no job passed and failed on the same commit since 1999-12-31T00:00:00Z"})

		time.Sleep(day)
		src.previous, src.current = created, created.Add(day)
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: "Passed and failed on the same commit since 1999-12-31T23:55:00Z:", Details: []string{
			"build / build on 3333333: failed in run 1, passed in run 2",
		}})
	})
}

// TestFlakyGapAtWindowEnd reads flakes with one job inside the window and
// one in the gap between this stall run's creation, where the window ends,
// and its listing of the runs: a failure inside and a pass in the gap, a
// pass inside and a failure in the gap, and a re-run whose second attempt
// passed in the gap. A job in the gap is the next run's, so this run
// reports nothing, and the next reports each flake, once.
func TestFlakyGapAtWindowEnd(t *testing.T) {
	t.Parallel()

	inside, gap := ago(30*time.Minute), ago(2*time.Minute)
	twoRuns := func(first, second string) ([]stall.Run, map[int64]map[int][]stall.Job) {
		r1 := flakyRun(1, built, ago(40*time.Minute), 1, first)
		r1.Updated = inside
		r2 := flakyRun(2, built, ago(10*time.Minute), 1, second)
		r2.Updated = gap
		return []stall.Run{r2, r1}, map[int64]map[int][]stall.Job{
			1: byAttempt([]stall.Job{job("build", first, inside)}),
			2: byAttempt([]stall.Job{job("build", second, gap)}),
		}
	}
	rerun := flakyRun(7, built, ago(time.Hour), 2, "success")
	rerun.Updated = gap

	tests := []struct {
		name string
		runs []stall.Run
		jobs map[int64]map[int][]stall.Job
		want string
	}{
		{name: "failure-inside-pass-in-gap", want: "build / build on 3333333: failed in run 1, passed in run 2"},
		{name: "pass-inside-failure-in-gap", want: "build / build on 3333333: failed in run 2, passed in run 1"},
		{
			name: "rerun-in-gap",
			runs: []stall.Run{rerun},
			jobs: map[int64]map[int][]stall.Job{7: byAttempt(
				[]stall.Job{job("build", "failure", inside)},
				[]stall.Job{job("build", "success", gap)},
			)},
			want: "build / build on 3333333: failed in run 7 attempt 1, passed in run 7 attempt 2",
		},
	}
	tests[0].runs, tests[0].jobs = twoRuns("failure", "success")
	tests[1].runs, tests[1].jobs = twoRuns("success", "failure")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				atEpoch(t)
				src := onRuns(tt.jobs, tt.runs...)
				created := ago(5 * time.Minute)
				src.previous, src.current = ago(day), created
				checkResult(t, flakyWith(t, src), stall.Result{Headline: "no job passed and failed on the same commit since 1999-12-31T00:00:00Z"})

				time.Sleep(day)
				src.previous, src.current = created, created.Add(day)
				checkResult(t, flakyWith(t, src), stall.Result{
					Stalled: true, Headline: "Passed and failed on the same commit since 1999-12-31T23:55:00Z:", Details: []string{tt.want},
				})
			})
		})
	}
}

// TestFlakyEarlierAttemptStillGoingAtListing reads a run whose flaky cells
// finished before one stall run listed the runs, while a long job of the
// same attempt was still going, so that stall run did not list it; the
// failed cell was then re-run, and passed, before the next stall run. The
// first attempt's jobs count from when its last job finished, so the next
// stall run reports its flake.
func TestFlakyEarlierAttemptStillGoingAtListing(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		atEpoch(t)
		cells, scanned, rerun := ago(90*time.Minute), epoch.Add(30*time.Minute), epoch.Add(2*time.Hour)
		run := flakyRun(3, built, ago(2*time.Hour), 2, "success")
		run.Updated = rerun
		passing := []stall.Job{job("test (amd64, docker)", "success", cells), job("test (arm64, podman)", "success", cells), job("scan", "success", scanned)}
		src := onRuns(map[int64]map[int][]stall.Job{3: byAttempt(
			append([]stall.Job{job("test (arm64, docker)", "failure", cells)}, passing...),
			append([]stall.Job{job("test (arm64, docker)", "success", rerun)}, passing...),
		)}, run)
		src.previous, src.current = ago(day), epoch
		checkResult(t, flakyWith(t, src), stall.Result{Headline: "no job passed and failed on the same commit since 1999-12-31T00:00:00Z"})

		time.Sleep(day)
		src.previous, src.current = epoch, epoch.Add(day)
		checkResult(t, flakyWith(t, src), stall.Result{Stalled: true, Headline: nextDayFlaky, Details: []string{
			"build / test on 3333333: failed in (arm64, docker) of attempt 1, passed in (amd64, docker) of attempt 1, " +
				"(arm64, podman) of attempt 1, (arm64, docker) of attempt 2",
		}})
	})
}
