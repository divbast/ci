// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall_test

import (
	"context"
	"errors"
	"fmt"
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
	Published:        image,
	SlotWorkflow:     "build.yml",
	RenovateWorkflow: "renovate.yml",
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
	err      error     // returned by every call when set
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
	ahead := comparison{status: "ahead"}
	lost := func(url, sha string) string { return "lost slot: " + url + " built " + sha }
	unpublished := "main " + head + " is unpublished, :latest is " + published + ", and 2 or more slots were lost:"

	tests := []struct {
		name    string
		src     source
		revs    revisions
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
			// R14: with nothing published, the newest slot run, still
			// going, is where the days with no slot run count from. It is
			// not lost, since it has not finished.
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
				got, err := stall.Slots(t.Context(), &tt.src, tt.revs, &config)
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
