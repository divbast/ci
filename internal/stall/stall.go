// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package stall finds the ways a repository's updates stop flowing without
// anything failing loudly: a Renovate pull request open too long, one red
// or pending too long, Renovate itself silent, daily slots that should
// have published main and did not, a dependency Renovate failed to look
// up, an update left waiting, which only its Dependency Dashboard shows,
// and a job that both failed and passed on one commit.
//
// Each check reads the time from [time.Now] and the repository through a
// [Source], and says what it found in a [Result].
package stall

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
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
	// StarvedDays is how many days an update may wait on the Dependency
	// Dashboard.
	StarvedDays int
	// Published is the image the daily slot publishes, such as
	// ghcr.io/divbast/librespeed:latest.
	Published string
	// SlotWorkflow is the workflow file whose scheduled runs on main are
	// the daily slots, such as build.yml.
	SlotWorkflow string
	// RenovateWorkflow is the workflow file that runs Renovate, such as
	// renovate.yml.
	RenovateWorkflow string
	// StallWorkflow is the workflow file whose scheduled runs run these
	// checks, such as stall.yml.
	StallWorkflow string
	// ContentGated says the slot workflow publishes only when the image's
	// content moved, as divbast-publish-decision's -content-gated does, so
	// that once the image is published, a slot run can succeed and leave
	// an older commit published.
	ContentGated bool
	// SlotJob, when set, names the job in each slot run that publishes
	// the image, as GitHub names it in the run, such as "publish
	// (baikal)". A content-gated slot then reads that job's conclusion
	// rather than the whole run's, so a run that went red elsewhere, in
	// another image's build say, is not lost when this one's job
	// succeeded. Only a content-gated slot reads a conclusion at all.
	SlotJob string
}

// ErrNoJob marks a slot run with jobs, none of them the one
// [Config.SlotJob] names, nor one whose unexpanded name stands for it: a
// name written wrong, which would otherwise read every run as lost, or
// none.
var ErrNoJob = errors.New("no such job in the slot run")

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

// Run is a run of a workflow: of the slot workflow, or any of the
// repository's.
type Run struct {
	// ID is the run's ID, as GitHub numbers its runs.
	ID int64
	// HeadSHA is the commit it built.
	HeadSHA string
	// Workflow is its workflow's name, as GitHub shows it, and WorkflowID
	// its workflow's ID. Only [Source.RunsSince] gives them.
	Workflow   string
	WorkflowID int64
	// Event is what started it, as GitHub puts it, such as "push" or
	// "schedule". Only [Source.RunsSince] gives it.
	Event string
	// Attempt is its latest attempt, counted from 1: a re-run keeps the
	// run and adds an attempt. Only [Source.RunsSince] gives it.
	Attempt int
	// Updated is when it last changed: once it has finished, when its
	// latest attempt finished. Only [Source.RunsSince] gives it.
	Updated time.Time
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
	// Jobs returns the jobs of run's latest attempt, each by its name as
	// GitHub shows it in the run, with its conclusion and when it
	// finished. A run that never started has none.
	Jobs(ctx context.Context, run *Run) ([]Job, error)
	// MainSHA returns the commit main is at.
	MainSHA(ctx context.Context) (string, error)
	// Compare returns how head stands against base, as GitHub's compare
	// API puts it ("ahead", "behind", "identical" or "diverged"), and the
	// committer date of the first commit on head's line after base, or the
	// zero time if there is none.
	Compare(ctx context.Context, base, head string) (status string, firstCommit time.Time, err error)
	// RepoCreated returns when the repository was created.
	RepoCreated(ctx context.Context) (time.Time, error)
	// Dashboards returns the open issues Renovate made titled exactly
	// [DashboardTitle].
	Dashboards(ctx context.Context) ([]Issue, error)
	// DashboardHistory returns the bodies the issue numbered number has
	// had, newest first, each as it stood after its edit. It reaches back
	// past since: its last edit is the newest made at or before since,
	// when there is one. A history that ends before since ends with the
	// oldest edit there is, so it says how far back it reaches, and an
	// issue never edited has one edit, its creation. GitHub keeps no more
	// than 100 edits of an issue, the original body and the latest 99, so
	// once an issue has 100, the original body is left out: the edits after
	// it may be gone, and the history ends with the oldest edit GitHub kept
	// after it. A line is never read as older than the edits kept show.
	DashboardHistory(ctx context.Context, number int, since time.Time) ([]DashboardEdit, error)
	// WorkflowCreated returns when the workflow in file, such as
	// build.yml, was created.
	WorkflowCreated(ctx context.Context, file string) (time.Time, error)
	// WorkflowID returns the ID of the workflow in file, such as
	// stall.yml, and fails, naming file, when there is none.
	WorkflowID(ctx context.Context, file string) (int64, error)
	// RunsSince returns every finished run created at or after since, of
	// every workflow, each with its workflow, event, latest attempt and
	// when it last changed.
	RunsSince(ctx context.Context, since time.Time) ([]Run, error)
	// PreviousRunStart returns when the run of workflow before the one
	// this check runs in was created, and when this one was. Either is the
	// zero time when there is none, or it is not known.
	PreviousRunStart(ctx context.Context, workflow string) (previous, current time.Time, err error)
	// AttemptJobs returns the jobs of run's attempt numbered attempt, as
	// Jobs does the latest's.
	AttemptJobs(ctx context.Context, run *Run, attempt int) ([]Job, error)
}

// DashboardTitle is the title of Renovate's Dependency Dashboard, by which
// Renovate itself finds its own, exactly.
const DashboardTitle = "Dependency Dashboard"

// Issue is an open issue of Renovate's: its number, title, body in
// Markdown, and page.
type Issue struct {
	Number           int
	Title, Body, URL string
}

// DashboardEdit is a Dependency Dashboard's whole body as it stood after
// the edit made at EditedAt.
type DashboardEdit struct {
	// EditedAt is when the edit was made. A history's oldest edit can be
	// the issue's creation.
	EditedAt time.Time
	// Body is the issue's whole body in Markdown after the edit.
	Body string
}

// Job is a job of a run.
type Job struct {
	// Name is the job's name as GitHub shows it in the run: a matrix
	// job's expanded, such as "publish (baikal)", or, when GitHub skipped
	// or cancelled the job before expanding its matrix, unexpanded, such
	// as "publish (${{ matrix.app }})".
	Name string
	// Conclusion is how it ended, as GitHub puts it, such as "success" or
	// "skipped".
	Conclusion string
	// Completed is when it finished, and the zero time until it has.
	Completed time.Time
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

// lookupSentence opens the line on which Renovate lists the dependencies
// it failed to look up, each backticked, on a Dependency Dashboard. Its
// other warnings share the section's heading but never the sentence, the
// one stable marker Renovate writes; its own tests pin it.
const lookupSentence = "Renovate failed to look up the following dependencies:"

// backticked is one backticked item of Renovate's.
var backticked = regexp.MustCompile("`([^`]+)`")

// lookupPersistence is how long a Dependency Dashboard must have listed
// the same failed lookup before it is a stall. A lookup can fail once, a
// registry briefly unreachable say, and clear on Renovate's next run.
const lookupPersistence = 24 * time.Hour

// Lookups finds lookups Renovate failed, on any open Dependency Dashboard,
// that the dashboard has listed for lookupPersistence, by its edits: a
// datasource that answered nothing, or a digest it could not resolve,
// leaves that dependency where it is, and only the dashboard says so.
// Each is a detail, and so is the list of files its line names. A lookup
// not yet seen listed that long is named, and is no stall: it may be
// younger, or listed on a dashboard GitHub kept too few edits of to show.
// A line with the sentence and nothing backticked is quoted whole, at
// once, whatever the history: a format that drifted fails closed. Beside
// such a line, a history that cannot be read is a detail, not an error
// that would hide the line.
//
// With no open dashboard, failed lookups cannot be seen: once Renovate has
// succeeded, which reopens or remakes its dashboard on every run, that is
// a stall. Before its first success, the renovate check owns the case.
func Lookups(ctx context.Context, s Source, c *Config) (Result, error) {
	dashboards, err := s.Dashboards(ctx)
	if err != nil {
		return Result{}, err
	}
	if len(dashboards) == 0 {
		return noDashboard(ctx, s, c, "failed lookups")
	}
	now := time.Now()
	lines := make([][]lookupLine, len(dashboards))
	unreadable := false
	for i := range dashboards {
		lines[i] = failedLookups(dashboards[i].Body)
		unreadable = unreadable || slices.ContainsFunc(lines[i], func(l lookupLine) bool { return l.unreadable != "" })
	}
	var urls, numbers, failed, newer []string
	for i := range dashboards {
		d := &dashboards[i]
		numbers = append(numbers, "#"+strconv.Itoa(d.Number))
		if len(lines[i]) == 0 {
			continue
		}
		lasting, young, err := lastingLookups(ctx, s, d, lines[i], now, unreadable)
		if err != nil {
			return Result{}, err
		}
		if len(lasting) > 0 {
			urls = append(urls, d.URL)
			failed = append(failed, lasting...)
		}
		newer = append(newer, young...)
	}
	if len(failed) > 0 {
		return Result{Stalled: true, Headline: "Renovate failed lookups, by the Dependency Dashboard " + strings.Join(urls, ", ") + ":", Details: failed}, nil
	}
	where := "on the Dependency Dashboard " + strings.Join(numbers, ", ")
	if len(newer) > 0 {
		for i, item := range newer {
			newer[i] = strconv.Quote(item)
		}
		return Result{Headline: fmt.Sprintf("no failed Renovate lookup listed for %d hours %s; not yet seen listed that long: %s",
			int(lookupPersistence.Hours()), where, strings.Join(newer, ", "))}, nil
	}
	return Result{Headline: "no failed Renovate lookup " + where}, nil
}

// noDashboard is what a check that reads the Dependency Dashboard finds
// when none is open: what it reads there, unseen, cannot be seen. Once
// c.RenovateWorkflow has succeeded, which reopens or remakes the dashboard
// on every run, that is a stall. Before its first success, the renovate
// check owns the case.
func noDashboard(ctx context.Context, s Source, c *Config, unseen string) (Result, error) {
	last, ok, err := s.LastSuccess(ctx, c.RenovateWorkflow)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Headline: "no Dependency Dashboard yet, and no successful Renovate run to have made one"}, nil
	}
	return Result{
		Stalled:  true,
		Headline: "No open Dependency Dashboard by divbast-renovate, so " + unseen + " cannot be seen:",
		Details:  []string{fmt.Sprintf("no open issue titled %q; Renovate last succeeded %s", DashboardTitle, timestamp(last))},
	}, nil
}

// lastingLookups returns, from the lines on dashboard d that list failed
// lookups, the details of a stall: each lookup d has listed for
// lookupPersistence, then the files of its line, and each line it cannot
// read. It returns the lookups not yet seen listed that long apart. It
// reads d's history only for a line it can read, and fails if it cannot,
// unless unreadable says some dashboard has a line it cannot read, which
// stalls whatever the history says: then the error is a detail in place
// of the lookups that history was read for.
func lastingLookups(ctx context.Context, s Source, d *Issue, lines []lookupLine, now time.Time, unreadable bool) (lasting, newer []string, err error) {
	var edits []DashboardEdit
	var historyErr error
	read := false
	for _, l := range lines {
		if l.unreadable != "" {
			lasting = append(lasting, "unreadable: "+l.unreadable)
			continue
		}
		if !read {
			edits, historyErr = s.DashboardHistory(ctx, d.Number, now.Add(-lookupPersistence))
			read = true
			if historyErr != nil {
				if !unreadable {
					return nil, nil, historyErr
				}
				lasting = append(lasting, fmt.Sprintf("could not read the history of #%d: %v", d.Number, historyErr))
			}
		}
		if historyErr != nil {
			continue
		}
		kept := false
		for _, item := range l.lookups {
			if persistent(item, d.Body, edits, now, lookupPersistence) {
				lasting = append(lasting, item)
				kept = true
			} else {
				newer = append(newer, item)
			}
		}
		if kept && len(l.files) > 0 {
			lasting = append(lasting, "files affected: "+strings.Join(l.files, ", "))
		}
	}
	return lasting, newer, nil
}

// persistent reports whether a dashboard has listed item, a failed
// lookup, for window up to now. It has if item is listed in current, the
// dashboard's body now, in each of its edits made after now-window, and
// in the newest edit made at or before then, the body that stood at
// now-window: if listedSince puts the start of its listing at now-window
// or earlier. The files item is in may have changed. A history with no
// edit that old cannot show what stood then, whether the dashboard is
// younger than window or GitHub kept too few of its edits, so then item
// is not persistent.
func persistent(item, current string, edits []DashboardEdit, now time.Time, window time.Duration) bool {
	since, ok := listedSince(current, edits, func(body string) bool { return listsLookup(body, item) })
	return ok && !since.After(now.Add(-window))
}

// listedSince returns when a dashboard began to list something without a
// break, by its edits: the time of the oldest edit in the unbroken run of
// edits, counted back from the newest, each of whose bodies lists it, as
// listed says. It is false when current, the dashboard's body now, does
// not list it, or the newest edit does not. The edits may come in any
// order. A history GitHub cut short ends the run at the oldest edit it
// kept, so what it returns is never earlier than those edits show.
func listedSince(current string, edits []DashboardEdit, listed func(body string) bool) (time.Time, bool) {
	if !listed(current) {
		return time.Time{}, false
	}
	var since time.Time
	found := false
	for _, e := range slices.SortedStableFunc(slices.Values(edits), func(a, b DashboardEdit) int { return b.EditedAt.Compare(a.EditedAt) }) {
		if !listed(e.Body) {
			break
		}
		since, found = e.EditedAt, true
	}
	return since, found
}

// listsLookup reports whether body lists item as a failed lookup.
func listsLookup(body, item string) bool {
	return slices.ContainsFunc(failedLookups(body), func(l lookupLine) bool { return slices.Contains(l.lookups, item) })
}

// lookupLine is a line on which a dashboard lists failed lookups: the
// lookups it names, and the files that the same quote names below it. A
// line with nothing backticked is unreadable: it is kept whole, trimmed,
// with neither.
type lookupLine struct {
	lookups, files []string
	unreadable     string
}

// failedLookups returns the lines on which a dashboard's body lists
// lookups as failed.
func failedLookups(body string) []lookupLine {
	// A web edit saves the body with CRLF until Renovate's next rewrite:
	// each line is trimmed, so a line's \r goes with its spaces
	lines := strings.Split(body, "\n")
	var found []lookupLine
	for i, line := range lines {
		rest, ok := strings.CutPrefix(unquote(line), lookupSentence)
		if !ok {
			continue
		}
		items := backticked.FindAllStringSubmatch(rest, -1)
		if len(items) == 0 {
			found = append(found, lookupLine{unreadable: strings.TrimSpace(line)})
			continue
		}
		var l lookupLine
		for _, m := range items {
			l.lookups = append(l.lookups, m[1])
		}
		// The files follow in the same quote
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(strings.TrimSpace(next), ">") {
				break
			}
			if files, ok := strings.CutPrefix(unquote(next), "Files affected:"); ok {
				for _, m := range backticked.FindAllStringSubmatch(files, -1) {
					l.files = append(l.files, m[1])
				}
				break
			}
		}
		found = append(found, l)
	}
	return found
}

// unquote is a Markdown quote's line without its marker.
func unquote(line string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), ">"))
}

// waitingSections are the headings of the Dependency Dashboard's sections
// that list updates left waiting, as Renovate 45 writes them
// (dependency-dashboard.ts): updates whose status checks are pending,
// their release age among them, and updates their schedule holds back.
var waitingSections = []string{"## Pending Status Checks", "## Awaiting Schedule"}

// waitingItem is the line on which a Dependency Dashboard lists an update
// in one of waitingSections, trimmed: its checkbox, ticked or not, the
// comment that names the update's branch, and its title, a link to its
// pull request when it has one.
var waitingItem = regexp.MustCompile(`^- \[[ x]\] <!-- [a-zA-Z]+-branch=(\S+) -->(.*)$`)

// bulkItem is the line, below two updates or more, that creates them all
// at once: no update itself.
var bulkItem = regexp.MustCompile(`^- \[[ x]\] <!-- create-all-[a-z-]+ -->`)

// htmlComment and markdownLink are what an update's title is shown
// without, and with the link's text in its place. The text runs to the
// last "](" on the line, so a bracket in the title, as in a security
// update's "[SECURITY]", stays in it: Renovate writes at most one link on
// an update's line.
var (
	htmlComment  = regexp.MustCompile(`<!--.*?-->`)
	markdownLink = regexp.MustCompile(`\[(.*)\]\([^)\s]*\)`)
)

// pendingUpdate is an update a Dependency Dashboard lists as waiting. Its
// branch is what it is known by: the same from one version or digest to
// the next. Its text is its line as shown, without its checkbox, comment
// and link.
type pendingUpdate struct {
	branch, text string
}

// pendingUpdates returns the updates a Dependency Dashboard's body lists
// in waitingSections, each once, and what it cannot read there: each line
// of the list that is not one of Renovate's updates, trimmed, and each
// heading with no update under it, which Renovate never writes. A section
// runs to the next heading of its level or above, or to a rule, which
// opens Renovate's warnings and a footer.
func pendingUpdates(body string) (items []pendingUpdate, unreadable []string) {
	// A web edit saves the body with CRLF until Renovate's next rewrite:
	// each line is trimmed, so a line's \r goes with its spaces
	var heading string
	read := false
	end := func() {
		if heading != "" && !read {
			unreadable = append(unreadable, heading+": no update under it in Renovate's form")
		}
		heading = ""
	}
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "## ") || line == "---" {
			end()
			if slices.Contains(waitingSections, line) {
				heading, read = line, false
			}
			continue
		}
		if heading == "" || !strings.HasPrefix(line, "- ") || bulkItem.MatchString(line) {
			continue
		}
		m := waitingItem.FindStringSubmatch(line)
		if m == nil {
			unreadable = append(unreadable, line)
			continue
		}
		read = true
		if slices.ContainsFunc(items, func(u pendingUpdate) bool { return u.branch == m[1] }) {
			continue
		}
		text := strings.TrimSpace(markdownLink.ReplaceAllString(htmlComment.ReplaceAllString(m[2], ""), "$1"))
		if text == "" {
			text = m[1]
		}
		items = append(items, pendingUpdate{branch: m[1], text: text})
	}
	end()
	return items, unreadable
}

// pendingIn reports whether body lists the update on branch as waiting.
func pendingIn(body, branch string) bool {
	items, _ := pendingUpdates(body)
	return slices.ContainsFunc(items, func(u pendingUpdate) bool { return u.branch == branch })
}

// Starved finds updates that each open Dependency Dashboard has listed as
// waiting, under Pending Status Checks or Awaiting Schedule, for more than
// c.StarvedDays days: an update whose release age is never reached, its
// tag re-pushed more often than the age, or one a schedule holds, leaves
// that dependency where it is, and nothing fails. Each is named by its line
// now, with when it was first listed: the oldest edit, by the dashboard's
// history back c.StarvedDays days and one more, in the unbroken run of
// edits up to now that list it. An update is known by its branch, so a
// newer version or digest, a pull request opened, or a move from one
// section to the other keeps its clock; an update that leaves both
// sections and comes back starts it again. A history GitHub cut short
// counts from its oldest edit, never earlier.
//
// What it cannot read in those sections, it quotes, at once, whatever the
// history: a format that drifted fails closed. Beside that, a history that
// cannot be read is a detail, not an error that would hide it. With no
// open dashboard it behaves as [Lookups] does.
func Starved(ctx context.Context, s Source, c *Config) (Result, error) {
	dashboards, err := s.Dashboards(ctx)
	if err != nil {
		return Result{}, err
	}
	if len(dashboards) == 0 {
		return noDashboard(ctx, s, c, "updates waiting on it")
	}
	now := time.Now()
	items := make([][]pendingUpdate, len(dashboards))
	unreadable := make([][]string, len(dashboards))
	anyUnreadable := false
	for i := range dashboards {
		items[i], unreadable[i] = pendingUpdates(dashboards[i].Body)
		anyUnreadable = anyUnreadable || len(unreadable[i]) > 0
	}
	limit := days(c.StarvedDays)
	var numbers, starved []string
	for i := range dashboards {
		d := &dashboards[i]
		numbers = append(numbers, "#"+strconv.Itoa(d.Number))
		for _, u := range unreadable[i] {
			starved = append(starved, "unreadable: "+u)
		}
		if len(items[i]) == 0 {
			continue
		}
		edits, err := s.DashboardHistory(ctx, d.Number, now.Add(-days(c.StarvedDays+1)))
		if err != nil {
			if !anyUnreadable {
				return Result{}, err
			}
			starved = append(starved, fmt.Sprintf("could not read the history of #%d: %v", d.Number, err))
			continue
		}
		for _, u := range items[i] {
			since, ok := listedSince(d.Body, edits, func(body string) bool { return pendingIn(body, u.branch) })
			if ok && time.Since(since) > limit {
				starved = append(starved, fmt.Sprintf("%s (since %s)", u.text, timestamp(since)))
			}
		}
	}
	if len(starved) > 0 {
		return Result{Stalled: true, Headline: fmt.Sprintf("Waiting on the Dependency Dashboard for more than %d days:", c.StarvedDays), Details: starved}, nil
	}
	return Result{Headline: fmt.Sprintf("no update waiting more than %d days on the Dependency Dashboard %s", c.StarvedDays, strings.Join(numbers, ", "))}, nil
}

// flakyLookback is how long before its window a flaky check lists runs
// from: a job that failed then pairs with one on the same commit that
// passed inside the window, as when a run is re-run hours later.
const flakyLookback = 24 * time.Hour

// firstWindow is the window of a flaky check with no stall run before it.
const firstWindow = 24 * time.Hour

// Flaky finds a job that both failed and passed on one commit, in runs of
// one workflow that one kind of event started. A test that fails at random
// fails a pull request, someone re-runs it, and nothing else records that
// it happened.
//
// Jobs are the same job when they ran on the same commit, in the same
// workflow, for the same event, such as "push" or "schedule", under the
// same name before its matrix cell, the part from " (". Runs of different
// events are never compared: a push run that passed and the daily slot
// that failed on one commit are no flake, since the slot's own red run
// reports what changed upstream. Each job that failed or passed counts, in
// every attempt of each run; cancelled and skipped jobs, and the [Required]
// job, which fails whenever a job it needs does, do not. A job that a
// re-run of the failed jobs lists again, with the time and conclusion it
// had, counts once, in the attempt that ran it.
//
// A failure and a pass pair as a flake in two ways. In one attempt of a
// run, a failing cell and a passing one pair unless every failing cell
// shares a matrix value, one of the comma-separated parts of its cell,
// that no passing cell has: every podman cell failing while every docker
// one passes is a fault of that engine, not a flake. Across runs or
// attempts, only the same cell pairs: the same job or cell failed, and
// then passed, or the other way round.
//
// The window runs from when the stall workflow's previous run was created,
// or 24 hours before this run with none, to when this run was created, or
// now when gh does not list it. A flake is reported when one of its paired
// failures, or its earliest paired pass, finished inside the window: the
// moment it first both failed and passed, or a new failure of it on a
// later day, which is a new flake. So each is reported once, by the stall
// run whose window holds that moment. A job finished when gh says it did,
// or when its attempt finished, if later: the run, for its latest attempt,
// and the attempt's last job, for an earlier one. A run still going when
// one stall run lists the runs is listed only by the next, even when it
// was re-run in between. A job that finished after the window's end, in
// the moments before this run listed the runs, is left out, so that the
// next run pairs it. Runs are listed from a day before the window, so
// that a job that failed then still pairs with one that passed inside it.
// The window starts at the previous stall run whether or not that run's
// flaky check ran or succeeded: a window it missed is not read again.
//
// The stall and Renovate workflows' runs are passed over: both run on an
// unmoved main every day. Jobs are read only for runs that could hold a
// flake, as flakyCandidates says.
func Flaky(ctx context.Context, s Source, c *Config) (Result, error) {
	passOver := make(map[int64]bool, 2)
	for _, file := range []string{c.StallWorkflow, c.RenovateWorkflow} {
		id, err := s.WorkflowID(ctx, file)
		if err != nil {
			return Result{}, err
		}
		passOver[id] = true
	}
	start, end, err := s.PreviousRunStart(ctx, c.StallWorkflow)
	if err != nil {
		return Result{}, err
	}
	if end.IsZero() {
		end = time.Now()
	}
	if start.IsZero() {
		start = end.Add(-firstWindow)
	}
	runs, err := s.RunsSince(ctx, start.Add(-flakyLookback))
	if err != nil {
		return Result{}, err
	}
	groups, err := flakyGroups(ctx, s, flakyCandidates(runs, passOver))
	if err != nil {
		return Result{}, err
	}
	var flaky []string
	for _, g := range groups {
		// A job that finished after this run was created, before it listed
		// the runs, is the next run's to pair
		g.jobs = slices.DeleteFunc(g.jobs, func(j flakyJob) bool { return j.at.After(end) })
		failed, passed := g.paired()
		if reportedIn(failed, passed, start, end) {
			flaky = append(flaky, g.line(failed, passed))
		}
	}
	if len(flaky) > 0 {
		return Result{Stalled: true, Headline: "Passed and failed on the same commit since " + timestamp(start) + ":", Details: flaky}, nil
	}
	return Result{Headline: "no job passed and failed on the same commit since " + timestamp(start)}, nil
}

// commitRuns is what the runs of one commit, in one workflow, for one
// event, share.
type commitRuns struct {
	sha      string
	workflow int64
	event    string
}

// flakyCandidates returns, in order, the runs whose jobs could hold a
// flake, none of a workflow passOver holds: each run that failed, each run
// re-run, whose earlier attempt may have failed, and each run of the same
// commit, workflow and event as one of those. A flake needs a job that
// failed, and such a job almost always fails its run. A run cancelled after
// one of its jobs failed ends cancelled, not failed, so its failure is read
// only when another run of its commit, workflow and event is.
func flakyCandidates(runs []Run, passOver map[int64]bool) []*Run {
	suspect := make(map[commitRuns]bool)
	for i := range runs {
		r := &runs[i]
		if !passOver[r.WorkflowID] && (r.Conclusion == "failure" || r.Attempt > 1) {
			suspect[commitRuns{r.HeadSHA, r.WorkflowID, r.Event}] = true
		}
	}
	var out []*Run
	for i := range runs {
		if r := &runs[i]; suspect[commitRuns{r.HeadSHA, r.WorkflowID, r.Event}] {
			out = append(out, r)
		}
	}
	return out
}

// flakyKey is what makes jobs the same job: the commit, the workflow and
// the event, and the name before its matrix cell.
type flakyKey struct {
	commitRuns
	job string
}

// flakyJob is a job that failed or passed: the run and attempt it ran in,
// its matrix cell, the values in it, and when it finished.
type flakyJob struct {
	run     int64
	attempt int
	cell    string
	values  []string
	failed  bool
	at      time.Time
}

// flakyGroup is the jobs, each failed or passed, that are one job, and the
// name of their workflow.
type flakyGroup struct {
	key      flakyKey
	workflow string
	jobs     []flakyJob
}

// flakyGroups reads the jobs of every attempt of each run, and returns
// them grouped into the same job, ordered by workflow, job, commit and
// event. A job that failed or passed with no time it finished is an error,
// since the time decides its window.
func flakyGroups(ctx context.Context, s Source, runs []*Run) ([]*flakyGroup, error) {
	byKey := make(map[flakyKey]*flakyGroup)
	for _, run := range runs {
		jobs, err := runJobs(ctx, s, run)
		if err != nil {
			return nil, err
		}
		for i := range jobs {
			j := &jobs[i]
			if j.Name == Required || (j.Conclusion != "failure" && j.Conclusion != "success") {
				continue
			}
			if j.Completed.IsZero() {
				return nil, fmt.Errorf("the run %s: its job %q ended as %s at no time GitHub gives", run.URL, j.Name, j.Conclusion)
			}
			at := j.Completed
			if j.finished.After(at) {
				at = j.finished
			}
			name, cell, values := matrixCell(j.Name)
			key := flakyKey{commitRuns{run.HeadSHA, run.WorkflowID, run.Event}, name}
			g, ok := byKey[key]
			if !ok {
				g = &flakyGroup{key: key, workflow: run.Workflow}
				byKey[key] = g
			}
			g.jobs = append(g.jobs, flakyJob{run: run.ID, attempt: j.attempt, cell: cell, values: values, failed: j.Conclusion == "failure", at: at})
		}
	}
	return slices.SortedFunc(maps.Values(byKey), func(a, b *flakyGroup) int {
		return cmp.Or(strings.Compare(a.workflow, b.workflow), strings.Compare(a.key.job, b.key.job),
			strings.Compare(a.key.sha, b.key.sha), strings.Compare(a.key.event, b.key.event))
	}), nil
}

// matrixCell splits a job's name into the name before its matrix cell, the
// cell, such as "(amd64, docker)", and the values in it, such as amd64 and
// docker. A name with no cell has neither.
func matrixCell(job string) (name, cell string, values []string) {
	name, rest, ok := strings.Cut(job, " (")
	if !ok {
		return job, "", nil
	}
	cell = "(" + rest
	for v := range strings.SplitSeq(strings.TrimSuffix(rest, ")"), ",") {
		values = append(values, strings.TrimSpace(v))
	}
	return name, cell, values
}

// attemptJob is a job of the attempt it ran in, with when that attempt
// finished.
type attemptJob struct {
	Job
	attempt  int
	finished time.Time
}

// runJobs returns the jobs of every attempt of run, oldest first. A re-run
// of the failed jobs lists the others again in its attempt, as new jobs
// with the times and conclusions they had: each is kept once, in the
// earliest attempt that lists it, the one that ran it.
//
// Each job carries when its attempt finished: for the latest attempt, when
// the run last changed, and for an earlier one, when the last job its
// listing holds finished, whatever its conclusion, which is when the run
// finished that attempt.
func runJobs(ctx context.Context, s Source, run *Run) ([]attemptJob, error) {
	type ran struct {
		name, conclusion string
		completed        int64
	}
	seen := make(map[ran]bool)
	var out []attemptJob
	latest := max(run.Attempt, 1)
	for n := 1; n <= latest; n++ {
		var jobs []Job
		var err error
		if n == latest {
			jobs, err = s.Jobs(ctx, run)
		} else {
			jobs, err = s.AttemptJobs(ctx, run, n)
		}
		if err != nil {
			return nil, fmt.Errorf("the run %s: %w", run.URL, err)
		}
		finished := run.Updated
		if n < latest {
			finished = time.Time{}
			for _, j := range jobs {
				if j.Completed.After(finished) {
					finished = j.Completed
				}
			}
		}
		for _, j := range jobs {
			k := ran{j.Name, j.Conclusion, j.Completed.UnixMicro()}
			if !seen[k] {
				seen[k] = true
				out = append(out, attemptJob{Job: j, attempt: n, finished: finished})
			}
		}
	}
	return out, nil
}

// paired returns the failures and the passes of g that pair as a flake,
// each in g's order. In one attempt of a run, every failure pairs with
// every pass unless the attempt's failures share a value no pass in it
// has; across runs or attempts, a failure pairs with a pass of the same
// cell.
func (g *flakyGroup) paired() (failed, passed []flakyJob) {
	oneValue := make(map[[2]int64]bool)
	for _, j := range g.jobs {
		k := [2]int64{j.run, int64(j.attempt)}
		if _, done := oneValue[k]; !done {
			oneValue[k] = g.oneValue(j.run, j.attempt)
		}
	}
	inFailed := make([]bool, len(g.jobs))
	inPassed := make([]bool, len(g.jobs))
	for i, f := range g.jobs {
		for k, p := range g.jobs {
			if !f.failed || p.failed {
				continue
			}
			sameAttempt := f.run == p.run && f.attempt == p.attempt
			if (sameAttempt && !oneValue[[2]int64{f.run, int64(f.attempt)}]) || (!sameAttempt && f.cell == p.cell) {
				inFailed[i], inPassed[k] = true, true
			}
		}
	}
	for i, j := range g.jobs {
		switch {
		case inFailed[i]:
			failed = append(failed, j)
		case inPassed[i]:
			passed = append(passed, j)
		}
	}
	return failed, passed
}

// oneValue reports whether, in the attempt of run numbered attempt, g's
// failures all share a matrix value that none of its passes has: one
// engine or architecture failing, as every one of its cells does.
func (g *flakyGroup) oneValue(run int64, attempt int) bool {
	var failed, passed [][]string
	for _, j := range g.jobs {
		switch {
		case j.run != run || j.attempt != attempt:
		case j.failed:
			failed = append(failed, j.values)
		default:
			passed = append(passed, j.values)
		}
	}
	if len(failed) == 0 || len(passed) == 0 {
		return false
	}
	for _, v := range failed[0] {
		has := func(values []string) bool { return slices.Contains(values, v) }
		if !slices.ContainsFunc(failed, func(f []string) bool { return !has(f) }) && !slices.ContainsFunc(passed, has) {
			return true
		}
	}
	return false
}

// reportedIn reports whether a flake, its paired failures and passes, is
// reported by the stall run whose window runs from start to end: when one
// of its failures, or the earliest of its passes, finished inside it.
func reportedIn(failed, passed []flakyJob, start, end time.Time) bool {
	if len(failed) == 0 || len(passed) == 0 {
		return false
	}
	inside := func(t time.Time) bool { return t.After(start) && !t.After(end) }
	first := slices.MinFunc(passed, func(a, b flakyJob) int { return a.at.Compare(b.at) })
	return inside(first.at) || slices.ContainsFunc(failed, func(j flakyJob) bool { return inside(j.at) })
}

// line is how a flaky job is listed: its workflow, its name, its commit,
// and where its paired failures and passes ran, oldest first, each by its
// matrix cell. The run names a job with no cell, and any job of a flake
// that spans runs, and the attempt one of a flake that spans attempts of
// its run.
func (g *flakyGroup) line(failed, passed []flakyJob) string {
	attempts := make(map[int64]map[int]bool)
	for _, j := range slices.Concat(failed, passed) {
		if attempts[j.run] == nil {
			attempts[j.run] = make(map[int]bool)
		}
		attempts[j.run][j.attempt] = true
	}
	where := func(jobs []flakyJob) string {
		var out []string
		for _, j := range slices.SortedFunc(slices.Values(jobs), func(a, b flakyJob) int {
			return cmp.Or(cmp.Compare(a.run, b.run), cmp.Compare(a.attempt, b.attempt), strings.Compare(a.cell, b.cell))
		}) {
			if w := j.where(len(attempts) > 1, len(attempts[j.run]) > 1); !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
		return strings.Join(out, ", ")
	}
	return fmt.Sprintf("%s / %s on %s: failed in %s, passed in %s",
		g.workflow, g.key.job, g.key.sha[:min(7, len(g.key.sha))], where(failed), where(passed))
}

// where names where j ran: its matrix cell, then its run when it has no
// cell or runs says its flake spans runs, and its attempt when attempts
// says its flake spans attempts of its run.
func (j *flakyJob) where(runs, attempts bool) string {
	var in []string
	if runs || j.cell == "" {
		in = append(in, "run "+strconv.FormatInt(j.run, 10))
	}
	if attempts {
		in = append(in, "attempt "+strconv.Itoa(j.attempt))
	}
	switch {
	case j.cell == "":
		return strings.Join(in, " ")
	case len(in) == 0:
		return j.cell
	default:
		return j.cell + " of " + strings.Join(in, " ")
	}
}

// Slots finds daily slots that should have published main and did not,
// while c.Published names an older commit, or nothing.
//
// A finished slot run that built a commit ahead of the published one would
// have published it, so each such run is a lost slot, whether it failed,
// was cancelled or skipped; with nothing published, every finished run is.
// Content-gated, once the image is published, a run that succeeded is
// never lost: it published, or decided that nothing in the image had
// moved. One that failed, was cancelled or ended any other way is lost all
// the same, and so is any run with nothing published yet, since then every
// run publishes, gated or not. With c.SlotJob set, it is that job's
// conclusion that counts, not the whole run's, and a run ahead whose jobs
// name neither it nor an unexpanded matrix job standing for it is an
// error.
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
// not. With nothing published, any run since the slot could first run is,
// content-gated or not: every such run publishes. With a commit published,
// a run that built a commit ahead of it is, unless content-gated and the
// run succeeded: the run as a whole, or with c.SlotJob set, that job in it.
// What costs nothing to ask is asked first: the run's own conclusion,
// then how its commit stands, then, only for a run ahead, its jobs.
func isLost(ctx context.Context, s Source, c *Config, run *Run, state registry.State, revision string, since time.Time) (bool, error) {
	if state == registry.Absent {
		return run.Created.After(since), nil
	}
	if c.ContentGated && c.SlotJob == "" && run.Conclusion == "success" {
		return false, nil
	}
	status, _, err := s.Compare(ctx, revision, run.HeadSHA)
	if err != nil {
		return false, fmt.Errorf("compare the slot run %s, which built %s, with %s: %w", run.URL, run.HeadSHA, revision, err)
	}
	if status != "ahead" {
		return false, nil
	}
	if c.ContentGated && c.SlotJob != "" {
		conclusion, err := slotConclusion(ctx, s, c, run)
		if err != nil {
			return false, err
		}
		return conclusion != "success", nil
	}
	return true, nil
}

// slotConclusion returns how a slot run ended for the image: the
// conclusion of its job c.SlotJob names, or the run's own when the run has
// no jobs at all. A job whose name GitHub left unexpanded, because it
// skipped or cancelled the job before expanding its matrix, stands for
// every name it would have expanded to. A run with jobs, none of them the
// one named or one standing for it, is an error wrapping [ErrNoJob], as is
// one with two.
func slotConclusion(ctx context.Context, s Source, c *Config, run *Run) (string, error) {
	jobs, err := s.Jobs(ctx, run)
	if err != nil {
		return "", fmt.Errorf("the slot run %s: %w", run.URL, err)
	}
	if len(jobs) == 0 {
		return run.Conclusion, nil
	}
	names := make([]string, 0, len(jobs))
	var found []Job
	for _, j := range jobs {
		names = append(names, strconv.Quote(j.Name))
		if j.Name == c.SlotJob || expandsTo(j.Name, c.SlotJob) {
			found = append(found, j)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%w: the slot run %s has no job called %q, nor one whose unexpanded name stands for it, only %s",
			ErrNoJob, run.URL, c.SlotJob, strings.Join(names, ", "))
	case 1:
		return found[0].Conclusion, nil
	default:
		return "", fmt.Errorf("the slot run %s has %d jobs that are or stand for %q, so which one publishes is unknown", run.URL, len(found), c.SlotJob)
	}
}

// expression is a ${{ }} expression in a job's name.
var expression = regexp.MustCompile(`\$\{\{.*?\}\}`)

// expandsTo reports whether name holds an unexpanded ${{ }} expression and
// job is a name it could expand to: name's text around its expressions,
// with any text in place of each.
func expandsTo(name, job string) bool {
	if !expression.MatchString(name) {
		return false
	}
	parts := expression.Split(name, -1)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$").MatchString(job)
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
