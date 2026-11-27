// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
)

// renovate is the author of Renovate's pull requests: the divbast org's
// divbast-renovate GitHub App.
const renovate = "app/divbast-renovate"

// renovateBot is the login of Renovate's issues: the divbast-renovate
// App's bot user.
const renovateBot = "divbast-renovate[bot]"

// issueLimit is how many issues one read returns, the most GitHub gives.
const issueLimit = 100

// prLimit is how many pull requests one read returns. With commits among
// the fields, each pull request can bring 100 commits of 100 authors, and
// GitHub refuses a query that could return more than 500,000 nodes, so 49
// is the most it allows.
const prLimit = 40

// slotLimit is how many slot runs one read returns, newest first: more
// than enough to see the lost slots that matter.
const slotLimit = 10

// runLimit is how many runs one read of the runs since a time returns: the
// most GitHub lists for a search by creation or status.
const runLimit = 1000

// timeout is how long one gh call may take when GH sets no Timeout of its
// own.
const timeout = time.Minute

// editLimit is how many edits of an issue GitHub keeps: the original body
// and the latest 99.
const editLimit = 100

// historyPages is how many pages one read of an issue's history may take.
// GitHub keeps no more edits than one page holds, so a history that needs
// more is an answer GitHub did not give when this was written.
const historyPages = 20

// pageSize is how many edits each page of an issue's history asks for: as
// many as GitHub gives in one, and as it keeps. A test lowers it to replay
// pages recorded smaller.
var pageSize = 100

// historyQuery asks GitHub's GraphQL API for a page of an issue's edits,
// newest first, after $cursor when it is set, with when the issue was
// created and its body now.
const historyQuery = `query($owner:String!,$name:String!,$number:Int!,$first:Int!,$cursor:String){` +
	`repository(owner:$owner,name:$name){issue(number:$number){createdAt body ` +
	`userContentEdits(first:$first,after:$cursor){totalCount pageInfo{hasNextPage endCursor} nodes{editedAt diff}}}}}`

// statuses are the ways GitHub's compare API says head stands against
// base.
var statuses = []string{"ahead", "behind", "identical", "diverged"}

// fullSHA is a commit as GitHub names one.
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// GH is the [Source] that reads a repository through the gh CLI, which
// brings its own authentication: in a workflow, GH_TOKEN.
type GH struct {
	// Run runs gh.
	Run execx.Runner
	// Repo is the repository, as owner/name.
	Repo string
	// Timeout bounds each call to gh, so that a gh that hangs fails the
	// check rather than holding the job until the job's own timeout. Zero
	// means a minute.
	Timeout time.Duration
	// RunID is the run the check runs in, as GITHUB_RUN_ID gives it, which
	// PreviousRunStart passes over; zero outside a run.
	RunID int64
}

// RenovatePRs implements [Source]. It fails, rather than read part of the
// list, when as many are open as one read returns.
func (g GH) RenovatePRs(ctx context.Context) ([]PR, error) {
	var raw []struct {
		Number    int       `json:"number"`
		Title     string    `json:"title"`
		CreatedAt time.Time `json:"createdAt"`
		Commits   []struct {
			CommittedDate time.Time `json:"committedDate"`
		} `json:"commits"`
		StatusCheckRollup []ghCheck `json:"statusCheckRollup"`
	}
	err := g.list(ctx, &raw, "pr", "list", "--repo", g.Repo, "--author", renovate, "--state", "open",
		"--limit", strconv.Itoa(prLimit), "--json", "number,title,createdAt,commits,statusCheckRollup")
	if err != nil {
		return nil, err
	}
	if len(raw) >= prLimit {
		return nil, fmt.Errorf("%d Renovate pull requests are open in %s, as many as one read returns, so any beyond them would go unchecked", len(raw), g.Repo)
	}

	prs := make([]PR, 0, len(raw))
	for _, r := range raw {
		if len(r.Commits) == 0 {
			return nil, fmt.Errorf("gh pr list: pull request #%d has no commits", r.Number)
		}
		checks := make([]Check, 0, len(r.StatusCheckRollup))
		for _, rc := range r.StatusCheckRollup {
			c, cerr := rc.check()
			if cerr != nil {
				return nil, fmt.Errorf("gh pr list: pull request #%d: %w", r.Number, cerr)
			}
			checks = append(checks, c)
		}
		prs = append(prs, PR{
			Number:  r.Number,
			Title:   r.Title,
			Created: r.CreatedAt,
			Pushed:  r.Commits[len(r.Commits)-1].CommittedDate,
			Checks:  checks,
		})
	}
	return prs, nil
}

// ghCheck is one entry of gh's statusCheckRollup: a check run, or a
// commit status.
type ghCheck struct {
	Typename string `json:"__typename"`
	// A check run's.
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
	// A commit status's.
	Context string `json:"context"`
	State   string `json:"state"`
}

// check reads where c stands. A check run has no conclusion until it
// finishes, which gh prints as "", and any conclusion but success, skipped
// or neutral is a failure. A commit status is pending or expected until it
// reports success, failure or error. Anything else is a kind of check or a
// state GitHub did not have when this was written, and an error rather
// than a guess.
func (c *ghCheck) check() (Check, error) {
	switch c.Typename {
	case "CheckRun":
		outcome := Failed
		switch c.Conclusion {
		case "":
			outcome = Pending
		case "SUCCESS", "SKIPPED", "NEUTRAL":
			outcome = Passed
		}
		return Check{Name: c.Name, Run: true, Outcome: outcome}, nil
	case "StatusContext":
		var outcome Outcome
		switch c.State {
		case "PENDING", "EXPECTED":
			outcome = Pending
		case "SUCCESS":
			outcome = Passed
		case "FAILURE", "ERROR":
			outcome = Failed
		default:
			return Check{}, fmt.Errorf("commit status %q is in state %q, which is not one GitHub has", c.Context, c.State)
		}
		return Check{Name: c.Context, Outcome: outcome}, nil
	default:
		return Check{}, fmt.Errorf("a check of the kind %q, which is neither a check run nor a commit status", c.Typename)
	}
}

// LastSuccess implements [Source].
func (g GH) LastSuccess(ctx context.Context, workflow string) (time.Time, bool, error) {
	var runs []struct {
		CreatedAt time.Time `json:"createdAt"`
	}
	err := g.list(ctx, &runs, "run", "list", "--repo", g.Repo, "--workflow", workflow, "--status", "success",
		"--limit", "1", "--json", "createdAt")
	if err != nil || len(runs) == 0 {
		return time.Time{}, false, err
	}
	return runs[0].CreatedAt, true, nil
}

// SlotRuns implements [Source].
func (g GH) SlotRuns(ctx context.Context, workflow string) ([]Run, error) {
	var raw []struct {
		ID         int64     `json:"databaseId"`
		HeadSHA    string    `json:"headSha"`
		CreatedAt  time.Time `json:"createdAt"`
		Status     string    `json:"status"`
		Conclusion string    `json:"conclusion"`
		URL        string    `json:"url"`
	}
	err := g.list(ctx, &raw, "run", "list", "--repo", g.Repo, "--workflow", workflow, "--event", "schedule", "--branch", "main",
		"--limit", strconv.Itoa(slotLimit), "--json", "databaseId,headSha,createdAt,status,conclusion,url")
	if err != nil {
		return nil, err
	}
	runs := make([]Run, 0, len(raw))
	for _, r := range raw {
		runs = append(runs, Run{
			ID:         r.ID,
			HeadSHA:    r.HeadSHA,
			Created:    r.CreatedAt,
			Completed:  r.Status == "completed",
			Conclusion: r.Conclusion,
			URL:        r.URL,
		})
	}
	return runs, nil
}

// Jobs implements [Source], from the latest attempt of run, as gh run view
// lists its jobs.
func (g GH) Jobs(ctx context.Context, run *Run) ([]Job, error) {
	return g.jobs(ctx, "run", "view", strconv.FormatInt(run.ID, 10), "--repo", g.Repo, "--json", "jobs")
}

// AttemptJobs implements [Source], as gh run view lists the attempt's jobs.
func (g GH) AttemptJobs(ctx context.Context, run *Run, attempt int) ([]Job, error) {
	return g.jobs(ctx, "run", "view", strconv.FormatInt(run.ID, 10), "--repo", g.Repo, "--attempt", strconv.Itoa(attempt), "--json", "jobs")
}

// jobs runs gh run view with args, which ask for a run's jobs, and reads
// them. gh gives a job that has not finished the zero time.
func (g GH) jobs(ctx context.Context, args ...string) ([]Job, error) {
	var raw struct {
		Jobs []struct {
			Name        string    `json:"name"`
			Conclusion  string    `json:"conclusion"`
			CompletedAt time.Time `json:"completedAt"`
		} `json:"jobs"`
	}
	if err := g.list(ctx, &raw, args...); err != nil {
		return nil, err
	}
	jobs := make([]Job, 0, len(raw.Jobs))
	for _, j := range raw.Jobs {
		jobs = append(jobs, Job{Name: j.Name, Conclusion: j.Conclusion, Completed: j.CompletedAt})
	}
	return jobs, nil
}

// RunsSince implements [Source], every run gh lists as completed, however
// it ended. It fails, rather than read part of the list, when as many come
// back as one read returns.
func (g GH) RunsSince(ctx context.Context, since time.Time) ([]Run, error) {
	var raw []struct {
		ID         int64     `json:"databaseId"`
		HeadSHA    string    `json:"headSha"`
		Workflow   string    `json:"workflowName"`
		Event      string    `json:"event"`
		CreatedAt  time.Time `json:"createdAt"`
		URL        string    `json:"url"`
		WorkflowID int64     `json:"workflowDatabaseId"`
		Attempt    int       `json:"attempt"`
		Conclusion string    `json:"conclusion"`
		UpdatedAt  time.Time `json:"updatedAt"`
	}
	err := g.list(ctx, &raw, "run", "list", "--repo", g.Repo, "--created", ">="+timestamp(since), "--status", "completed",
		"--limit", strconv.Itoa(runLimit), "--json", "databaseId,headSha,workflowName,event,createdAt,url,workflowDatabaseId,attempt,conclusion,updatedAt")
	if err != nil {
		return nil, err
	}
	if len(raw) >= runLimit {
		return nil, fmt.Errorf("%d finished runs in %s created since %s, as many as one read returns, so any beyond them would go unchecked",
			len(raw), g.Repo, timestamp(since))
	}
	runs := make([]Run, 0, len(raw))
	for i := range raw {
		r := &raw[i]
		runs = append(runs, Run{
			ID:         r.ID,
			HeadSHA:    r.HeadSHA,
			Workflow:   r.Workflow,
			WorkflowID: r.WorkflowID,
			Event:      r.Event,
			Attempt:    r.Attempt,
			Updated:    r.UpdatedAt,
			Created:    r.CreatedAt,
			Completed:  true,
			Conclusion: r.Conclusion,
			URL:        r.URL,
		})
	}
	return runs, nil
}

// PreviousRunStart implements [Source], from workflow's newest three runs,
// newest first, so that a newer run already queued leaves this one and the
// one before it in the list. When g.RunID is one of them, the current run
// is that one, and the previous run the one listed after it, if any: with
// two newer runs started since, the one before this is not among the
// three, and is none. When g.RunID is none of them, outside a run or with
// three newer runs started since, the previous run is the newest, and the
// current one is not known.
func (g GH) PreviousRunStart(ctx context.Context, workflow string) (previous, current time.Time, err error) {
	type listed struct {
		ID        int64     `json:"databaseId"`
		CreatedAt time.Time `json:"createdAt"`
	}
	var runs []listed
	err = g.list(ctx, &runs, "run", "list", "--repo", g.Repo, "--workflow", workflow, "--limit", "3", "--json", "databaseId,createdAt")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	i := slices.IndexFunc(runs, func(r listed) bool { return r.ID == g.RunID })
	switch {
	case i < 0 && len(runs) > 0:
		return runs[0].CreatedAt, time.Time{}, nil
	case i < 0:
		return time.Time{}, time.Time{}, nil
	case i+1 < len(runs):
		return runs[i+1].CreatedAt, runs[i].CreatedAt, nil
	default:
		return time.Time{}, runs[i].CreatedAt, nil
	}
}

// MainSHA implements [Source].
func (g GH) MainSHA(ctx context.Context) (string, error) {
	var c struct {
		SHA string `json:"sha"`
	}
	if err := g.api(ctx, "repos/{owner}/{repo}/commits/main", &c); err != nil {
		return "", err
	}
	if !fullSHA.MatchString(c.SHA) {
		return "", fmt.Errorf("GitHub gives main of %s as %q, not a commit", g.Repo, c.SHA)
	}
	return c.SHA, nil
}

// Compare implements [Source]. GitHub lists the commits base lacks oldest
// first, but those a merge brought in come before the merge, and can be
// days older than it. So the first commit on head's line is found by
// following first parents back from head to the commit after base, and
// only when head is not among those listed, as when GitHub cuts a long
// list short, is it the oldest listed. A status GitHub did not have when
// this was written is an error rather than a guess.
func (g GH) Compare(ctx context.Context, base, head string) (string, time.Time, error) {
	for _, sha := range []string{base, head} {
		if !fullSHA.MatchString(sha) {
			return "", time.Time{}, fmt.Errorf("compare %s...%s: %q is not a full commit SHA", base, head, sha)
		}
	}
	var c struct {
		Status  string `json:"status"`
		Commits []struct {
			SHA     string `json:"sha"`
			Parents []struct {
				SHA string `json:"sha"`
			} `json:"parents"`
			Commit struct {
				Committer struct {
					Date time.Time `json:"date"`
				} `json:"committer"`
			} `json:"commit"`
		} `json:"commits"`
	}
	if err := g.api(ctx, "repos/{owner}/{repo}/compare/"+base+"..."+head, &c); err != nil {
		return "", time.Time{}, err
	}
	if !slices.Contains(statuses, c.Status) {
		return "", time.Time{}, fmt.Errorf("compare %s...%s: GitHub gives the status %q, which is none of %s",
			base, head, c.Status, strings.Join(statuses, ", "))
	}
	if len(c.Commits) == 0 {
		return c.Status, time.Time{}, nil
	}

	index := make(map[string]int, len(c.Commits))
	for i, cm := range c.Commits {
		index[cm.SHA] = i
	}
	i, ok := index[head]
	if !ok {
		return c.Status, c.Commits[0].Commit.Committer.Date, nil
	}
	// At most one step per commit listed, whatever the parents say.
	for range len(c.Commits) {
		parents := c.Commits[i].Parents
		if len(parents) == 0 {
			break
		}
		parent, ok := index[parents[0].SHA]
		if !ok {
			// The parent is base, or where head's line left base's.
			break
		}
		i = parent
	}
	return c.Status, c.Commits[i].Commit.Committer.Date, nil
}

// Dashboards implements [Source]. The issues API lists pull requests too,
// which it drops. It fails, rather than read part of the list, when as
// many come back as one read returns.
func (g GH) Dashboards(ctx context.Context) ([]Issue, error) {
	var raw []struct {
		Number      int
		Title, Body string
		HTMLURL     string          `json:"html_url"`
		PullRequest json.RawMessage `json:"pull_request"`
	}
	path := "repos/{owner}/{repo}/issues?state=open&creator=" + url.QueryEscape(renovateBot) + "&per_page=" + strconv.Itoa(issueLimit)
	if err := g.api(ctx, path, &raw); err != nil {
		return nil, err
	}
	if len(raw) >= issueLimit {
		return nil, fmt.Errorf("%d open issues by %s in %s, as many as one read returns, so its dashboard may not be among them",
			len(raw), renovateBot, g.Repo)
	}
	var out []Issue
	for _, is := range raw {
		if isPR := len(is.PullRequest) > 0 && string(is.PullRequest) != "null"; !isPR && is.Title == DashboardTitle {
			out = append(out, Issue{Number: is.Number, Title: is.Title, Body: is.Body, URL: is.HTMLURL})
		}
	}
	return out, nil
}

// DashboardHistory implements [Source], from the issue's edits as GitHub's
// GraphQL API lists them, newest first, a page at a time. Each edit's diff
// is, whatever its name, the whole body after the edit, and the oldest is
// the issue's creation, with its original body.
//
// GitHub's documentation, in "Tracking changes in a comment" under "Editing
// history limits", says it keeps at most 100 edits of an issue. Past that,
// it removes the oldest edits after the original body, and keeps the
// original and the latest 99. So when GitHub counts 100 edits or more, the
// original body is left out: it stood only until edits that may be gone,
// not until the next one kept. An issue never edited lists no edits, and
// its creation is made one from when it was created and the body it has
// now.
//
// It fails rather than read part of the history: on an edit it reaches
// whose body was deleted from the history, which leaves what it held
// unknown, and on a history that goes on past historyPages pages.
func (g GH) DashboardHistory(ctx context.Context, number int, since time.Time) ([]DashboardEdit, error) {
	owner, name, ok := strings.Cut(g.Repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("the repository %q is not owner/name", g.Repo)
	}
	args := []string{
		"api", "graphql", "-f", "query=" + historyQuery, "-F", "owner=" + owner, "-F", "name=" + name,
		"-F", "number=" + strconv.Itoa(number), "-F", "first=" + strconv.Itoa(pageSize),
	}
	var edits []DashboardEdit
	cursor := ""
	for page := range historyPages {
		call := args
		if page > 0 {
			call = append(slices.Clip(args), "-f", "cursor="+cursor)
		}
		var raw struct {
			Data struct {
				Repository struct {
					Issue *struct {
						CreatedAt        time.Time
						Body             string
						UserContentEdits struct {
							TotalCount int
							PageInfo   struct {
								HasNextPage bool
								EndCursor   string
							}
							Nodes []struct {
								EditedAt time.Time
								// Diff is null for an edit whose body was
								// deleted from the history.
								Diff *string
							}
						}
					}
				}
			}
		}
		if err := g.list(ctx, &raw, call...); err != nil {
			return nil, err
		}
		issue := raw.Data.Repository.Issue
		if issue == nil {
			return nil, fmt.Errorf("GitHub gives no issue #%d in %s", number, g.Repo)
		}
		listed := &issue.UserContentEdits
		last := !listed.PageInfo.HasNextPage
		if page == 0 && last && len(listed.Nodes) == 0 {
			return []DashboardEdit{{EditedAt: issue.CreatedAt, Body: issue.Body}}, nil
		}
		for i, n := range listed.Nodes {
			if last && i == len(listed.Nodes)-1 && listed.TotalCount >= editLimit {
				// The original body, which stood only until edits
				// GitHub may have removed.
				break
			}
			if n.Diff == nil {
				return nil, fmt.Errorf("issue #%d in %s: the body of its edit of %s was deleted from its history, so what it held is unknown",
					number, g.Repo, n.EditedAt.UTC().Format(time.RFC3339))
			}
			edits = append(edits, DashboardEdit{EditedAt: n.EditedAt, Body: *n.Diff})
			if !n.EditedAt.After(since) {
				return edits, nil
			}
		}
		if last {
			return edits, nil
		}
		cursor = listed.PageInfo.EndCursor
	}
	return nil, fmt.Errorf("the history of issue #%d in %s goes on past %d pages of %d edits, more than GitHub keeps, so it is not read in part",
		number, g.Repo, historyPages, pageSize)
}

// RepoCreated implements [Source].
func (g GH) RepoCreated(ctx context.Context) (time.Time, error) {
	var r struct {
		CreatedAt time.Time `json:"created_at"`
	}
	if err := g.api(ctx, "repos/{owner}/{repo}", &r); err != nil {
		return time.Time{}, err
	}
	if r.CreatedAt.IsZero() {
		return time.Time{}, fmt.Errorf("GitHub gives no creation time for %s", g.Repo)
	}
	return r.CreatedAt, nil
}

// WorkflowCreated implements [Source].
func (g GH) WorkflowCreated(ctx context.Context, file string) (time.Time, error) {
	var w struct {
		CreatedAt time.Time `json:"created_at"`
	}
	if err := g.api(ctx, "repos/{owner}/{repo}/actions/workflows/"+url.PathEscape(file), &w); err != nil {
		return time.Time{}, err
	}
	if w.CreatedAt.IsZero() {
		return time.Time{}, fmt.Errorf("GitHub gives no creation time for %s's workflow %s", g.Repo, file)
	}
	return w.CreatedAt, nil
}

// WorkflowID implements [Source].
func (g GH) WorkflowID(ctx context.Context, file string) (int64, error) {
	var w struct {
		ID int64 `json:"id"`
	}
	path := "repos/{owner}/{repo}/actions/workflows/" + url.PathEscape(file)
	status, err := ghapi.Client{Run: g.Run, Repo: g.Repo, Timeout: g.Timeout}.API(ctx, path, &w)
	switch {
	case err != nil:
		return 0, err
	case status == http.StatusNotFound:
		return 0, fmt.Errorf("%s has no workflow in the file %s", g.Repo, file)
	case status != http.StatusOK:
		return 0, g.answered(path, status)
	case w.ID == 0:
		return 0, fmt.Errorf("GitHub gives no ID for %s's workflow %s", g.Repo, file)
	}
	return w.ID, nil
}

// list runs gh with args, which ask for JSON, and decodes what it prints
// into v.
func (g GH) list(ctx context.Context, v any, args ...string) error {
	limit := g.Timeout
	if limit == 0 {
		limit = timeout
	}
	callCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	res, err := g.Run.Run(callCtx, "gh", args...)
	if err != nil {
		// Only GH's own limit is GH's to name: a deadline of the caller's,
		// reached first, is the caller's to report.
		if ctx.Err() == nil && errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("gh %s %s gave up after %v: %w", args[0], args[1], limit, err)
		}
		return fmt.Errorf("gh %s %s: %w", args[0], args[1], err)
	}
	if res.Code != 0 {
		return fmt.Errorf("gh %s %s: exit status %d: %s", args[0], args[1], res.Code, bytes.TrimSpace(res.Stderr))
	}
	if err = json.Unmarshal(res.Stdout, v); err != nil {
		return fmt.Errorf("gh %s %s: decode what it printed: %w", args[0], args[1], err)
	}
	return nil
}

// api GETs path from the GitHub API into v, and fails on anything but
// 200.
func (g GH) api(ctx context.Context, path string, v any) error {
	status, err := ghapi.Client{Run: g.Run, Repo: g.Repo, Timeout: g.Timeout}.API(ctx, path, v)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return g.answered(path, status)
	}
	return nil
}

// answered is the error for GitHub answering path with status.
func (g GH) answered(path string, status int) error {
	return fmt.Errorf("gh api %s: GitHub answered HTTP %d", strings.ReplaceAll(path, "{owner}/{repo}", g.Repo), status)
}
