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

// prLimit is how many pull requests one read returns. With commits among
// the fields, each pull request can bring 100 commits of 100 authors, and
// GitHub refuses a query that could return more than 500,000 nodes, so 49
// is the most it allows.
const prLimit = 40

// slotLimit is how many slot runs one read returns, newest first: more
// than enough to see the lost slots that matter.
const slotLimit = 10

// timeout is how long one gh call may take when GH sets no Timeout of its
// own.
const timeout = time.Minute

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
		HeadSHA    string    `json:"headSha"`
		CreatedAt  time.Time `json:"createdAt"`
		Status     string    `json:"status"`
		Conclusion string    `json:"conclusion"`
		URL        string    `json:"url"`
	}
	err := g.list(ctx, &raw, "run", "list", "--repo", g.Repo, "--workflow", workflow, "--event", "schedule", "--branch", "main",
		"--limit", strconv.Itoa(slotLimit), "--json", "headSha,createdAt,status,conclusion,url")
	if err != nil {
		return nil, err
	}
	runs := make([]Run, 0, len(raw))
	for _, r := range raw {
		runs = append(runs, Run{
			HeadSHA:    r.HeadSHA,
			Created:    r.CreatedAt,
			Completed:  r.Status == "completed",
			Conclusion: r.Conclusion,
			URL:        r.URL,
		})
	}
	return runs, nil
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
		return fmt.Errorf("gh api %s: GitHub answered HTTP %d", strings.ReplaceAll(path, "{owner}/{repo}", g.Repo), status)
	}
	return nil
}
