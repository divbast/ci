// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/stall"
)

const (
	baikal     = "divbast/baikal-oci-image"
	librespeed = "divbast/librespeed-oci-image"

	// Baikal's main on 2026-11-11, and the commit four before it. Between
	// them: two commits on a branch, its merge, and a Renovate squash.
	baikalMain = "5b6f71aa65f688ee3bbdf9b89e5708722f8b9f64"
	baikalBase = "0f6bb73b0bc9f05e62bdb98540c6ee05fa1e8c30"
)

// testdata returns a recording from testdata, every one made by the
// owner's token as GH would run it: with gh 2.103.3 on 2026-11-11,
//
//	gh-pr-list-open-baikal.json        gh pr list --repo divbast/baikal-oci-image --author app/divbast-renovate --state open --limit 40 --json number,title,createdAt,commits,statusCheckRollup
//	gh-pr-list-merged-librespeed.json  gh pr list --repo divbast/librespeed-oci-image --author app/divbast-renovate --state merged --limit 40 --json number,title,createdAt,commits,statusCheckRollup
//	gh-pr-list-pending-baikal.json     gh pr list --repo divbast/baikal-oci-image --state all --search status:pending --limit 40 --json number,title,createdAt,commits,statusCheckRollup
//	gh-run-list-renovate-librespeed.json  gh run list --repo divbast/librespeed-oci-image --workflow renovate.yml --status success --limit 1 --json createdAt
//	gh-api-commits-main-baikal.txt     gh api -i repos/divbast/baikal-oci-image/commits/main
//	gh-api-compare-ahead-baikal.txt    gh api -i repos/divbast/baikal-oci-image/compare/<baikalBase>...<baikalMain>
//	gh-api-compare-behind-baikal.txt   gh api -i repos/divbast/baikal-oci-image/compare/<baikalMain>...<baikalBase>
//	gh-api-compare-404-baikal.txt      gh api -i repos/divbast/baikal-oci-image/compare/<40 zeros>...<baikalMain>
//	gh-api-repo-baikal.txt             gh api -i repos/divbast/baikal-oci-image
//
// with gh 2.104.0 on 2026-11-13,
//
//	gh-api-workflow-build-baikal.txt   gh api -i repos/divbast/baikal-oci-image/actions/workflows/build.yml
//
// and with gh 2.104.0 on 2026-11-14,
//
//	gh-run-list-slots-baikal.json      gh run list --repo divbast/baikal-oci-image --workflow build.yml --event schedule --branch main --limit 10 --json databaseId,headSha,createdAt,status,conclusion,url
//	gh-run-list-slots-librespeed.json  the same for divbast/librespeed-oci-image
//	gh-run-view-jobs-frankenphp.json   gh run view 43493850688 --repo divbast/frankenphp --json jobs
//	gh-run-view-jobs-baikal-failed.json  gh run view 42310287997 --repo divbast/baikal-oci-image --json jobs
//	gh-run-view-jobs-frankenphp-skipped.json  gh run view 43481642005 --repo divbast/frankenphp --json jobs
//
// and with gh 2.104.0 on 2026-11-20,
//
//	gh-api-issues-open-baikal.txt      gh api -i 'repos/divbast/baikal-oci-image/issues?state=open&creator=divbast-renovate%5Bbot%5D&per_page=100'
//	gh-api-issues-open-sonarr.txt      the same for divbast/sonarr-oci-image
//
// and with gh 2.105.0 on 2026-11-27, each through gh api graphql with
// historyQuery, owner divbast, and the name, number and page size (first)
// given, the later pages with -f cursor= the page before's endCursor,
//
//	gh-api-graphql-edits-sabnzbd-1.json   sabnzbd-oci-image #2, first 8
//	gh-api-graphql-edits-sabnzbd-2.json   the same, its second and last page
//	gh-api-graphql-edits-template-1.json  oci-image-template #3, first 5
//	gh-api-graphql-edits-template-20.json  the same, its twentieth and last page
//	gh-api-graphql-edits-never-sabnzbd.json  sabnzbd-oci-image #2, first 100, its edits emptied
//
// and the same day,
//
//	dashboard-pending.md               gh api repos/divbast/pisati/issues/7 --jq .body
//	gh-run-list-since-baikal.json      gh run list --repo divbast/baikal-oci-image --created '>=2026-11-26T00:00:00Z' --status completed --limit 1000 --json databaseId,headSha,workflowName,event,createdAt,url,workflowDatabaseId,attempt,conclusion,updatedAt
//	gh-run-list-previous-baikal.json   gh run list --repo divbast/baikal-oci-image --workflow stall.yml --limit 3 --json databaseId,createdAt
//	gh-run-view-jobs-ci-attempt-1.json  gh run view 43785315672 --repo divbast/ci --attempt 1 --json jobs
//	gh-api-workflow-missing-baikal.txt  gh api -i repos/divbast/baikal-oci-image/actions/workflows/no-such.yml
//
// The run list holds Baikal's finished runs from 26 November to early on
// the 27th: Renovate's, some of them cancelled or skipped, the build's, and
// one of stall's. The ci
// run is one whose test (amd64, docker) failed in its first attempt and
// passed in its second, which re-ran only the jobs that had failed: the
// second lists the others too, as new jobs with the first's times and
// conclusions.
//
// Sabnzbd's dashboard had been edited 12 times, so its two pages hold the
// whole of its history, ending with its creation. Oci-image-template's had
// reached 100, as many as GitHub keeps: its original body and the latest
// 99, with whatever came between gone. Its 20 pages were read in turn, and
// its tests answer the first page's cursor with the last page, leaving
// out the 18 between, which hold only more bodies. No issue in divbast's
// public repositories had never been edited, so the never-edited answer
// is sabnzbd's, with its edits replaced by what GitHub answered for a pull
// request never edited, baikal-oci-image #154: no nodes, and a null
// endCursor. gh api graphql prints only the body, with no headers and no
// newline at the end; each is as gh printed it.
//
// The issue lists hold each repository's Dependency Dashboard, #94 and
// #4, both clean, among Renovate's open pull requests, which the issues
// API lists too: two in Baikal's, four in Sonarr's. dashboard-clean.md is
// Baikal's dashboard's body. dashboard-pending.md is pisati's, as gh
// printed it: one update under Pending Approval, and seven under Pending
// Status Checks, two of them with a pull request.
//
// The two slot lists hold the same runs as their recordings of the day
// before, which lacked databaseId. The frankenphp run is a daily slot in
// which every job succeeded; the Baikal one is the slot of 2026-11-06,
// whose arm64 build failed and whose publish job was skipped. The other
// frankenphp run is a pull request's, on which the publish job's if: is
// false, so GitHub skipped the job before expanding its matrix, and lists
// it once, by its unexpanded name, as it does for a slot whose lint failed.
//
// From each gh api -i recording, the headers that describe the caller
// rather than the response are taken out: the token's OAuth scopes and
// client, its rate limit, the edge region that answered and the request's
// ID. The rest, and the status line and body, are as gh printed them, line
// endings included.
//
// No Renovate pull request was open in either repository, so the open
// list is empty. The ones with checks to read are merged, or closed with
// a check that never reported, which is what status:pending finds:
// Renovate's own pull requests from before Baikal's required job, two of
// them with a failed scan. The output has the same shape whatever the
// filter.
func testdata(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func prList(repo string) []string {
	return []string{
		"gh", "pr", "list", "--repo", repo, "--author", "app/divbast-renovate", "--state", "open",
		"--limit", "40", "--json", "number,title,createdAt,commits,statusCheckRollup",
	}
}

func successRuns(repo, workflow string) []string {
	return []string{"gh", "run", "list", "--repo", repo, "--workflow", workflow, "--status", "success", "--limit", "1", "--json", "createdAt"}
}

func slotRuns(repo, workflow string) []string {
	return []string{
		"gh", "run", "list", "--repo", repo, "--workflow", workflow, "--event", "schedule", "--branch", "main",
		"--limit", "10", "--json", "databaseId,headSha,createdAt,status,conclusion,url",
	}
}

func runJobs(repo string, id int64) []string {
	return []string{"gh", "run", "view", strconv.FormatInt(id, 10), "--repo", repo, "--json", "jobs"}
}

func api(path string) []string { return []string{"gh", "api", "-i", path} }

// stdout is a command that printed out and exited 0.
func stdout(out []byte) execx.Result { return execx.Result{Stdout: out} }

// ghFailed is gh exiting 1 with stderr and nothing on stdout.
func ghFailed(stderr string) execx.Result {
	return execx.Result{Stderr: []byte(stderr), Code: 1}
}

// rfc3339 parses s, which the test knows is a time.
func rfc3339(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// summary writes a PR on one line, so a test can compare all of one.
func summary(pr *stall.PR) string {
	checks := make([]string, 0, len(pr.Checks))
	for _, c := range pr.Checks {
		kind := "run"
		if !c.Run {
			kind = "status"
		}
		checks = append(checks, fmt.Sprintf("%s %s=%s", kind, c.Name, c.Outcome))
	}
	return fmt.Sprintf("#%d %s created %s pushed %s: %s", pr.Number, pr.Title,
		pr.Created.UTC().Format(time.RFC3339), pr.Pushed.UTC().Format(time.RFC3339), strings.Join(checks, ", "))
}

func TestGHRenovatePRs(t *testing.T) {
	t.Parallel()

	// gh's shape for an unfinished check run, with conclusion "" rather
	// than null, as gh 2.103.3 printed one for a public repository's open
	// pull request; and a commit status in each state GitHub has.
	unfinished := `[{"number":5,"title":"ci: update x","createdAt":"2026-11-10T01:00:00Z",` +
		`"commits":[{"committedDate":"2026-11-10T00:59:00Z"},{"committedDate":"2026-11-10T02:00:00Z"}],` +
		`"statusCheckRollup":[` +
		`{"__typename":"CheckRun","completedAt":"0001-01-01T00:00:00Z","conclusion":"","detailsUrl":"https://github.com/o/r/actions/runs/1/job/2","name":"required","startedAt":"2026-11-11T02:48:02Z","status":"IN_PROGRESS","workflowName":"CI"},` +
		`{"__typename":"CheckRun","conclusion":"NEUTRAL","name":"n","status":"COMPLETED"},` +
		`{"__typename":"CheckRun","conclusion":"CANCELLED","name":"c","status":"COMPLETED"},` +
		`{"__typename":"CheckRun","conclusion":"TIMED_OUT","name":"t","status":"COMPLETED"},` +
		`{"__typename":"CheckRun","conclusion":"ACTION_REQUIRED","name":"a","status":"COMPLETED"},` +
		`{"__typename":"StatusContext","context":"s/success","state":"SUCCESS","targetUrl":"https://example.com"},` +
		`{"__typename":"StatusContext","context":"s/pending","state":"PENDING"},` +
		`{"__typename":"StatusContext","context":"s/expected","state":"EXPECTED"},` +
		`{"__typename":"StatusContext","context":"s/failure","state":"FAILURE"},` +
		`{"__typename":"StatusContext","context":"s/error","state":"ERROR"}]}]`

	tests := []struct {
		name    string
		repo    string
		result  execx.Result
		want    []string
		wantErr string
	}{
		{
			name:   "open-baikal",
			repo:   baikal,
			result: stdout(testdata(t, "gh-pr-list-open-baikal.json")),
		},
		{
			name:   "merged-librespeed",
			repo:   librespeed,
			result: stdout(testdata(t, "gh-pr-list-merged-librespeed.json")),
			want: []string{
				"#2 ci: update ghcr.io/renovatebot/renovate Docker tag to v44.227.4 created 2026-11-10T21:50:48Z pushed 2026-11-10T22:08:49Z: " +
					"run lint=passed, run build (amd64, ubuntu-26.04)=passed, run build (arm64, ubuntu-26.04-arm)=passed, " +
					"run test (amd64, docker)=passed, run test (amd64, podman)=passed, run test (arm64, docker)=passed, run test (arm64, podman)=passed, " +
					"run scan (amd64, ubuntu-26.04)=passed, run scan (arm64, ubuntu-26.04-arm)=passed, run required=passed, run publish=passed",
			},
		},
		{
			name:   "pending-baikal",
			repo:   baikal,
			result: stdout(testdata(t, "gh-pr-list-pending-baikal.json")),
			want: []string{
				"#92 ci: update ghcr.io/renovatebot/renovate Docker tag to v44.225.1 created 2026-11-10T07:38:48Z pushed 2026-11-10T07:36:13Z: " +
					"run lint=passed, run build (amd64, ubuntu-26.04)=passed, run build (arm64, ubuntu-26.04-arm)=passed, " +
					"run test (amd64, docker)=passed, run test (amd64, podman)=passed, run test (arm64, docker)=passed, run test (arm64, podman)=passed, " +
					"run scan (amd64, ubuntu-26.04)=passed, run scan (arm64, ubuntu-26.04-arm)=passed, run publish=passed",
				"#89 ci: update renovatebot/github-action action to v46.3.13 created 2026-11-10T01:33:06Z pushed 2026-11-10T07:38:52Z: " +
					"run lint=passed, run build (amd64, ubuntu-26.04)=passed, run build (arm64, ubuntu-26.04-arm)=passed, " +
					"run test (amd64, docker)=passed, run test (amd64, podman)=passed, run test (arm64, docker)=passed, run test (arm64, podman)=passed, " +
					"run scan (amd64, ubuntu-26.04)=passed, run scan (arm64, ubuntu-26.04-arm)=passed, run publish=passed",
				"#27 build: update dunglas/frankenphp:static-builder-gnu Docker digest to b8d0d87 created 2026-10-22T17:35:59Z pushed 2026-10-22T17:35:57Z: " +
					"run lint=passed, run build (amd64, ubuntu-26.04)=passed, run build (arm64, ubuntu-26.04-arm)=passed, " +
					"run test (amd64, docker)=passed, run test (amd64, podman)=passed, run test (arm64, docker)=passed, run test (arm64, podman)=passed, " +
					"run scan (amd64, ubuntu-26.04)=passed, run scan (arm64, ubuntu-26.04-arm)=passed, run publish=passed",
				"#26 build: update gcr.io/distroless/cc-debian13:nonroot Docker digest to 83b9b50 created 2026-10-21T21:44:45Z pushed 2026-10-21T21:44:43Z: " +
					"run lint=passed, run build (amd64, ubuntu-26.04)=passed, run build (arm64, ubuntu-26.04-arm)=passed, " +
					"run test (amd64, docker)=passed, run test (amd64, podman)=passed, run test (arm64, docker)=passed, run test (arm64, podman)=passed, " +
					"run scan (amd64, ubuntu-26.04)=failed, run scan (arm64, ubuntu-26.04-arm)=failed, run publish=passed",
			},
		},
		{
			// Pushed is the last commit's date, and an unfinished check run
			// is pending, not failed.
			name:   "outcomes",
			repo:   baikal,
			result: stdout([]byte(unfinished)),
			want: []string{
				"#5 ci: update x created 2026-11-10T01:00:00Z pushed 2026-11-10T02:00:00Z: " +
					"run required=pending, run n=passed, run c=failed, run t=failed, run a=failed, " +
					"status s/success=passed, status s/pending=pending, status s/expected=pending, " +
					"status s/failure=failed, status s/error=failed",
			},
		},
		{
			name:    "full",
			repo:    baikal,
			result:  stdout(fullPage()),
			wantErr: "40 Renovate pull requests are open",
		},
		{
			name:    "gh-fails",
			repo:    baikal,
			result:  ghFailed("GraphQL: Could not resolve to a Repository with the name 'divbast/baikal-oci-image'. (repository)\n"),
			wantErr: "Could not resolve to a Repository",
		},
		{
			name:    "not-json",
			repo:    baikal,
			result:  stdout([]byte("no pull requests match your search\n")),
			wantErr: "gh pr list",
		},
		{
			name:    "no-commits",
			repo:    baikal,
			result:  stdout([]byte(`[{"number":5,"title":"x","createdAt":"2026-11-10T01:00:00Z","commits":[],"statusCheckRollup":[]}]`)),
			wantErr: "#5 has no commits",
		},
		{
			name: "unknown-check",
			repo: baikal,
			result: stdout([]byte(`[{"number":5,"title":"x","createdAt":"2026-11-10T01:00:00Z",` +
				`"commits":[{"committedDate":"2026-11-10T01:00:00Z"}],"statusCheckRollup":[{"__typename":"Mystery","name":"m"}]}]`)),
			wantErr: `"Mystery"`,
		},
		{
			name: "unknown-state",
			repo: baikal,
			result: stdout([]byte(`[{"number":5,"title":"x","createdAt":"2026-11-10T01:00:00Z",` +
				`"commits":[{"committedDate":"2026-11-10T01:00:00Z"}],"statusCheckRollup":[{"__typename":"StatusContext","context":"m","state":"MAYBE"}]}]`)),
			wantErr: `"MAYBE"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: prList(tt.repo), Result: tt.result}), Repo: tt.repo}
			prs, err := gh.RenovatePRs(t.Context())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("RenovatePRs() = %v, %v; want an error containing %q", prs, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(prs))
			for i := range prs {
				got = append(got, summary(&prs[i]))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("RenovatePRs() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
		})
	}
}

// fullPage is as many pull requests as one read returns.
func fullPage() []byte {
	prs := make([]string, 40)
	for i := range prs {
		prs[i] = fmt.Sprintf(`{"number":%d,"title":"x","createdAt":"2026-11-10T01:00:00Z","commits":[{"committedDate":"2026-11-10T01:00:00Z"}],"statusCheckRollup":[]}`, i+1)
	}
	return []byte("[" + strings.Join(prs, ",") + "]")
}

func TestGHLastSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		result  execx.Result
		want    string // empty for none
		wantErr string
	}{
		{
			name:   "librespeed",
			result: stdout(testdata(t, "gh-run-list-renovate-librespeed.json")),
			want:   "2026-11-10T22:14:50Z",
		},
		{
			name:   "never",
			result: stdout([]byte("[]\n")),
		},
		{
			name:    "no-such-workflow",
			result:  ghFailed("could not find any workflows named renovate.yml\n"),
			wantErr: "could not find any workflows named renovate.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: successRuns(librespeed, "renovate.yml"), Result: tt.result}), Repo: librespeed}
			got, ok, err := gh.LastSuccess(t.Context(), "renovate.yml")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LastSuccess() = %v, %t, %v; want an error containing %q", got, ok, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if ok || !got.IsZero() {
					t.Errorf("LastSuccess() = %v, %t; want none", got, ok)
				}
				return
			}
			if want := rfc3339(t, tt.want); !ok || !got.Equal(want) {
				t.Errorf("LastSuccess() = %v, %t; want %v, true", got, ok, want)
			}
		})
	}
}

func TestGHSlotRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		repo    string
		result  execx.Result
		want    []stall.Run
		wantLen int
		// wantConclusions is every run's conclusion, in order, when set.
		wantConclusions []string
		wantErr         string
	}{
		{
			// The seventh run, on 2026-11-06, failed.
			name:    "baikal",
			repo:    baikal,
			result:  stdout(testdata(t, "gh-run-list-slots-baikal.json")),
			wantLen: 10,
			want: []stall.Run{
				{
					ID:         43330795962,
					HeadSHA:    "f235a10b970004f0b16b700a76ea7fbf98908586",
					Created:    rfc3339(t, "2026-11-12T23:40:15Z"),
					Completed:  true,
					Conclusion: "success",
					URL:        "https://github.com/divbast/baikal-oci-image/actions/runs/43330795962",
				},
				{
					ID:         43129777907,
					HeadSHA:    baikalMain,
					Created:    rfc3339(t, "2026-11-12T00:46:44Z"),
					Completed:  true,
					Conclusion: "success",
					URL:        "https://github.com/divbast/baikal-oci-image/actions/runs/43129777907",
				},
			},
			wantConclusions: []string{"success", "success", "success", "success", "success", "success", "failure", "success", "failure", "success"},
		},
		{
			name:            "librespeed",
			repo:            librespeed,
			result:          stdout(testdata(t, "gh-run-list-slots-librespeed.json")),
			wantLen:         2,
			wantConclusions: []string{"success", "success"},
		},
		{
			// A run still going has no conclusion yet, which gh prints as "".
			name: "running",
			repo: baikal,
			result: stdout([]byte(`[{"conclusion":"","createdAt":"2026-11-11T18:50:00Z","databaseId":1,"headSha":"` + baikalMain +
				`","status":"in_progress","url":"https://github.com/divbast/baikal-oci-image/actions/runs/1"}]`)),
			wantLen: 1,
			want: []stall.Run{{
				ID:      1,
				HeadSHA: baikalMain,
				Created: rfc3339(t, "2026-11-11T18:50:00Z"),
				URL:     "https://github.com/divbast/baikal-oci-image/actions/runs/1",
			}},
		},
		{
			name:    "gh-fails",
			repo:    baikal,
			result:  ghFailed("HTTP 403: Resource not accessible by integration\n"),
			wantErr: "Resource not accessible by integration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: slotRuns(tt.repo, "build.yml"), Result: tt.result}), Repo: tt.repo}
			runs, err := gh.SlotRuns(t.Context(), "build.yml")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("SlotRuns() = %v, %v; want an error containing %q", runs, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(runs) != tt.wantLen {
				t.Fatalf("SlotRuns() returned %d runs, want %d", len(runs), tt.wantLen)
			}
			for i, want := range tt.want {
				if got := runs[i]; got.ID != want.ID || got.HeadSHA != want.HeadSHA || !got.Created.Equal(want.Created) ||
					got.Completed != want.Completed || got.Conclusion != want.Conclusion || got.URL != want.URL {
					t.Errorf("run %d = %+v, want %+v", i, got, want)
				}
			}
			if tt.wantConclusions != nil {
				got := make([]string, 0, len(runs))
				for _, r := range runs {
					got = append(got, r.Conclusion)
				}
				if !slices.Equal(got, tt.wantConclusions) {
					t.Errorf("conclusions = %q, want %q", got, tt.wantConclusions)
				}
			}
			for i, r := range runs {
				if tt.name == "baikal" && !r.Completed {
					t.Errorf("run %d = %+v, want it completed, as every recorded run is", i, r)
				}
			}
		})
	}
}

// TestGHJobs reads the jobs of a slot run, each by its name as GitHub
// shows it in the run, its conclusion, and when it finished (backlog CI-7).
func TestGHJobs(t *testing.T) {
	t.Parallel()

	const frankenphp = "divbast/frankenphp"
	tests := []struct {
		name   string
		repo   string
		id     int64
		result execx.Result
		// count is how many jobs the run has, and has one of them.
		count   int
		has     stall.Job
		wantErr []string
	}{
		{
			name: "frankenphp", repo: frankenphp, id: 43493850688,
			result: stdout(testdata(t, "gh-run-view-jobs-frankenphp.json")),
			count:  8, has: stall.Job{Name: "publish (baikal)", Conclusion: "success", Completed: rfc3339(t, "2026-11-13T19:54:28Z")},
		},
		{
			// The run failed in its arm64 build, and so never published.
			name: "baikal-publish-skipped", repo: baikal, id: 42310287997,
			result: stdout(testdata(t, "gh-run-view-jobs-baikal-failed.json")),
			count:  6, has: stall.Job{Name: "publish", Conclusion: "skipped", Completed: rfc3339(t, "2026-11-06T23:26:15Z")},
		},
		{
			// GitHub skipped the publish matrix before expanding it, and
			// names the job as written
			name: "frankenphp-matrix-skipped", repo: frankenphp, id: 43481642005,
			result: stdout(testdata(t, "gh-run-view-jobs-frankenphp-skipped.json")),
			count:  7, has: stall.Job{Name: "publish (${{ matrix.app }})", Conclusion: "skipped", Completed: rfc3339(t, "2026-11-13T18:23:36Z")},
		},
		{
			// A run that never started has no jobs.
			name: "no-jobs", repo: baikal, id: 7,
			result: stdout([]byte(`{"jobs":[]}`)),
		},
		{
			name: "gh-fails", repo: baikal, id: 7,
			result:  ghFailed("HTTP 404: Not Found\n"),
			wantErr: []string{"gh run view", "Not Found"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: runJobs(tt.repo, tt.id), Result: tt.result}), Repo: tt.repo}
			jobs, err := gh.Jobs(t.Context(), &stall.Run{ID: tt.id})
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("Jobs() = %q, want an error", jobs)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Jobs() error = %q, want it to contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tt.count || (tt.count > 0 && !slices.Contains(jobs, tt.has)) {
				t.Errorf("Jobs() = %q, want %d jobs, %+v among them", jobs, tt.count, tt.has)
			}
		})
	}
}

func runsSince(repo, since string) []string {
	return []string{
		"gh", "run", "list", "--repo", repo, "--created", ">=" + since, "--status", "completed",
		"--limit", "1000", "--json", "databaseId,headSha,workflowName,event,createdAt,url,workflowDatabaseId,attempt,conclusion,updatedAt",
	}
}

func previousRuns(repo, workflow string) []string {
	return []string{"gh", "run", "list", "--repo", repo, "--workflow", workflow, "--limit", "3", "--json", "databaseId,createdAt"}
}

func attemptJobs(repo string, id int64, attempt int) []string {
	return []string{"gh", "run", "view", strconv.FormatInt(id, 10), "--repo", repo, "--attempt", strconv.Itoa(attempt), "--json", "jobs"}
}

// sameRun fails t unless got is want, field by field.
func sameRun(t *testing.T, got, want *stall.Run) {
	t.Helper()
	if got.ID != want.ID || got.HeadSHA != want.HeadSHA || got.Workflow != want.Workflow || got.WorkflowID != want.WorkflowID ||
		got.Event != want.Event || got.Attempt != want.Attempt || !got.Updated.Equal(want.Updated) || !got.Created.Equal(want.Created) ||
		got.Completed != want.Completed || got.Conclusion != want.Conclusion || got.URL != want.URL {
		t.Errorf("run = %+v\nwant  %+v", *got, *want)
	}
}

// TestGHRunsSince reads every finished run created since a time, of every
// workflow, with its workflow's name and ID, its event, its latest attempt
// and when it last changed.
func TestGHRunsSince(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		repo string
		// since is the time asked, and argSince how gh is given it.
		since, argSince string
		result          execx.Result
		wantLen         int
		want            []stall.Run
		wantErr         string
	}{
		{
			// Renovate's runs, the build's and stall's, from 26 November to
			// early on the 27th; the first is the newest.
			name: "baikal", repo: baikal,
			since: "2026-11-26T00:00:00Z", argSince: "2026-11-26T00:00:00Z",
			result:  stdout(testdata(t, "gh-run-list-since-baikal.json")),
			wantLen: 42,
			want: []stall.Run{{
				ID:         45926771468,
				HeadSHA:    "851947707e7e6d2b34c22779c1820669fc67b9fb",
				Workflow:   "renovate",
				WorkflowID: 389993186,
				Event:      "issues",
				Attempt:    1,
				Updated:    rfc3339(t, "2026-11-27T02:10:33Z"),
				Created:    rfc3339(t, "2026-11-27T02:10:32Z"),
				Completed:  true,
				Conclusion: "skipped",
				URL:        "https://github.com/divbast/baikal-oci-image/actions/runs/45926771468",
			}},
		},
		{
			// A run of ci's re-run once, as gh lists it: its creation, and
			// its second attempt. The time asked is written in UTC.
			name: "re-run", repo: "divbast/ci",
			since: "2026-11-16T12:00:00+11:00", argSince: "2026-11-16T01:00:00Z",
			result: stdout([]byte(`[{"attempt":2,"conclusion":"success","createdAt":"2026-11-16T01:16:44Z","databaseId":43785315672,"event":"push",` +
				`"headSha":"1335cbc6827ce97e058d10711188752e0b2b349f","updatedAt":"2026-11-16T01:32:19Z","url":"https://github.com/divbast/ci/actions/runs/43785315672",` +
				`"workflowDatabaseId":414049623,"workflowName":"self-ci"}]` + "\n")),
			wantLen: 1,
			want: []stall.Run{{
				ID:         43785315672,
				HeadSHA:    "1335cbc6827ce97e058d10711188752e0b2b349f",
				Workflow:   "self-ci",
				WorkflowID: 414049623,
				Event:      "push",
				Attempt:    2,
				Updated:    rfc3339(t, "2026-11-16T01:32:19Z"),
				Created:    rfc3339(t, "2026-11-16T01:16:44Z"),
				Completed:  true,
				Conclusion: "success",
				URL:        "https://github.com/divbast/ci/actions/runs/43785315672",
			}},
		},
		{
			name: "none", repo: baikal,
			since: "2026-11-26T00:00:00Z", argSince: "2026-11-26T00:00:00Z",
			result: stdout([]byte("[]\n")),
		},
		{
			name: "gh-fails", repo: baikal,
			since: "2026-11-26T00:00:00Z", argSince: "2026-11-26T00:00:00Z",
			result:  ghFailed("HTTP 403: Resource not accessible by integration\n"),
			wantErr: "Resource not accessible by integration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: runsSince(tt.repo, tt.argSince), Result: tt.result}), Repo: tt.repo}
			runs, err := gh.RunsSince(t.Context(), rfc3339(t, tt.since))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("RunsSince() = %v, %v; want an error containing %q", runs, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(runs) != tt.wantLen {
				t.Fatalf("RunsSince() returned %d runs, want %d", len(runs), tt.wantLen)
			}
			for i := range tt.want {
				sameRun(t, &runs[i], &tt.want[i])
			}
			for i := range runs {
				if r := &runs[i]; r.ID == 0 || r.WorkflowID == 0 || r.Workflow == "" || r.Event == "" || r.Attempt < 1 || r.Updated.Before(r.Created) || !r.Completed {
					t.Errorf("run %d = %+v, want every field GitHub gives set", i, *r)
				}
			}
		})
	}
}

// TestGHRunsSinceCap checks that RunsSince fails, rather than read part of
// the list, when as many runs come back as one read returns: 1000, the most
// GitHub lists for a search by creation or status.
func TestGHRunsSinceCap(t *testing.T) {
	t.Parallel()

	page := func(n int) []byte {
		runs := make([]string, n)
		for i := range runs {
			runs[i] = fmt.Sprintf(`{"attempt":1,"conclusion":"success","createdAt":"2026-11-26T01:00:00Z","databaseId":%d,"event":"push",`+
				`"headSha":"%s","updatedAt":"2026-11-26T01:20:00Z","url":"https://github.com/divbast/baikal-oci-image/actions/runs/%d","workflowDatabaseId":354063381,"workflowName":"build"}`,
				i+1, baikalMain, i+1)
		}
		return []byte("[" + strings.Join(runs, ",") + "]")
	}
	for _, tt := range []struct {
		n       int
		wantErr bool
	}{{999, false}, {1000, true}} {
		t.Run(strconv.Itoa(tt.n), func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: runsSince(baikal, "2026-11-26T00:00:00Z"), Result: stdout(page(tt.n))}), Repo: baikal}
			runs, err := gh.RunsSince(t.Context(), rfc3339(t, "2026-11-26T00:00:00Z"))
			if !tt.wantErr {
				if err != nil || len(runs) != tt.n {
					t.Fatalf("RunsSince() = %d runs, %v; want %d, nil", len(runs), err, tt.n)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "1000") {
				t.Fatalf("RunsSince() = %d runs, %v; want an error naming 1000", len(runs), err)
			}
		})
	}
}

// TestGHPreviousRunStart reads when the stall workflow's run before this
// one was created, and when this one was, from its newest three runs:
// Baikal's of 26 November, 45900219294, and of the two days before,
// 45708076923 and 45502688399.
func TestGHPreviousRunStart(t *testing.T) {
	t.Parallel()

	const (
		newest  = "2026-11-26T21:44:46Z"
		before  = "2026-11-25T21:51:05Z"
		earlier = "2026-11-24T22:37:37Z"
	)
	recordedRuns := stdout(testdata(t, "gh-run-list-previous-baikal.json"))
	tests := []struct {
		name   string
		runID  int64
		result execx.Result
		// wantPrevious and wantCurrent are empty for none.
		wantPrevious, wantCurrent string
		wantErr                   string
	}{
		{
			// Inside the newest run, the one before it.
			name: "inside-the-newest", runID: 45900219294, result: recordedRuns,
			wantPrevious: before, wantCurrent: newest,
		},
		{
			// A newer run is already queued: the one before this is the
			// third.
			name: "newer-run-queued", runID: 45708076923, result: recordedRuns,
			wantPrevious: earlier, wantCurrent: before,
		},
		{
			// Two newer runs have started since this one, so the one
			// before this is not among the three.
			name: "two-newer-runs", runID: 45502688399, result: recordedRuns,
			wantCurrent: earlier,
		},
		{
			// Outside a run, the newest is the one before, and this one is
			// not known.
			name: "outside-a-run", result: recordedRuns,
			wantPrevious: newest,
		},
		{
			// Three newer runs have started since this one.
			name: "not-listed", runID: 5, result: recordedRuns,
			wantPrevious: newest,
		},
		{
			// The first run of stall.yml has none before it.
			name: "first", runID: 45900219294, result: stdout([]byte(`[{"createdAt":"2026-11-26T21:44:46Z","databaseId":45900219294}]` + "\n")),
			wantCurrent: newest,
		},
		{
			name: "never", result: stdout([]byte("[]\n")),
		},
		{
			name: "no-such-workflow", result: ghFailed("could not find any workflows named stall.yml\n"),
			wantErr: "could not find any workflows named stall.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: previousRuns(baikal, "stall.yml"), Result: tt.result}), Repo: baikal, RunID: tt.runID}
			previous, current, err := gh.PreviousRunStart(t.Context(), "stall.yml")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("PreviousRunStart() = %v, %v, %v; want an error containing %q", previous, current, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				what string
				got  time.Time
				want string
			}{{"previous", previous, tt.wantPrevious}, {"current", current, tt.wantCurrent}} {
				if c.want == "" && !c.got.IsZero() {
					t.Errorf("PreviousRunStart() %s = %v, want none", c.what, c.got)
				}
				if c.want != "" && !c.got.Equal(rfc3339(t, c.want)) {
					t.Errorf("PreviousRunStart() %s = %v, want %s", c.what, c.got, c.want)
				}
			}
		})
	}
}

// TestGHAttemptJobs reads the jobs of an earlier attempt of a run: ci's run
// whose test (amd64, docker) failed in its first attempt and passed when
// re-run, which its latest attempt's jobs no longer show.
func TestGHAttemptJobs(t *testing.T) {
	t.Parallel()

	const ci = "divbast/ci"
	t.Run("recorded", func(t *testing.T) {
		t.Parallel()
		gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: attemptJobs(ci, 43785315672, 1), Result: stdout(testdata(t, "gh-run-view-jobs-ci-attempt-1.json"))}), Repo: ci}
		jobs, err := gh.AttemptJobs(t.Context(), &stall.Run{ID: 43785315672, Attempt: 2}, 1)
		if err != nil {
			t.Fatal(err)
		}
		want := []stall.Job{
			{Name: "test (amd64, docker)", Conclusion: "failure", Completed: rfc3339(t, "2026-11-16T01:21:55Z")},
			{Name: "test (amd64, podman)", Conclusion: "success", Completed: rfc3339(t, "2026-11-16T01:20:57Z")},
			{Name: "required", Conclusion: "failure", Completed: rfc3339(t, "2026-11-16T01:22:02Z")},
		}
		if len(jobs) != 8 {
			t.Errorf("AttemptJobs() = %d jobs, want 8", len(jobs))
		}
		for _, w := range want {
			if !slices.Contains(jobs, w) {
				t.Errorf("AttemptJobs() = %+v, want %+v among them", jobs, w)
			}
		}
	})
	t.Run("gh-fails", func(t *testing.T) {
		t.Parallel()
		gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: attemptJobs(ci, 7, 1), Result: ghFailed("HTTP 404: Not Found\n")}), Repo: ci}
		jobs, err := gh.AttemptJobs(t.Context(), &stall.Run{ID: 7, Attempt: 2}, 1)
		if err == nil || !strings.Contains(err.Error(), "gh run view") || !strings.Contains(err.Error(), "Not Found") {
			t.Fatalf("AttemptJobs() = %v, %v; want gh run view's error", jobs, err)
		}
	})
}

// TestGHWorkflowID reads the ID of the workflow in a file, and fails,
// naming the file, when the repository has no such workflow.
func TestGHWorkflowID(t *testing.T) {
	t.Parallel()

	workflow := func(file string) []string { return api("repos/divbast/baikal-oci-image/actions/workflows/" + file) }
	tests := []struct {
		name    string
		file    string
		result  execx.Result
		want    int64
		wantErr []string
	}{
		{name: "build", file: "build.yml", result: stdout(testdata(t, "gh-api-workflow-build-baikal.txt")), want: 354063381},
		{
			name: "no-such-workflow", file: "no-such.yml",
			result: execx.Result{
				Stdout: testdata(t, "gh-api-workflow-missing-baikal.txt"),
				Stderr: []byte("gh: Not Found (HTTP 404)\n"),
				Code:   1,
			},
			wantErr: []string{"no-such.yml", baikal},
		},
		{
			name: "no-id", file: "build.yml", result: stdout([]byte("HTTP/2.0 200 OK\r\n\r\n{}")),
			wantErr: []string{"build.yml", "no ID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: workflow(tt.file), Result: tt.result}), Repo: baikal}
			got, err := gh.WorkflowID(t.Context(), tt.file)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("WorkflowID() = %d, want an error", got)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("WorkflowID() error = %q, want it to contain %q", err, want)
					}
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("WorkflowID() = %d, %v; want %d", got, err, tt.want)
			}
		})
	}
}

func TestGHMainSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		result  execx.Result
		want    string
		wantErr string
	}{
		{
			name:   "baikal",
			result: stdout(testdata(t, "gh-api-commits-main-baikal.txt")),
			want:   baikalMain,
		},
		{
			name: "not-found",
			result: execx.Result{
				Stdout: []byte("HTTP/2.0 404 Not Found\nContent-Type: application/json; charset=utf-8\r\n\r\n" + `{"message":"Not Found","status":"404"}`),
				Stderr: []byte("gh: Not Found (HTTP 404)\n"),
				Code:   1,
			},
			wantErr: "HTTP 404",
		},
		{
			name:    "not-a-commit",
			result:  stdout([]byte("HTTP/2.0 200 OK\nContent-Type: application/json; charset=utf-8\r\n\r\n" + `{"sha":"--output=x"}`)),
			wantErr: `"--output=x"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: api("repos/divbast/baikal-oci-image/commits/main"), Result: tt.result}), Repo: baikal}
			got, err := gh.MainSHA(t.Context())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MainSHA() = %q, %v; want an error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("MainSHA() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGHCompare(t *testing.T) {
	t.Parallel()

	zeros := strings.Repeat("0", 40)
	tests := []struct {
		name       string
		base, head string
		result     execx.Result
		wantStatus string
		wantFirst  string // empty for none
		wantErr    string
	}{
		{
			// The first commit on main after the base is the merge, made
			// after the two commits it brought in: c677e3c at 21:36:49 and
			// 36eaae2 at 21:37:51.
			name:       "ahead",
			base:       baikalBase,
			head:       baikalMain,
			result:     stdout(testdata(t, "gh-api-compare-ahead-baikal.txt")),
			wantStatus: "ahead",
			wantFirst:  "2026-11-10T21:47:53Z",
		},
		{
			name:       "behind",
			base:       baikalMain,
			head:       baikalBase,
			result:     stdout(testdata(t, "gh-api-compare-behind-baikal.txt")),
			wantStatus: "behind",
		},
		{
			// A list cut short, without head, falls back to the earliest
			// commit listed.
			name: "head-not-listed",
			base: baikalBase,
			head: baikalMain,
			result: stdout([]byte("HTTP/2.0 200 OK\nContent-Type: application/json; charset=utf-8\r\n\r\n" +
				`{"status":"ahead","commits":[` +
				`{"sha":"` + strings.Repeat("a", 40) + `","parents":[{"sha":"` + baikalBase + `"}],"commit":{"committer":{"date":"2026-11-01T00:00:00Z"}}},` +
				`{"sha":"` + strings.Repeat("b", 40) + `","parents":[{"sha":"` + strings.Repeat("a", 40) + `"}],"commit":{"committer":{"date":"2026-11-02T00:00:00Z"}}}]}`)),
			wantStatus: "ahead",
			wantFirst:  "2026-11-01T00:00:00Z",
		},
		{
			name:       "identical",
			base:       baikalMain,
			head:       baikalMain,
			result:     stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"status":"identical","commits":[]}`)),
			wantStatus: "identical",
		},
		{
			name: "diverged",
			base: baikalBase,
			head: baikalMain,
			result: stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"status":"diverged","commits":[` +
				`{"sha":"` + baikalMain + `","parents":[{"sha":"` + strings.Repeat("a", 40) + `"}],"commit":{"committer":{"date":"2026-11-03T00:00:00Z"}}}]}`)),
			wantStatus: "diverged",
			wantFirst:  "2026-11-03T00:00:00Z",
		},
		{
			// A status GitHub did not have when this was written is an
			// error, not a guess at what it means.
			name:    "unknown-status",
			base:    baikalBase,
			head:    baikalMain,
			result:  stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"status":"sideways","commits":[]}`)),
			wantErr: `"sideways"`,
		},
		{
			name:    "no-status",
			base:    baikalBase,
			head:    baikalMain,
			result:  stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"commits":[]}`)),
			wantErr: `""`,
		},
		{
			name: "unknown-status-with-commits",
			base: baikalBase,
			head: baikalMain,
			result: stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"status":"AHEAD","commits":[` +
				`{"sha":"` + baikalMain + `","parents":[{"sha":"` + baikalBase + `"}],"commit":{"committer":{"date":"2026-11-03T00:00:00Z"}}}]}`)),
			wantErr: `"AHEAD"`,
		},
		{
			name:    "not-found",
			base:    zeros,
			head:    baikalMain,
			result:  execx.Result{Stdout: testdata(t, "gh-api-compare-404-baikal.txt"), Stderr: []byte("gh: Not Found (HTTP 404)\n"), Code: 1},
			wantErr: "HTTP 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			call := execx.Call{Argv: api("repos/divbast/baikal-oci-image/compare/" + tt.base + "..." + tt.head), Result: tt.result}
			gh := stall.GH{Run: execx.NewFake(t, call), Repo: baikal}
			status, first, err := gh.Compare(t.Context(), tt.base, tt.head)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Compare() = %q, %v, %v; want an error containing %q", status, first, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if status != tt.wantStatus {
				t.Errorf("Compare() status = %q, want %q", status, tt.wantStatus)
			}
			if tt.wantFirst == "" {
				if !first.IsZero() {
					t.Errorf("Compare() first commit = %v, want none", first)
				}
				return
			}
			if want := rfc3339(t, tt.wantFirst); !first.Equal(want) {
				t.Errorf("Compare() first commit = %v, want %v", first, want)
			}
		})
	}
}

// TestGHCompareRejects checks that what is not a commit never reaches gh,
// where it would become part of an API path.
func TestGHCompareRejects(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "main", "../../../user", strings.Repeat("A", 40), baikalMain + "/x"} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t), Repo: baikal}
			if _, _, err := gh.Compare(t.Context(), baikalBase, bad); err == nil {
				t.Errorf("Compare(%q) succeeded, want an error", bad)
			}
			if _, _, err := gh.Compare(t.Context(), bad, baikalMain); err == nil {
				t.Errorf("Compare(%q, head) succeeded, want an error", bad)
			}
		})
	}
}

func TestGHRepoCreated(t *testing.T) {
	t.Parallel()

	gh := stall.GH{Run: execx.NewFake(t, execx.Call{
		Argv:   api("repos/divbast/baikal-oci-image"),
		Result: stdout(testdata(t, "gh-api-repo-baikal.txt")),
	}), Repo: baikal}
	got, err := gh.RepoCreated(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Baikal's repository came to divbast by transfer and kept the date
	// it was created elsewhere.
	if want := rfc3339(t, "2026-09-09T05:04:37Z"); !got.Equal(want) {
		t.Errorf("RepoCreated() = %v, want %v", got, want)
	}
}

func TestGHWorkflowCreated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workflow string
		// argPath is the endpoint gh is expected to be given.
		argPath string
		result  execx.Result
		want    string
		wantErr string
	}{
		{
			// GitHub writes the time in the owner's zone: 23:32:15+10:00.
			name:     "baikal",
			workflow: "build.yml",
			argPath:  "repos/divbast/baikal-oci-image/actions/workflows/build.yml",
			result:   stdout(testdata(t, "gh-api-workflow-build-baikal.txt")),
			want:     "2026-09-09T13:32:15Z",
		},
		{
			// The file name is one segment of the path, whatever it holds.
			name:     "escaped",
			workflow: "../x.yml",
			argPath:  "repos/divbast/baikal-oci-image/actions/workflows/..%2Fx.yml",
			result:   stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"created_at":"2026-11-01T00:00:00Z"}`)),
			want:     "2026-11-01T00:00:00Z",
		},
		{
			name:     "no-such-workflow",
			workflow: "publish.yml",
			argPath:  "repos/divbast/baikal-oci-image/actions/workflows/publish.yml",
			result: execx.Result{
				Stdout: []byte("HTTP/2.0 404 Not Found\r\n\r\n" + `{"message":"Not Found","status":"404"}`),
				Stderr: []byte("gh: Not Found (HTTP 404)\n"),
				Code:   1,
			},
			wantErr: "HTTP 404",
		},
		{
			name:     "no-creation-time",
			workflow: "build.yml",
			argPath:  "repos/divbast/baikal-oci-image/actions/workflows/build.yml",
			result:   stdout([]byte("HTTP/2.0 200 OK\r\n\r\n" + `{"path":".github/workflows/build.yml"}`)),
			wantErr:  "no creation time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: api(tt.argPath), Result: tt.result}), Repo: baikal}
			got, err := gh.WorkflowCreated(t.Context(), tt.workflow)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("WorkflowCreated(%q) = %v, %v; want an error containing %q", tt.workflow, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := rfc3339(t, tt.want); !got.Equal(want) {
				t.Errorf("WorkflowCreated(%q) = %v, want %v", tt.workflow, got, want)
			}
		})
	}
}

// hang is a Runner whose every command runs until its context ends, as a
// gh that hangs would, and then fails as execx.OS does.
type hang struct{}

func (hang) Run(ctx context.Context, name string, _ ...string) (execx.Result, error) {
	<-ctx.Done()
	return execx.Result{}, fmt.Errorf("run %s: %w", name, ctx.Err())
}

// TestGHTimeout checks that a gh that hangs is given up on after a minute,
// or after GH's own Timeout, whether GH runs it to list or to call the API,
// with an error that names the call and the limit. A deadline of the
// caller's that comes first is the caller's to report: the error then
// says nothing of GH giving up (backlog CI-6).
// The bubble's clock moves only when everything in it waits, so no test
// waits a minute.
func TestGHTimeout(t *testing.T) {
	t.Parallel()

	// Each call, and what its error names it.
	calls := map[string]struct {
		call func(ctx context.Context, gh stall.GH) error
		says string
	}{
		"list": {
			call: func(ctx context.Context, gh stall.GH) error {
				_, err := gh.SlotRuns(ctx, "build.yml")
				return err
			},
			says: "gh run list",
		},
		"api": {
			call: func(ctx context.Context, gh stall.GH) error {
				_, err := gh.MainSHA(ctx)
				return err
			},
			says: "gh api repos/divbast/baikal-oci-image/commits/main",
		},
	}
	for name, c := range calls {
		for _, tt := range []struct {
			name    string
			timeout time.Duration
			// caller is a deadline the caller's context sets; zero for
			// none.
			caller time.Duration
			want   time.Duration
		}{
			{name: "default", want: time.Minute},
			{name: "set", timeout: 4 * time.Second, want: 4 * time.Second},
			{name: "caller-first", caller: 2 * time.Second, want: 2 * time.Second},
		} {
			t.Run(name+"-"+tt.name, func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					ctx := t.Context()
					if tt.caller != 0 {
						var cancel context.CancelFunc
						ctx, cancel = context.WithTimeout(ctx, tt.caller)
						defer cancel()
					}
					start := time.Now()
					err := c.call(ctx, stall.GH{Run: hang{}, Repo: baikal, Timeout: tt.timeout})
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("got %v, want an error wrapping %v", err, context.DeadlineExceeded)
					}
					if waited := time.Since(start); waited != tt.want {
						t.Errorf("gave up after %v, want %v", waited, tt.want)
					}
					want := fmt.Sprintf("%s gave up after %v: ", c.says, tt.want)
					switch said := err.Error(); {
					case tt.caller != 0 && strings.Contains(said, "gave up"):
						t.Errorf("error = %q, want it not to say GH gave up on a deadline of the caller's", err)
					case tt.caller == 0 && !strings.Contains(said, want):
						t.Errorf("error = %q, want it to contain %q", err, want)
					}
				})
			})
		}
	}
}

// issuesPath is the issues GH.Dashboards reads for repo.
func issuesPath(repo string) string {
	return "repos/" + repo + "/issues?state=open&creator=divbast-renovate%5Bbot%5D&per_page=100"
}

// okJSON is a gh api -i answer of 200 with body.
func okJSON(body string) []byte {
	return []byte("HTTP/2.0 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n" + body)
}

func TestGHDashboards(t *testing.T) {
	t.Parallel()
	sonarr := "divbast/sonarr-oci-image"
	tests := []struct {
		name    string
		repo    string
		result  execx.Result
		want    []int // the issues' numbers
		wantURL string
		wantErr bool
	}{
		{
			name: "baikal", repo: baikal, result: stdout(testdata(t, "gh-api-issues-open-baikal.txt")),
			want: []int{94}, wantURL: "https://github.com/divbast/baikal-oci-image/issues/94",
		},
		{
			name: "sonarr", repo: sonarr, result: stdout(testdata(t, "gh-api-issues-open-sonarr.txt")),
			want: []int{4}, wantURL: "https://github.com/divbast/sonarr-oci-image/issues/4",
		},
		{
			// Renovate's own lookup takes the title exactly
			name: "other-titles", repo: baikal,
			result: stdout(okJSON(`[{"number":7,"title":"Dependency Dashboard (old)","body":"x","html_url":"u7"},` +
				`{"number":8,"title":"dependency dashboard","body":"x","html_url":"u8"}]`)),
		},
		{
			// The issues API lists pull requests too, whatever their title
			name: "pull-request", repo: baikal,
			result: stdout(okJSON(`[{"number":9,"title":"Dependency Dashboard","body":"x","html_url":"u9",` +
				`"pull_request":{"url":"https://api.github.com/repos/divbast/baikal-oci-image/pulls/9"}},` +
				`{"number":10,"title":"Dependency Dashboard","body":"x","html_url":"u10","pull_request":null}]`)),
			want: []int{10},
		},
		{
			name: "full-page", repo: baikal,
			result:  stdout(okJSON("[" + strings.Repeat(`{"number":1,"title":"Dependency Dashboard","body":"x","html_url":"u"},`, 99) + `{"number":1,"title":"x","body":"x","html_url":"u"}]`)),
			wantErr: true,
		},
		{name: "gh-fails", repo: baikal, result: ghFailed("gh: HTTP 502"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: api(issuesPath(tt.repo)), Result: tt.result}), Repo: tt.repo}
			got, err := gh.Dashboards(t.Context())
			if tt.wantErr {
				if err == nil {
					t.Errorf("Dashboards() = %+v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var numbers []int
			for _, is := range got {
				numbers = append(numbers, is.Number)
				if is.Title != "Dependency Dashboard" || is.Body == "" {
					t.Errorf("issue %+v, want the dashboard's title and body", is)
				}
			}
			if !slices.Equal(numbers, tt.want) {
				t.Errorf("Dashboards() numbers = %v, want %v", numbers, tt.want)
			}
			if tt.wantURL != "" && got[0].URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", got[0].URL, tt.wantURL)
			}
		})
	}
}

const (
	sabnzbd  = "divbast/sabnzbd-oci-image"
	template = "divbast/oci-image-template"
)

// historyQuery is the query GH.DashboardHistory sends, with which the
// recordings were made.
const historyQuery = `query($owner:String!,$name:String!,$number:Int!,$first:Int!,$cursor:String){repository(owner:$owner,name:$name){issue(number:$number){createdAt body userContentEdits(first:$first,after:$cursor){totalCount pageInfo{hasNextPage endCursor} nodes{editedAt diff}}}}}`

// history is the gh call that reads a page of first edits of issue number
// in repo: the first page when cursor is empty, else the one after it.
func history(repo string, number, first int, cursor string) []string {
	owner, name, _ := strings.Cut(repo, "/")
	argv := []string{
		"gh", "api", "graphql", "-f", "query=" + historyQuery, "-F", "owner=" + owner, "-F", "name=" + name,
		"-F", "number=" + strconv.Itoa(number), "-F", "first=" + strconv.Itoa(first),
	}
	if cursor != "" {
		argv = append(argv, "-f", "cursor="+cursor)
	}
	return argv
}

// recorded reads the recorded pages of an issue's history: each edit's
// body by when it was made, and the issue's body as it was recorded.
func recorded(t *testing.T, names ...string) (bodies map[string]string, body string) {
	t.Helper()
	bodies = map[string]string{}
	for _, name := range names {
		var page struct {
			Data struct {
				Repository struct {
					Issue struct {
						Body             string
						UserContentEdits struct {
							Nodes []struct {
								EditedAt string
								Diff     string
							}
						}
					}
				}
			}
		}
		if err := json.Unmarshal(testdata(t, name), &page); err != nil {
			t.Fatal(err)
		}
		body = page.Data.Repository.Issue.Body
		for _, n := range page.Data.Repository.Issue.UserContentEdits.Nodes {
			bodies[n.EditedAt] = n.Diff
		}
	}
	return bodies, body
}

// checkHistory fails t unless edits were made at want, in that order,
// each with the body recorded for it.
func checkHistory(t *testing.T, edits []stall.DashboardEdit, bodies map[string]string, want []string) {
	t.Helper()
	got := make([]string, 0, len(edits))
	for _, e := range edits {
		got = append(got, e.EditedAt.UTC().Format(time.RFC3339))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("DashboardHistory() edits made at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for i, e := range edits {
		at := e.EditedAt.UTC().Format(time.RFC3339)
		if b, ok := bodies[at]; !ok || e.Body != b {
			t.Errorf("edit %d, made at %s, has a body of %d bytes, not the %d recorded for it", i, at, len(e.Body), len(b))
		}
	}
}

// TestGHDashboardHistory reads one page of sabnzbd's dashboard's history
// whose oldest edit is before since: the edits come newest first, down to
// the newest made at or before since, and no second page is asked for.
//
//nolint:paralleltest // Not parallel: it lowers the page size every read of a history uses
func TestGHDashboardHistory(t *testing.T) {
	stall.SetPageSize(t, 8)
	bodies, body := recorded(t, "gh-api-graphql-edits-sabnzbd-1.json")
	newest := []string{
		"2026-11-27T03:27:37Z", "2026-11-27T03:18:31Z", "2026-11-27T03:17:24Z", "2026-11-27T03:05:47Z",
		"2026-11-27T02:45:27Z", "2026-11-27T02:13:55Z",
	}
	for _, tt := range []struct {
		name, since string
		want        []string
	}{
		{name: "between-edits", since: "2026-11-27T02:00:00Z", want: append(slices.Clip(newest), "2026-11-27T01:47:47Z")},
		{name: "at-an-edit", since: "2026-11-27T02:13:55Z", want: newest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{
				Argv:   history(sabnzbd, 2, 8, ""),
				Result: stdout(testdata(t, "gh-api-graphql-edits-sabnzbd-1.json")),
			}), Repo: sabnzbd}
			edits, err := gh.DashboardHistory(t.Context(), 2, rfc3339(t, tt.since))
			if err != nil {
				t.Fatal(err)
			}
			checkHistory(t, edits, bodies, tt.want)
			// The newest edit's body is the issue's body now.
			if edits[0].Body != body {
				t.Errorf("the newest edit's body is not the issue's")
			}
		})
	}
}

// TestGHDashboardHistoryPages reads sabnzbd's dashboard's history over two
// pages: down to the newest edit at or before since, when there is one,
// and otherwise down to its creation, which is what there is.
//
//nolint:paralleltest // Not parallel: it lowers the page size every read of a history uses
func TestGHDashboardHistoryPages(t *testing.T) {
	stall.SetPageSize(t, 8)
	bodies, _ := recorded(t, "gh-api-graphql-edits-sabnzbd-1.json", "gh-api-graphql-edits-sabnzbd-2.json")
	first := []string{
		"2026-11-27T03:27:37Z", "2026-11-27T03:18:31Z", "2026-11-27T03:17:24Z", "2026-11-27T03:05:47Z",
		"2026-11-27T02:45:27Z", "2026-11-27T02:13:55Z", "2026-11-27T01:47:47Z", "2026-11-26T10:42:55Z",
	}
	for _, tt := range []struct {
		name, since string
		want        []string
	}{
		{
			name: "stops", since: "2026-11-26T09:30:00Z",
			want: append(slices.Clip(first), "2026-11-26T09:35:26Z", "2026-11-26T09:25:37Z"),
		},
		{
			// The history ends before since: with its creation, and no error
			name: "ends-before-since", since: "2026-11-01T00:00:00Z",
			want: append(slices.Clip(first), "2026-11-26T09:35:26Z", "2026-11-26T09:25:37Z", "2026-11-26T08:56:55Z", "2026-11-26T06:52:53Z"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gh := stall.GH{Run: execx.NewFake(t,
				execx.Call{Argv: history(sabnzbd, 2, 8, ""), Result: stdout(testdata(t, "gh-api-graphql-edits-sabnzbd-1.json"))},
				execx.Call{
					Argv:   history(sabnzbd, 2, 8, "Y3Vyc29yOnYyOpHPAAAAATnNQEw="),
					Result: stdout(testdata(t, "gh-api-graphql-edits-sabnzbd-2.json")),
				},
			), Repo: sabnzbd}
			edits, err := gh.DashboardHistory(t.Context(), 2, rfc3339(t, tt.since))
			if err != nil {
				t.Fatal(err)
			}
			checkHistory(t, edits, bodies, tt.want)
		})
	}
}

// TestGHDashboardHistoryTruncated reads oci-image-template's dashboard,
// edited 100 times, as many as GitHub keeps: its original body and the
// latest 99, with what came between gone. The original body, of
// 2026-11-13T07:45:38Z, is left out, since it did not stand until the
// oldest edit kept, of 2026-11-16T01:50:09Z. So whether since is before
// the original or in the days whose edits are gone, the history ends with
// that oldest edit kept, newer than since, and no error.
//
//nolint:paralleltest // Not parallel: it lowers the page size every read of a history uses
func TestGHDashboardHistoryTruncated(t *testing.T) {
	stall.SetPageSize(t, 5)
	bodies, _ := recorded(t, "gh-api-graphql-edits-template-1.json", "gh-api-graphql-edits-template-20.json")
	want := []string{
		"2026-11-27T03:23:06Z", "2026-11-27T03:18:03Z", "2026-11-27T03:17:04Z", "2026-11-27T03:05:18Z", "2026-11-27T02:53:59Z",
		"2026-11-17T01:25:00Z", "2026-11-17T01:20:36Z", "2026-11-17T01:16:34Z", "2026-11-16T01:50:09Z",
	}
	for _, tt := range []struct{ name, since string }{
		{name: "before-the-original", since: "2026-11-01T00:00:00Z"},
		{name: "in-the-gap", since: "2026-11-15T00:00:00Z"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gh := stall.GH{Run: execx.NewFake(t,
				execx.Call{Argv: history(template, 3, 5, ""), Result: stdout(testdata(t, "gh-api-graphql-edits-template-1.json"))},
				execx.Call{
					Argv:   history(template, 3, 5, "Y3Vyc29yOnYyOpHPAAAAATqso38="),
					Result: stdout(testdata(t, "gh-api-graphql-edits-template-20.json")),
				},
			), Repo: template}
			edits, err := gh.DashboardHistory(t.Context(), 3, rfc3339(t, tt.since))
			if err != nil {
				t.Fatal(err)
			}
			checkHistory(t, edits, bodies, want)
		})
	}
}

// TestGHDashboardHistoryEditLimit pins where the original body is left
// out: at 100 edits, as many as GitHub keeps, and not one fewer, since an
// issue edited 99 times has lost none of them.
func TestGHDashboardHistoryEditLimit(t *testing.T) {
	t.Parallel()

	created := "2026-11-01T00:00:00Z"
	tests := []struct {
		total int
		want  []string
	}{
		{total: 99, want: []string{"2026-11-03T00:00:00Z", "2026-11-02T00:00:00Z", created}},
		{total: 100, want: []string{"2026-11-03T00:00:00Z", "2026-11-02T00:00:00Z"}},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.total), func(t *testing.T) {
			t.Parallel()
			page := fmt.Sprintf(`{"data":{"repository":{"issue":{"createdAt":%q,"body":"c",`+
				`"userContentEdits":{"totalCount":%d,"pageInfo":{"hasNextPage":false,"endCursor":"x"},"nodes":[`+
				`{"editedAt":"2026-11-03T00:00:00Z","diff":"c"},{"editedAt":"2026-11-02T00:00:00Z","diff":"b"},`+
				`{"editedAt":%q,"diff":"a"}]}}}}}`, created, tt.total, created)
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: history(baikal, 94, 100, ""), Result: stdout([]byte(page))}), Repo: baikal}
			edits, err := gh.DashboardHistory(t.Context(), 94, rfc3339(t, "2026-10-01T00:00:00Z"))
			if err != nil {
				t.Fatal(err)
			}
			checkHistory(t, edits, map[string]string{"2026-11-03T00:00:00Z": "c", "2026-11-02T00:00:00Z": "b", created: "a"}, tt.want)
		})
	}
}

// TestGHDashboardHistoryNeverEdited reads a dashboard GitHub lists no
// edits of: its history is its creation, with the body it has now.
func TestGHDashboardHistoryNeverEdited(t *testing.T) {
	t.Parallel()
	_, body := recorded(t, "gh-api-graphql-edits-never-sabnzbd.json")
	gh := stall.GH{Run: execx.NewFake(t, execx.Call{
		Argv:   history(sabnzbd, 2, 100, ""),
		Result: stdout(testdata(t, "gh-api-graphql-edits-never-sabnzbd.json")),
	}), Repo: sabnzbd}
	edits, err := gh.DashboardHistory(t.Context(), 2, rfc3339(t, "2026-11-27T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	checkHistory(t, edits, map[string]string{"2026-11-26T06:52:53Z": body}, []string{"2026-11-26T06:52:53Z"})
}

func TestGHDashboardHistoryFails(t *testing.T) {
	t.Parallel()

	// What gh 2.105.0 printed on 2026-11-27 for an issue
	// baikal-oci-image does not have.
	missing := `{"data":{"repository":{"issue":null}},"errors":[{"type":"NOT_FOUND","path":["repository","issue"],` +
		`"locations":[{"line":1,"column":113}],"message":"Could not resolve to an Issue with the number of 999999."}]}`
	tests := []struct {
		name    string
		repo    string
		number  int
		calls   []execx.Call
		wantErr []string
	}{
		{
			name: "gh-fails", repo: baikal, number: 999999,
			calls: []execx.Call{{Argv: history(baikal, 999999, 100, ""), Result: execx.Result{
				Stdout: []byte(missing),
				Stderr: []byte("gh: Could not resolve to an Issue with the number of 999999.\n"),
				Code:   1,
			}}},
			wantErr: []string{"gh api graphql", "Could not resolve to an Issue with the number of 999999."},
		},
		{
			name: "not-json", repo: baikal, number: 94,
			calls:   []execx.Call{{Argv: history(baikal, 94, 100, ""), Result: stdout([]byte("<html>"))}},
			wantErr: []string{"gh api graphql", "decode"},
		},
		{
			name: "no-issue", repo: baikal, number: 94,
			calls:   []execx.Call{{Argv: history(baikal, 94, 100, ""), Result: stdout([]byte(`{"data":{"repository":{"issue":null}}}`))}},
			wantErr: []string{"#94", baikal},
		},
		{
			// Not owner/name, which never reaches gh
			name: "not-a-repository", repo: "baikal-oci-image", number: 94,
			wantErr: []string{`"baikal-oci-image"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, tt.calls...), Repo: tt.repo}
			edits, err := gh.DashboardHistory(t.Context(), tt.number, rfc3339(t, "2026-11-27T00:00:00Z"))
			if err == nil {
				t.Fatalf("DashboardHistory() = %+v, want an error", edits)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("DashboardHistory() error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// TestGHDashboardHistoryDeletedRevision checks that an edit whose body
// someone deleted from the history fails the read when the history
// reaches it, and only then: whether a line was there is not known.
func TestGHDashboardHistoryDeletedRevision(t *testing.T) {
	t.Parallel()

	page := `{"data":{"repository":{"issue":{"createdAt":"2026-11-01T00:00:00Z","body":"c",` +
		`"userContentEdits":{"totalCount":3,"pageInfo":{"hasNextPage":false,"endCursor":"x"},"nodes":[` +
		`{"editedAt":"2026-11-03T00:00:00Z","diff":"c"},{"editedAt":"2026-11-02T00:00:00Z","diff":null},` +
		`{"editedAt":"2026-11-01T00:00:00Z","diff":"a"}]}}}}}`
	tests := []struct {
		name, since string
		wantErr     bool
	}{
		{name: "reached", since: "2026-11-01T12:00:00Z", wantErr: true},
		{name: "at-since", since: "2026-11-02T00:00:00Z", wantErr: true},
		{name: "beyond-since", since: "2026-11-03T00:00:00Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gh := stall.GH{Run: execx.NewFake(t, execx.Call{Argv: history(baikal, 94, 100, ""), Result: stdout([]byte(page))}), Repo: baikal}
			edits, err := gh.DashboardHistory(t.Context(), 94, rfc3339(t, tt.since))
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "2026-11-02T00:00:00Z") {
					t.Errorf("DashboardHistory() = %+v, %v; want an error naming the edit of 2026-11-02T00:00:00Z", edits, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			checkHistory(t, edits, map[string]string{"2026-11-03T00:00:00Z": "c"}, []string{"2026-11-03T00:00:00Z"})
		})
	}
}

// scriptedPages scripts the first n pages of a history, one edit each, all
// newer than 2026-11-26; the last page says another follows when more.
func scriptedPages(n int, more bool) []execx.Call {
	calls := make([]execx.Call, 0, n)
	for k := 1; k <= n; k++ {
		cursor := ""
		if k > 1 {
			cursor = fmt.Sprintf("c%d", k-1)
		}
		next := k < n || more
		edited := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC).Add(-time.Duration(k) * time.Minute)
		page := fmt.Sprintf(`{"data":{"repository":{"issue":{"createdAt":"2026-11-01T00:00:00Z","body":"b",`+
			`"userContentEdits":{"totalCount":21,"pageInfo":{"hasNextPage":%t,"endCursor":"c%d"},"nodes":[{"editedAt":%q,"diff":"b%d"}]}}}}}`,
			next, k, edited.Format(time.RFC3339), k)
		calls = append(calls, execx.Call{Argv: history(baikal, 94, 100, cursor), Result: stdout([]byte(page))})
	}
	return calls
}

// TestGHDashboardHistoryPageCap checks that a history is read over at
// most 20 pages: one that goes on past them fails, rather than be read in
// part, without asking for a 21st.
func TestGHDashboardHistoryPageCap(t *testing.T) {
	t.Parallel()

	since := rfc3339(t, "2026-11-26T00:00:00Z")
	t.Run("20-pages", func(t *testing.T) {
		t.Parallel()
		gh := stall.GH{Run: execx.NewFake(t, scriptedPages(20, false)...), Repo: baikal}
		edits, err := gh.DashboardHistory(t.Context(), 94, since)
		if err != nil {
			t.Fatal(err)
		}
		if len(edits) != 20 {
			t.Errorf("DashboardHistory() returned %d edits, want 20", len(edits))
		}
	})
	t.Run("more", func(t *testing.T) {
		t.Parallel()
		gh := stall.GH{Run: execx.NewFake(t, scriptedPages(20, true)...), Repo: baikal}
		edits, err := gh.DashboardHistory(t.Context(), 94, since)
		if err == nil || !strings.Contains(err.Error(), "20 pages") {
			t.Errorf("DashboardHistory() = %d edits, %v; want an error naming 20 pages", len(edits), err)
		}
	})
}
