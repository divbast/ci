// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall_test

import (
	"context"
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
// shows it in the run, and its conclusion (backlog CI-7).
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
			count:  8, has: stall.Job{Name: "publish (baikal)", Conclusion: "success"},
		},
		{
			// The run failed in its arm64 build, and so never published.
			name: "baikal-publish-skipped", repo: baikal, id: 42310287997,
			result: stdout(testdata(t, "gh-run-view-jobs-baikal-failed.json")),
			count:  6, has: stall.Job{Name: "publish", Conclusion: "skipped"},
		},
		{
			// GitHub skipped the publish matrix before expanding it, and
			// names the job as written
			name: "frankenphp-matrix-skipped", repo: frankenphp, id: 43481642005,
			result: stdout(testdata(t, "gh-run-view-jobs-frankenphp-skipped.json")),
			count:  7, has: stall.Job{Name: "publish (${{ matrix.app }})", Conclusion: "skipped"},
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
