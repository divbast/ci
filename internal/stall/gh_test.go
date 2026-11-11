// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
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

// testdata returns a recording from testdata, every one made with gh
// 2.103.3 on 2026-11-11 by the owner's token, as GH would run it:
//
//	gh-pr-list-open-baikal.json        gh pr list --repo divbast/baikal-oci-image --author app/divbast-renovate --state open --limit 40 --json number,title,createdAt,commits,statusCheckRollup
//	gh-pr-list-merged-librespeed.json  gh pr list --repo divbast/librespeed-oci-image --author app/divbast-renovate --state merged --limit 40 --json number,title,createdAt,commits,statusCheckRollup
//	gh-pr-list-pending-baikal.json     gh pr list --repo divbast/baikal-oci-image --state all --search status:pending --limit 40 --json number,title,createdAt,commits,statusCheckRollup
//	gh-run-list-renovate-librespeed.json  gh run list --repo divbast/librespeed-oci-image --workflow renovate.yml --status success --limit 1 --json createdAt
//	gh-run-list-slots-baikal.json      gh run list --repo divbast/baikal-oci-image --workflow build.yml --event schedule --branch main --limit 10 --json headSha,createdAt,status,url
//	gh-run-list-slots-librespeed.json  the same for divbast/librespeed-oci-image
//	gh-api-commits-main-baikal.txt     gh api -i repos/divbast/baikal-oci-image/commits/main
//	gh-api-compare-ahead-baikal.txt    gh api -i repos/divbast/baikal-oci-image/compare/<baikalBase>...<baikalMain>
//	gh-api-compare-behind-baikal.txt   gh api -i repos/divbast/baikal-oci-image/compare/<baikalMain>...<baikalBase>
//	gh-api-compare-404-baikal.txt      gh api -i repos/divbast/baikal-oci-image/compare/<40 zeros>...<baikalMain>
//	gh-api-repo-baikal.txt             gh api -i repos/divbast/baikal-oci-image
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
		"--limit", "10", "--json", "headSha,createdAt,status,url",
	}
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
		wantErr string
	}{
		{
			name:    "baikal",
			repo:    baikal,
			result:  stdout(testdata(t, "gh-run-list-slots-baikal.json")),
			wantLen: 10,
			want: []stall.Run{
				{
					HeadSHA:   baikalMain,
					Created:   rfc3339(t, "2026-11-10T23:25:56Z"),
					Completed: true,
					URL:       "https://github.com/divbast/baikal-oci-image/actions/runs/42923306213",
				},
			},
		},
		{
			name:   "librespeed",
			repo:   librespeed,
			result: stdout(testdata(t, "gh-run-list-slots-librespeed.json")),
		},
		{
			name: "running",
			repo: baikal,
			result: stdout([]byte(`[{"createdAt":"2026-11-11T18:50:00Z","headSha":"` + baikalMain +
				`","status":"in_progress","url":"https://github.com/divbast/baikal-oci-image/actions/runs/1"}]`)),
			wantLen: 1,
			want: []stall.Run{{
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
				if got := runs[i]; got.HeadSHA != want.HeadSHA || !got.Created.Equal(want.Created) ||
					got.Completed != want.Completed || got.URL != want.URL {
					t.Errorf("run %d = %+v, want %+v", i, got, want)
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
