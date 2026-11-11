// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"maps"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/divbast/ci/internal/execx"
)

const (
	repo     = "divbast/librespeed-oci-image"
	image    = "ghcr.io/divbast/librespeed:latest"
	revision = "24e63e21ef880cd22c26964ee987fa593f5e92fc"
)

var (
	prList = []string{
		"gh", "pr", "list", "--repo", repo, "--author", "app/divbast-renovate", "--state", "open",
		"--limit", "40", "--json", "number,title,createdAt,commits,statusCheckRollup",
	}
	inspect  = []string{"skopeo", "inspect", "--raw", "--no-creds", "docker://" + image}
	pkgAPI   = []string{"gh", "api", "-i", "orgs/divbast/packages/container/librespeed"}
	mainAPI  = []string{"gh", "api", "-i", "repos/divbast/librespeed-oci-image/commits/main"}
	repoAPI  = []string{"gh", "api", "-i", "repos/divbast/librespeed-oci-image"}
	refused  = execx.Result{Stderr: []byte("Requesting bearer token: received unexpected HTTP status: 403 Forbidden"), Code: 1}
	indexOut = execx.Result{Stdout: []byte(`{"annotations":{"org.opencontainers.image.revision":"` + revision + `"}}`)}
)

func successRuns(workflow string) []string {
	return []string{"gh", "run", "list", "--repo", repo, "--workflow", workflow, "--status", "success", "--limit", "1", "--json", "createdAt"}
}

func slotRuns(workflow string) []string {
	return []string{
		"gh", "run", "list", "--repo", repo, "--workflow", workflow, "--event", "schedule", "--branch", "main",
		"--limit", "10", "--json", "headSha,createdAt,status,url",
	}
}

// ok is a command that printed out and exited 0.
func ok(out string) execx.Result { return execx.Result{Stdout: []byte(out)} }

// apiOK is gh api -i answering 200 with body.
func apiOK(body string) execx.Result {
	return ok("HTTP/2.0 200 OK\nContent-Type: application/json; charset=utf-8\r\n\r\n" + body)
}

// env is the environment stall.yml gives the command, before a test's
// changes: a value of "" unsets the variable.
func env(changes map[string]string) func(string) string {
	vars := map[string]string{
		"GH_REPO":     repo,
		"OPEN_DAYS":   "14",
		"STUCK_HOURS": "24",
		"RUN_HOURS":   "24",
		"LOST_SLOTS":  "2",
		"PUBLISHED":   image,
	}
	maps.Copy(vars, changes)
	return func(k string) string { return vars[k] }
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		calls      []execx.Call
		wantCode   int
		wantStdout string
		// wantStderr lists what stderr must contain.
		wantStderr []string
	}{
		{
			name:       "open",
			args:       []string{"open"},
			calls:      []execx.Call{{Argv: prList, Result: ok("[]\n")}},
			wantStdout: "no Renovate pull request open more than 14 days\n",
		},
		{
			// The bubble's clock reads 2000-01-01.
			name: "open-stalled",
			args: []string{"open"},
			calls: []execx.Call{{Argv: prList, Result: ok(`[` +
				`{"number":4,"title":"ci: update y","createdAt":"1999-12-01T00:00:00Z","commits":[{"committedDate":"1999-12-01T00:00:00Z"}],"statusCheckRollup":[]},` +
				`{"number":3,"title":"ci: update x","createdAt":"1999-11-01T00:00:00Z","commits":[{"committedDate":"1999-11-01T00:00:00Z"}],"statusCheckRollup":[]}]`)}},
			wantCode:   1,
			wantStdout: "Open more than 14 days:\n  #4 ci: update y\n  #3 ci: update x\n",
		},
		{
			name: "stuck",
			args: []string{"stuck"},
			calls: []execx.Call{{Argv: prList, Result: ok(`[{"number":3,"title":"ci: update x","createdAt":"1999-12-01T00:00:00Z",` +
				`"commits":[{"committedDate":"1999-12-01T00:00:00Z"}],"statusCheckRollup":[{"__typename":"CheckRun","name":"lint / lint","conclusion":"SUCCESS"}]}]`)}},
			wantCode:   1,
			wantStdout: "Not green for more than 24 hours:\n  #3 ci: update x\n",
		},
		{
			name: "stuck-green",
			args: []string{"stuck"},
			calls: []execx.Call{{Argv: prList, Result: ok(`[{"number":3,"title":"ci: update x","createdAt":"1999-12-01T00:00:00Z",` +
				`"commits":[{"committedDate":"1999-12-01T00:00:00Z"}],"statusCheckRollup":[{"__typename":"CheckRun","name":"lint / lint","conclusion":"SUCCESS"},` +
				`{"__typename":"CheckRun","name":"required","conclusion":"SUCCESS"}]}]`)}},
			wantStdout: "no Renovate pull request red or pending more than 24 hours\n",
		},
		{
			name:       "renovate",
			args:       []string{"renovate"},
			calls:      []execx.Call{{Argv: successRuns("renovate.yml"), Result: ok(`[{"createdAt":"1999-12-31T23:00:00Z"}]`)}},
			wantStdout: "Renovate succeeded within 24 hours\n",
		},
		{
			name: "renovate-workflow",
			args: []string{"renovate"},
			env:  map[string]string{"RENOVATE_WORKFLOW": "self-renovate.yml"},
			calls: []execx.Call{
				{Argv: successRuns("self-renovate.yml"), Result: ok("[]")},
				{Argv: repoAPI, Result: apiOK(`{"created_at":"1999-12-25T00:00:00Z"}`)},
			},
			wantCode:   1,
			wantStdout: "Renovate silent for more than 24 hours:\n  no successful Renovate run\n",
		},
		{
			name: "slots-published",
			args: []string{"slots"},
			calls: []execx.Call{
				{Argv: inspect, Result: indexOut},
				{Argv: mainAPI, Result: apiOK(`{"sha":"` + revision + `"}`)},
			},
			wantStdout: "main " + revision + " is published\n",
		},
		{
			name: "slots-first-day",
			args: []string{"slots"},
			env:  map[string]string{"SLOT_WORKFLOW": "publish.yml"},
			calls: []execx.Call{
				{Argv: inspect, Result: refused},
				{Argv: pkgAPI, Result: execx.Result{Stdout: []byte("HTTP/2.0 404 Not Found\n\r\n{}"), Code: 1}},
				{Argv: mainAPI, Result: apiOK(`{"sha":"` + revision + `"}`)},
				{Argv: slotRuns("publish.yml"), Result: ok("[]")},
				{Argv: repoAPI, Result: apiOK(`{"created_at":"1999-12-31T21:00:00Z"}`)},
			},
			wantStdout: "main " + revision + " is ahead of :latest (absent), with 0 lost slot(s), under 2\n",
		},
		{
			name: "slots-private",
			args: []string{"slots"},
			calls: []execx.Call{
				{Argv: inspect, Result: refused},
				{Argv: pkgAPI, Result: apiOK(`{"visibility":"private"}`)},
			},
			wantCode: 1,
			wantStdout: image + " is private, so no one can pull it:\n" +
				`  package is private: GitHub gives ghcr.io/divbast/librespeed the visibility "private", so no anonymous client can read ` + image + "\n",
		},
		{
			name: "slots-unreadable",
			args: []string{"slots"},
			calls: []execx.Call{{Argv: inspect, Result: execx.Result{
				Stderr: []byte("received unexpected HTTP status: 503 Service Unavailable"),
				Code:   1,
			}}},
			wantCode:   2,
			wantStderr: []string{"divbast-stall: could not read " + image, "503"},
		},
		{
			name:       "slots-nothing-published",
			args:       []string{"slots"},
			env:        map[string]string{"PUBLISHED": ""},
			wantCode:   2,
			wantStderr: []string{"PUBLISHED is not set"},
		},
		{
			name:       "gh-fails",
			args:       []string{"open"},
			calls:      []execx.Call{{Argv: prList, Result: execx.Result{Stderr: []byte("HTTP 401: Bad credentials"), Code: 1}}},
			wantCode:   2,
			wantStderr: []string{"Bad credentials"},
		},
		{
			name:       "no-repository",
			args:       []string{"open"},
			env:        map[string]string{"GH_REPO": ""},
			wantCode:   2,
			wantStderr: []string{"GH_REPO is not set"},
		},
		{
			name:       "no-limit",
			args:       []string{"stuck"},
			env:        map[string]string{"STUCK_HOURS": ""},
			wantCode:   2,
			wantStderr: []string{"STUCK_HOURS is not set"},
		},
		{
			name:       "limit-not-a-number",
			args:       []string{"renovate"},
			env:        map[string]string{"RUN_HOURS": "a day"},
			wantCode:   2,
			wantStderr: []string{`RUN_HOURS is "a day", not a whole number`},
		},
		{
			name:       "limit-negative",
			args:       []string{"slots"},
			env:        map[string]string{"LOST_SLOTS": "-1"},
			wantCode:   2,
			wantStderr: []string{`LOST_SLOTS is "-1", not a whole number`},
		},
		{
			// Only the check's own limit is read.
			name:       "other-limits-unset",
			args:       []string{"open"},
			env:        map[string]string{"STUCK_HOURS": "", "RUN_HOURS": "x", "LOST_SLOTS": "", "PUBLISHED": ""},
			calls:      []execx.Call{{Argv: prList, Result: ok("[]")}},
			wantStdout: "no Renovate pull request open more than 14 days\n",
		},
		{
			name:       "no-check",
			wantCode:   2,
			wantStderr: []string{"want one check, not 0 arguments", "usage: divbast-stall open|stuck|renovate|slots"},
		},
		{
			name:       "two-checks",
			args:       []string{"open", "stuck"},
			wantCode:   2,
			wantStderr: []string{"want one check, not 2 arguments"},
		},
		{
			name:       "no-such-check",
			args:       []string{"lint"},
			wantCode:   2,
			wantStderr: []string{`no such check: "lint"`, "usage:"},
		},
		{
			name:       "help",
			args:       []string{"-h"},
			wantStderr: []string{"usage: divbast-stall open|stuck|renovate|slots"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := run(t.Context(), tt.args, env(tt.env), execx.NewFake(t, tt.calls...), &stdout, &stderr)
				if code != tt.wantCode {
					t.Errorf("run(%q) = %d, want %d; stderr: %s", tt.args, code, tt.wantCode, stderr.String())
				}
				if got := stdout.String(); got != tt.wantStdout {
					t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
				}
				for _, want := range tt.wantStderr {
					if !strings.Contains(stderr.String(), want) {
						t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
					}
				}
			})
		})
	}
}
