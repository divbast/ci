// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package ghapi_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
)

// recorded returns what gh api -i printed on stdout for one of the
// responses in testdata, each recorded with gh 2.103.3 by:
//
//	gh-api-200.txt  gh api -i users/divbast
//	gh-api-404.txt  gh api -i orgs/divbast/packages/container/no-such-package
//	gh-api-403.txt  gh api -i orgs/divbast/packages/container/librespeed
//	                (a token without read:packages)
func recorded(t *testing.T, name string) []byte {
	t.Helper()
	return readTestdata(t, name)
}

// readTestdata returns the file name in testdata.
func readTestdata(t *testing.T, name string) []byte {
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

// profile is the part of a users/ response the 200 case decodes.
type profile struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

func TestAPI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		repo string
		path string
		// argPath is the endpoint gh is expected to be given.
		argPath    string
		result     execx.Result
		runErr     error
		wantStatus int
		want       profile
		// wantErr lists what the error must contain; nil means no error.
		wantErr []string
	}{
		{
			name:       "200-decodes-the-body",
			path:       "users/divbast",
			argPath:    "users/divbast",
			result:     execx.Result{Stdout: recorded(t, "gh-api-200.txt")},
			wantStatus: 200,
			want:       profile{Login: "divbast", Type: "Organization"},
		},
		{
			// gh exits 1 on a 4xx but still prints the response.
			name:    "404-is-a-status-not-an-error",
			path:    "orgs/divbast/packages/container/no-such-package",
			argPath: "orgs/divbast/packages/container/no-such-package",
			result: execx.Result{
				Stdout: recorded(t, "gh-api-404.txt"),
				Stderr: []byte("gh: Package not found. (HTTP 404)\n"),
				Code:   1,
			},
			wantStatus: 404,
		},
		{
			name:    "403-is-a-status-not-an-error",
			path:    "orgs/divbast/packages/container/librespeed",
			argPath: "orgs/divbast/packages/container/librespeed",
			result: execx.Result{
				Stdout: recorded(t, "gh-api-403.txt"),
				Stderr: []byte("gh: You need at least read:packages scope to get a package. (HTTP 403)\n"),
				Code:   1,
			},
			wantStatus: 403,
		},
		{
			name:       "lf-only-and-no-headers",
			path:       "users/divbast",
			argPath:    "users/divbast",
			result:     execx.Result{Stdout: []byte("HTTP/1.1 200 OK\n\n{\"login\":\"divbast\"}\n")},
			wantStatus: 200,
			want:       profile{Login: "divbast"},
		},
		{
			name:       "204-has-no-body",
			path:       "users/divbast",
			argPath:    "users/divbast",
			result:     execx.Result{Stdout: []byte("HTTP/2.0 204 No Content\n\r\n")},
			wantStatus: 204,
		},
		{
			name:       "repo-fills-placeholders",
			repo:       "divbast/ci",
			path:       "repos/{owner}/{repo}/pulls",
			argPath:    "repos/divbast/ci/pulls",
			result:     execx.Result{Stdout: []byte("HTTP/2.0 200 OK\r\n\r\n{}")},
			wantStatus: 200,
		},
		{
			name:       "no-repo-leaves-placeholders-to-gh",
			path:       "repos/{owner}/{repo}/pulls",
			argPath:    "repos/{owner}/{repo}/pulls",
			result:     execx.Result{Stdout: []byte("HTTP/2.0 200 OK\r\n\r\n{}")},
			wantStatus: 200,
		},
		{
			// Recorded: gh api -i --hostname no-such-host.invalid users/divbast
			name:    "no-response",
			path:    "users/divbast",
			argPath: "users/divbast",
			result: execx.Result{
				Stderr: []byte("error connecting to no-such-host.invalid\ncheck your internet connection or https://githubstatus.com\n"),
				Code:   1,
			},
			wantErr: []string{"users/divbast", "no response", "error connecting to no-such-host.invalid"},
		},
		{
			name:    "gh-missing",
			path:    "users/divbast",
			argPath: "users/divbast",
			runErr:  exec.ErrNotFound,
			wantErr: []string{"users/divbast", exec.ErrNotFound.Error()},
		},
		{
			name:    "2xx-but-gh-failed",
			path:    "users/divbast",
			argPath: "users/divbast",
			result: execx.Result{
				Stdout: []byte("HTTP/2.0 200 OK\r\n\r\n{\"login\":"),
				Stderr: []byte("gh: unexpected EOF\n"),
				Code:   1,
			},
			wantStatus: 200,
			wantErr:    []string{"exit status 1", "unexpected EOF"},
		},
		{
			name:       "2xx-body-is-not-json",
			path:       "users/divbast",
			argPath:    "users/divbast",
			result:     execx.Result{Stdout: []byte("HTTP/2.0 200 OK\r\n\r\n<html>")},
			wantStatus: 200,
			wantErr:    []string{"decode"},
		},
		{
			name:    "no-status-line",
			path:    "users/divbast",
			argPath: "users/divbast",
			result:  execx.Result{Stdout: []byte("{\"login\":\"divbast\"}")},
			wantErr: []string{"status line"},
		},
		{
			name:    "bad-repo",
			repo:    "divbast",
			path:    "repos/{owner}/{repo}",
			wantErr: []string{`"divbast"`, "owner/name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls []execx.Call
			if tt.argPath != "" {
				calls = append(calls, execx.Call{
					Argv:   []string{"gh", "api", "-i", tt.argPath},
					Result: tt.result,
					Err:    tt.runErr,
				})
			}
			c := ghapi.Client{Run: execx.NewFake(t, calls...), Repo: tt.repo}

			var got profile
			status, err := c.API(t.Context(), tt.path, &got)
			if status != tt.wantStatus {
				t.Errorf("API(%q) status = %d, want %d", tt.path, status, tt.wantStatus)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("API(%q) error = %v, want nil", tt.path, err)
				}
				if got != tt.want {
					t.Errorf("API(%q) decoded %+v, want %+v", tt.path, got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("API(%q) error = nil, want one containing %q", tt.path, tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("API(%q) error = %q, want it to contain %q", tt.path, err, want)
				}
			}
			if tt.runErr != nil && !errors.Is(err, tt.runErr) {
				t.Errorf("API(%q) error = %v, want it to wrap %v", tt.path, err, tt.runErr)
			}
		})
	}
}

// A 4xx body is GitHub's error, not the resource: v is left alone.
func TestAPILeavesVAloneOnError(t *testing.T) {
	t.Parallel()

	c := ghapi.Client{Run: execx.NewFake(t, execx.Call{
		Argv:   []string{"gh", "api", "-i", "orgs/divbast/packages/container/no-such-package"},
		Result: execx.Result{Stdout: recorded(t, "gh-api-404.txt"), Code: 1},
	})}
	got := map[string]any{"kept": true}
	status, err := c.API(t.Context(), "orgs/divbast/packages/container/no-such-package", &got)
	if err != nil || status != 404 {
		t.Fatalf("API() = %d, %v; want 404, nil", status, err)
	}
	if len(got) != 1 || got["kept"] != true {
		t.Errorf("API() changed v to %v on a 404, want it left alone", got)
	}
}
