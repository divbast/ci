// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

const (
	image    = "ghcr.io/divbast/librespeed:latest"
	revision = "24e63e21ef880cd22c26964ee987fa593f5e92fc"
)

var (
	inspect = []string{"skopeo", "inspect", "--raw", "--no-creds", "docker://" + image}
	api     = []string{"gh", "api", "-i", "orgs/divbast/packages/container/librespeed"}
	// What ghcr.io says to an anonymous token request for a package that
	// is missing or private.
	refused = execx.Result{
		Stderr: []byte(`level=fatal msg="Error parsing image name \"docker://` + image +
			`\": fetching manifest latest in ghcr.io/divbast/librespeed: Requesting bearer token: received unexpected HTTP status: 403 Forbidden"`),
		Code: 1,
	}
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		calls      []execx.Call
		wantCode   int
		wantStdout string
		// wantStderr lists what stderr must contain.
		wantStderr []string
	}{
		{
			name: "published",
			args: []string{image},
			calls: []execx.Call{{Argv: inspect, Result: execx.Result{
				Stdout: []byte(`{"annotations":{"org.opencontainers.image.revision":"` + revision + `"}}`),
			}}},
			wantStdout: revision + "\n",
		},
		{
			name: "absent",
			args: []string{image},
			calls: []execx.Call{
				{Argv: inspect, Result: refused},
				{Argv: api, Result: execx.Result{Stdout: []byte("HTTP/2.0 404 Not Found\n\r\n{}"), Code: 1}},
			},
			wantStderr: []string{"nothing is published as " + image + " yet"},
		},
		{
			name: "private",
			args: []string{image},
			calls: []execx.Call{
				{Argv: inspect, Result: refused},
				{Argv: api, Result: execx.Result{Stdout: []byte("HTTP/2.0 200 OK\n\r\n" + `{"visibility":"private"}`)}},
			},
			wantCode:   1,
			wantStderr: []string{"package is private"},
		},
		{
			name: "unreadable",
			args: []string{image},
			calls: []execx.Call{{Argv: inspect, Result: execx.Result{
				Stderr: []byte("received unexpected HTTP status: 503 Service Unavailable"),
				Code:   1,
			}}},
			wantCode:   1,
			wantStderr: []string{"could not read " + image, "503"},
		},
		{
			name:       "no-image",
			wantCode:   2,
			wantStderr: []string{"want one IMAGE, not 0 arguments", "usage:"},
		},
		{
			name:       "two-images",
			args:       []string{image, image},
			wantCode:   2,
			wantStderr: []string{"want one IMAGE, not 2 arguments"},
		},
		{
			name:       "help",
			args:       []string{"-h"},
			wantStderr: []string{"usage: divbast-published-revision IMAGE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := run(t.Context(), tt.args, execx.NewFake(t, tt.calls...), &stdout, &stderr)
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
	}
}
