// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// inDir runs every command with git's -C dir.
type inDir struct{ dir string }

func (r inDir) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	return execx.OS{}.Run(ctx, name, append([]string{"-C", r.dir}, args...)...)
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{
		"-c", "user.name=divbast test", "-c", "user.email=test@divbast.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
	}, args...)
	res, err := inDir{dir}.Run(t.Context(), "git", argv...)
	if err != nil || res.Code != 0 {
		t.Fatalf("git %q: %v, exit %d: %s", args, err, res.Code, res.Stderr)
	}
	return strings.TrimSpace(string(res.Stdout))
}

// history is a clone with an origin: a, tagged v1.0.0, then b, which
// breaks something, then c, all pushed, and side, a commit on a branch
// from a that main does not hold. It returns the clone and the commits.
func history(t *testing.T) (dir string, h commits) {
	t.Helper()
	base := t.TempDir()
	dir, origin := filepath.Join(base, "work"), filepath.Join(base, "origin.git")
	gitIn(t, base, "init", "--quiet", "--bare", "--initial-branch=main", origin)
	gitIn(t, base, "init", "--quiet", "--initial-branch=main", dir)
	gitIn(t, dir, "remote", "add", "origin", origin)
	commit := func(msg string) string {
		gitIn(t, dir, "commit", "--quiet", "--allow-empty", "--message", msg)
		return gitIn(t, dir, "rev-parse", "HEAD")
	}
	h.a = commit("lint: share the recipes\n\nWhy.\n\nDeveloped-by: X <x@x.invalid>")
	gitIn(t, dir, "tag", "v1.0.0")
	h.b = commit("scan: rename -layout\n\nWhy.\n\nBreaking-change: divbast-scan's -layout is now -oci-layout\nDeveloped-by: X <x@x.invalid>")
	h.c = commit("docs: say so\n\nWhy.\n\nDeveloped-by: X <x@x.invalid>")
	gitIn(t, dir, "push", "--quiet", "origin", "main", "v1.0.0")
	gitIn(t, dir, "checkout", "--quiet", "-b", "side", h.a)
	h.side = commit("side: not on main\n\nDeveloped-by: X <x@x.invalid>")
	gitIn(t, dir, "checkout", "--quiet", "main")
	return dir, h
}

// commits are history's.
type commits struct{ a, b, c, side string }

const (
	notes  = "## Breaking changes\n\n- divbast-scan's -layout is now -oci-layout\n\n## Changes\n\n- scan: rename -layout\n- docs: say so\n"
	notesB = "## Breaking changes\n\n- divbast-scan's -layout is now -oci-layout\n\n## Changes\n\n- scan: rename -layout\n"
)

func create(c string) []string {
	return []string{"gh", "release", "create", "v2.0.0", "--target", c, "--title", "v2.0.0", "--notes-file", "-"}
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args func(h commits) []string
		// gh is what gh is scripted to be asked; anything else fails.
		gh       func(h commits) []execx.Call
		wantCode int
		stdout   func(h commits) string
		// wantStderr lists what stderr must contain.
		wantStderr []string
	}{
		{
			name:   "dry-run",
			args:   func(h commits) []string { return []string{"-sha", h.c, "-dry-run"} },
			stdout: func(commits) string { return "v2.0.0\n\n" + notes },
		},
		// A dry run says what a real one would do, and still shows the
		// release.
		{
			name:       "dry-run-superseded",
			args:       func(h commits) []string { return []string{"-sha", h.b, "-dry-run"} },
			stdout:     func(commits) string { return "v2.0.0\n\n" + notesB },
			wantStderr: []string{"no longer main's tip", "would skip it"},
		},
		{
			name:       "dry-run-not-on-main",
			args:       func(h commits) []string { return []string{"-sha", h.side, "-dry-run"} },
			stdout:     func(commits) string { return "v1.1.0\n\n## Changes\n\n- side: not on main\n" },
			wantStderr: []string{"not on origin's main", "would refuse it"},
		},
		{
			name: "releases",
			args: func(h commits) []string { return []string{"-sha", h.c} },
			gh: func(h commits) []execx.Call {
				return []execx.Call{{
					Argv:   create(h.c),
					Stdin:  []byte(notes),
					Result: execx.Result{Stdout: []byte("https://github.com/divbast/ci/releases/tag/v2.0.0\n")},
				}}
			},
			stdout: func(h commits) string {
				return "https://github.com/divbast/ci/releases/tag/v2.0.0\nreleased v2.0.0 at " + h.c + "\n"
			},
		},
		{
			name: "already-released",
			args: func(h commits) []string { return []string{"-sha", h.a} },
			stdout: func(h commits) string {
				return h.a + " is already released as v1.0.0: nothing to do\n"
			},
		},
		// Ruling R29: a later merge landed first, and its run releases
		// this commit with it.
		{
			name: "superseded",
			args: func(h commits) []string { return []string{"-sha", h.b} },
			stdout: func(h commits) string {
				return h.b + " is no longer main's tip (" + h.c + "); the run for " + h.c + " releases it\n"
			},
		},
		{
			name:       "not-on-main",
			args:       func(h commits) []string { return []string{"-sha", h.side} },
			wantCode:   1,
			wantStderr: []string{"is not on origin's main"},
		},
		{
			name: "gh-fails",
			args: func(h commits) []string { return []string{"-sha", h.c} },
			gh: func(h commits) []execx.Call {
				return []execx.Call{{
					Argv:   create(h.c),
					Stdin:  []byte(notes),
					Result: execx.Result{Code: 1, Stderr: []byte("HTTP 403: Resource not accessible by integration\n")},
				}}
			},
			wantCode:   1,
			wantStderr: []string{"Resource not accessible"},
		},
		{
			name: "not-a-commit",
			args: func(commits) []string {
				return []string{"-sha", "0000000000000000000000000000000000000000", "-dry-run"}
			},
			wantCode:   1,
			wantStderr: []string{"not a commit"},
		},
		{
			name:       "no-sha",
			args:       func(commits) []string { return []string{"-dry-run"} },
			wantCode:   2,
			wantStderr: []string{"-sha is required"},
		},
		{
			name:       "short-sha",
			args:       func(h commits) []string { return []string{"-sha", h.c[:7]} },
			wantCode:   2,
			wantStderr: []string{"full 40-character commit SHA"},
		},
		{
			name:       "stray-argument",
			args:       func(h commits) []string { return []string{"-sha", h.c, "now"} },
			wantCode:   2,
			wantStderr: []string{`unexpected argument "now"`},
		},
		{
			name:       "help",
			args:       func(commits) []string { return []string{"-h"} },
			wantStderr: []string{"-dry-run"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir, h := history(t)
			var calls []execx.Call
			if tt.gh != nil {
				calls = tt.gh(h)
			}
			args := tt.args(h)
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, inDir{dir}, execx.NewFake(t, calls...), &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d; stderr:\n%s", args, code, tt.wantCode, stderr.String())
			}
			want := ""
			if tt.stdout != nil {
				want = tt.stdout(h)
			}
			if got := stdout.String(); got != want {
				t.Errorf("run(%q) stdout = %q, want %q", args, got, want)
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("run(%q) stderr = %q, want it to contain %q", args, stderr.String(), s)
				}
			}
		})
	}
}
