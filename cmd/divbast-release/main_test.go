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
// breaks something, then c, all pushed. It returns the clone and the
// commits.
func history(t *testing.T) (dir, a, b, c string) {
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
	a = commit("lint: share the recipes\n\nWhy.\n\nDeveloped-by: X <x@x.invalid>")
	gitIn(t, dir, "tag", "v1.0.0")
	b = commit("scan: rename -layout\n\nWhy.\n\nBreaking-change: divbast-scan's -layout is now -oci-layout\nDeveloped-by: X <x@x.invalid>")
	c = commit("docs: say so\n\nWhy.\n\nDeveloped-by: X <x@x.invalid>")
	gitIn(t, dir, "push", "--quiet", "origin", "main", "v1.0.0")
	return dir, a, b, c
}

const notes = "## Breaking changes\n\n- divbast-scan's -layout is now -oci-layout\n\n## Changes\n\n- scan: rename -layout\n- docs: say so\n"

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// args builds the command line from the commits.
		args func(a, b, c string) []string
		// gh is what gh is scripted to be asked; anything else fails.
		gh         func(c string) []execx.Call
		wantCode   int
		wantStdout string
		// wantStderr lists what stderr must contain.
		wantStderr []string
	}{
		{
			name:       "dry-run",
			args:       func(_, _, c string) []string { return []string{"-sha", c, "-dry-run"} },
			wantStdout: "v2.0.0\n\n" + notes,
		},
		// A dry run says what a real one would refuse, and still shows
		// the release.
		{
			name:       "dry-run-not-the-tip",
			args:       func(_, b, _ string) []string { return []string{"-sha", b, "-dry-run"} },
			wantStdout: "v2.0.0\n\n## Breaking changes\n\n- divbast-scan's -layout is now -oci-layout\n\n## Changes\n\n- scan: rename -layout\n",
			wantStderr: []string{"not the tip of origin's main", "would refuse"},
		},
		{
			name: "releases",
			args: func(_, _, c string) []string { return []string{"-sha", c} },
			gh: func(c string) []execx.Call {
				return []execx.Call{{
					Argv:   []string{"gh", "release", "create", "v2.0.0", "--target", c, "--title", "v2.0.0", "--notes-file", "-"},
					Stdin:  []byte(notes),
					Result: execx.Result{Stdout: []byte("https://github.com/divbast/ci/releases/tag/v2.0.0\n")},
				}}
			},
			wantStdout: "https://github.com/divbast/ci/releases/tag/v2.0.0\nreleased v2.0.0 at ",
		},
		{
			name:       "already-released",
			args:       func(a, _, _ string) []string { return []string{"-sha", a} },
			wantStdout: " is already released as v1.0.0: nothing to do\n",
		},
		{
			name:       "not-the-tip",
			args:       func(_, b, _ string) []string { return []string{"-sha", b} },
			wantCode:   1,
			wantStderr: []string{"not the tip of origin's main"},
		},
		{
			name: "gh-fails",
			args: func(_, _, c string) []string { return []string{"-sha", c} },
			gh: func(c string) []execx.Call {
				return []execx.Call{{
					Argv:   []string{"gh", "release", "create", "v2.0.0", "--target", c, "--title", "v2.0.0", "--notes-file", "-"},
					Stdin:  []byte(notes),
					Result: execx.Result{Code: 1, Stderr: []byte("HTTP 403: Resource not accessible by integration\n")},
				}}
			},
			wantCode:   1,
			wantStderr: []string{"Resource not accessible"},
		},
		{
			name: "not-a-commit",
			args: func(_, _, _ string) []string {
				return []string{"-sha", "0000000000000000000000000000000000000000", "-dry-run"}
			},
			wantCode:   1,
			wantStderr: []string{"not a commit"},
		},
		{
			name:       "no-sha",
			args:       func(_, _, _ string) []string { return []string{"-dry-run"} },
			wantCode:   2,
			wantStderr: []string{"-sha is required"},
		},
		{
			name:       "short-sha",
			args:       func(_, _, c string) []string { return []string{"-sha", c[:7]} },
			wantCode:   2,
			wantStderr: []string{"full 40-character commit SHA"},
		},
		{
			name:       "stray-argument",
			args:       func(_, _, c string) []string { return []string{"-sha", c, "now"} },
			wantCode:   2,
			wantStderr: []string{`unexpected argument "now"`},
		},
		{
			name:       "help",
			args:       func(_, _, _ string) []string { return []string{"-h"} },
			wantStderr: []string{"-dry-run"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir, a, b, c := history(t)
			var calls []execx.Call
			if tt.gh != nil {
				calls = tt.gh(c)
			}
			args := tt.args(a, b, c)
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, inDir{dir}, execx.NewFake(t, calls...), &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d; stderr:\n%s", args, code, tt.wantCode, stderr.String())
			}
			// A SHA in the output varies with the repository; the rest of
			// a line is checked by prefix or suffix.
			switch got := stdout.String(); {
			case tt.wantStdout == "" && got != "":
				t.Errorf("run(%q) stdout = %q, want nothing", args, got)
			case strings.HasPrefix(tt.wantStdout, " ") && !strings.HasSuffix(got, tt.wantStdout):
				t.Errorf("run(%q) stdout = %q, want it to end %q", args, got, tt.wantStdout)
			case strings.HasSuffix(tt.wantStdout, " ") && !strings.HasPrefix(got, tt.wantStdout):
				t.Errorf("run(%q) stdout = %q, want it to start %q", args, got, tt.wantStdout)
			case !strings.HasPrefix(tt.wantStdout, " ") && !strings.HasSuffix(tt.wantStdout, " ") && got != tt.wantStdout:
				t.Errorf("run(%q) stdout = %q, want %q", args, got, tt.wantStdout)
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("run(%q) stderr = %q, want it to contain %q", args, stderr.String(), s)
				}
			}
		})
	}
}
