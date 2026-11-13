// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package publish_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/publish"
)

// Commits of the DAG fakeGit describes: A←B←C on main, at C, and D
// branching off A. E names no commit at all.
var (
	a = strings.Repeat("a", 40)
	b = strings.Repeat("b", 40)
	c = strings.Repeat("c", 40)
	d = strings.Repeat("d", 40)
	e = strings.Repeat("e", 40)
)

// fakeGit answers from a fixed DAG, as git would in a clone with
// origin/main fetched. Like git, it fails on a commit it does not have.
type fakeGit struct {
	parent map[string]string
	main   string
	err    error
}

func newFakeGit() fakeGit {
	return fakeGit{parent: map[string]string{a: "", b: a, c: b, d: a}, main: c}
}

func (g fakeGit) CommitExists(_ context.Context, sha string) (bool, error) {
	if g.err != nil {
		return false, g.err
	}
	_, ok := g.parent[sha]
	return ok, nil
}

func (g fakeGit) IsAncestor(_ context.Context, ancestor, descendant string) (bool, error) {
	if g.err != nil {
		return false, g.err
	}
	if descendant == "origin/main" {
		descendant = g.main
	}
	for _, sha := range []string{ancestor, descendant} {
		if _, ok := g.parent[sha]; !ok {
			return false, fmt.Errorf("fatal: Not a valid commit name %s", sha)
		}
	}
	for sha := descendant; sha != ""; sha = g.parent[sha] {
		if sha == ancestor {
			return true, nil
		}
	}
	return false, nil
}

func TestDecide(t *testing.T) {
	t.Parallel()

	errGit := errors.New("git broke")

	tests := []struct {
		name          string
		git           fakeGit
		event         publish.Event
		built         string
		published     string
		contentChange string
		want          publish.Decision
		// wantErr is the whole error message; empty means no error.
		wantErr string
		// wantErrIs is an error the error must wrap, when its message is
		// not the point.
		wantErrIs error
	}{
		// Every branch of librespeed-oci-image's publish-decision.sh, with
		// its reason strings.
		{
			name:      "nothing-published",
			event:     publish.EventSchedule,
			built:     c,
			published: "",
			want:      publish.Decision{Publish: true, Reason: "nothing is published yet"},
		},
		{
			name:      "pull_request",
			event:     "pull_request",
			built:     c,
			published: b,
			wantErr:   "only a push to main, the daily slot and a manual run publish, not a pull_request run",
		},
		{
			name:      "not-on-main",
			event:     publish.EventSchedule,
			built:     c,
			published: d,
			wantErr:   "the published image was built from " + d + ", which is not on main",
		},
		{
			name:      "published-unknown",
			event:     publish.EventSchedule,
			built:     c,
			published: e,
			wantErr:   "the published image was built from " + e + ", which is not on main",
		},
		{
			name:      "schedule-same",
			event:     publish.EventSchedule,
			built:     c,
			published: c,
			want:      publish.Decision{Publish: false, Reason: "main has not moved since " + c},
		},
		{
			name:      "dispatch-same",
			event:     publish.EventDispatch,
			built:     c,
			published: c,
			want:      publish.Decision{Publish: true, Reason: "republishing " + c + " by hand"},
		},
		{
			name:      "main-moved",
			event:     publish.EventSchedule,
			built:     c,
			published: a,
			want:      publish.Decision{Publish: true, Reason: "main moved from " + a + " to " + c},
		},
		{
			name:      "dispatch-moved",
			event:     publish.EventDispatch,
			built:     c,
			published: b,
			want:      publish.Decision{Publish: true, Reason: "main moved from " + b + " to " + c},
		},
		{
			name:      "published-newer",
			event:     publish.EventSchedule,
			built:     b,
			published: c,
			want:      publish.Decision{Publish: false, Reason: c + ", published while this run built " + b + ", is newer"},
		},
		{
			name:      "dispatch-older",
			event:     publish.EventDispatch,
			built:     a,
			published: c,
			want:      publish.Decision{Publish: false, Reason: c + ", published while this run built " + a + ", is newer"},
		},
		{
			name:      "diverged",
			event:     publish.EventSchedule,
			built:     d,
			published: b,
			wantErr:   d + " and the published " + b + " have diverged",
		},

		// push, and a change in content with no new commit.
		{
			name:      "push-nothing-published",
			event:     publish.EventPush,
			built:     c,
			published: "",
			want:      publish.Decision{Publish: true, Reason: "nothing is published yet"},
		},
		{
			name:      "push-same",
			event:     publish.EventPush,
			built:     c,
			published: c,
			want:      publish.Decision{Publish: false, Reason: "already published"},
		},
		{
			name:          "push-content",
			event:         publish.EventPush,
			built:         c,
			published:     c,
			contentChange: "libaom",
			want:          publish.Decision{Publish: true, Reason: "content moved: libaom"},
		},
		{
			name:      "push-moved",
			event:     publish.EventPush,
			built:     c,
			published: b,
			want:      publish.Decision{Publish: true, Reason: "main moved from " + b + " to " + c},
		},
		{
			name:      "push-not-on-main",
			event:     publish.EventPush,
			built:     c,
			published: d,
			wantErr:   "the published image was built from " + d + ", which is not on main",
		},
		{
			name:          "schedule-content",
			event:         publish.EventSchedule,
			built:         c,
			published:     c,
			contentChange: "libaom",
			want:          publish.Decision{Publish: true, Reason: "content moved: libaom"},
		},
		{
			// A manual run republishes whether or not anything moved.
			name:          "dispatch-content",
			event:         publish.EventDispatch,
			built:         c,
			published:     c,
			contentChange: "libaom",
			want:          publish.Decision{Publish: true, Reason: "republishing " + c + " by hand"},
		},
		{
			// A content change never moves :latest backwards.
			name:          "content-but-published-newer",
			event:         publish.EventSchedule,
			built:         b,
			published:     c,
			contentChange: "libaom",
			want:          publish.Decision{Publish: false, Reason: c + ", published while this run built " + b + ", is newer"},
		},
		{
			name:          "content-but-diverged",
			event:         publish.EventPush,
			built:         d,
			published:     b,
			contentChange: "libaom",
			wantErr:       d + " and the published " + b + " have diverged",
		},

		// What the shell script took on trust.
		{
			name:      "built-not-a-sha",
			event:     publish.EventSchedule,
			built:     "main",
			published: c,
			wantErr:   `the built commit "main" is not a full commit SHA`,
		},
		{
			name:      "published-not-a-sha",
			event:     publish.EventSchedule,
			built:     c,
			published: "--output=x",
			wantErr:   `the published commit "--output=x" is not a full commit SHA`,
		},
		{
			name:      "git-fails",
			git:       fakeGit{err: errGit},
			event:     publish.EventSchedule,
			built:     c,
			published: b,
			wantErrIs: errGit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := tt.git
			if g.parent == nil && g.err == nil {
				g = newFakeGit()
			}
			got, err := publish.Decide(t.Context(), g, tt.event, tt.built, tt.published, tt.contentChange)
			if tt.wantErr != "" || tt.wantErrIs != nil {
				if err == nil {
					t.Fatalf("Decide() = %+v, nil; want an error", got)
				}
				if tt.wantErr != "" && err.Error() != tt.wantErr {
					t.Errorf("Decide() error = %q, want %q", err, tt.wantErr)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("Decide() error = %v, want it to wrap %v", err, tt.wantErrIs)
				}
				if got.Publish {
					t.Errorf("Decide() = %+v with an error, want no publish", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decide() error = %v, want %+v", err, tt.want)
			}
			if got != tt.want {
				t.Errorf("Decide() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecisionString(t *testing.T) {
	t.Parallel()

	for d, want := range map[publish.Decision]string{
		{Publish: true, Reason: "nothing is published yet"}: "publish: nothing is published yet",
		{Publish: false, Reason: "already published"}:       "skip: already published",
	} {
		if got := d.String(); got != want {
			t.Errorf("%+v.String() = %q, want %q", d, got, want)
		}
	}
}

// inDir runs every command with git's -C dir, so ExecGit's commands run
// against the repository in dir rather than the test's working directory,
// and with env on top of the test's environment.
type inDir struct {
	dir string
	env []string
}

func (r inDir) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	return execx.OS{Env: r.env}.Run(ctx, name, append([]string{"-C", r.dir}, args...)...)
}

// git runs a git command in dir that must succeed, and returns its stdout.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{
		"-c", "user.name=divbast test", "-c", "user.email=test@divbast.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
	}, args...)
	res, err := inDir{dir: dir}.Run(t.Context(), "git", argv...)
	if err != nil || res.Code != 0 {
		t.Fatalf("git %q: %v, exit %d: %s", args, err, res.Code, res.Stderr)
	}
	return strings.TrimSpace(string(res.Stdout))
}

func TestExecGit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	git(t, dir, "init", "--quiet", "--initial-branch=main")
	commits := make([]string, 0, 3)
	for _, msg := range []string{"A", "B", "C"} {
		git(t, dir, "commit", "--quiet", "--allow-empty", "--message", msg)
		commits = append(commits, git(t, dir, "rev-parse", "HEAD"))
	}
	ca, cb, cc := commits[0], commits[1], commits[2]
	// What a clone that fetched main has, and the ref Decide asks about.
	git(t, dir, "update-ref", "refs/remotes/origin/main", cb)
	tree := git(t, dir, "rev-parse", "HEAD^{tree}")

	g := publish.ExecGit(inDir{dir: dir})

	exists := []struct {
		name string
		sha  string
		want bool
	}{
		{name: "commit", sha: ca, want: true},
		{name: "missing", sha: e, want: false},
		// A tree is an object, but not a commit.
		{name: "tree", sha: tree, want: false},
	}
	for _, tt := range exists {
		got, err := g.CommitExists(t.Context(), tt.sha)
		if err != nil || got != tt.want {
			t.Errorf("CommitExists(%s %s) = %t, %v; want %t, nil", tt.name, tt.sha, got, err, tt.want)
		}
	}

	ancestry := []struct {
		ancestor, descendant string
		want                 bool
	}{
		{ancestor: ca, descendant: cc, want: true},
		{ancestor: cc, descendant: ca, want: false},
		{ancestor: cb, descendant: cb, want: true},
		{ancestor: ca, descendant: "origin/main", want: true},
		{ancestor: cc, descendant: "origin/main", want: false},
	}
	for _, tt := range ancestry {
		got, err := g.IsAncestor(t.Context(), tt.ancestor, tt.descendant)
		if err != nil || got != tt.want {
			t.Errorf("IsAncestor(%s, %s) = %t, %v; want %t, nil", tt.ancestor, tt.descendant, got, err, tt.want)
		}
	}

	// git exits 128, not 1, when it cannot answer: that is an error, not a no.
	if got, err := g.IsAncestor(t.Context(), e, cc); err == nil {
		t.Errorf("IsAncestor(missing, %s) = %t, nil; want an error", cc, got)
	}
	if got, err := g.IsAncestor(t.Context(), ca, "refs/remotes/upstream/main"); err == nil {
		t.Errorf("IsAncestor(%s, missing ref) = %t, nil; want an error", ca, got)
	}

	// Where there is no repository to look in, as in a job that never
	// checked one out, a missing commit is not the answer. The ceiling
	// keeps git from finding one above the directory.
	empty := t.TempDir()
	nowhere := publish.ExecGit(inDir{dir: empty, env: []string{"GIT_CEILING_DIRECTORIES=" + filepath.Dir(empty)}})
	if got, err := nowhere.CommitExists(t.Context(), ca); err == nil {
		t.Errorf("CommitExists with no repository = %t, nil; want an error", got)
	}
}
