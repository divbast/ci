// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package release_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/release"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tag    string
		want   release.Version
		wantOK bool
	}{
		{tag: "v1.2.3", want: release.Version{Major: 1, Minor: 2, Patch: 3}, wantOK: true},
		{tag: "v0.0.0", want: release.Version{}, wantOK: true},
		{tag: "v10.20.30", want: release.Version{Major: 10, Minor: 20, Patch: 30}, wantOK: true},
		{tag: "1.2.3"},
		{tag: "v1.2"},
		{tag: "v1.2.3.4"},
		{tag: "v01.2.3"},
		{tag: "v1.2.3-rc.1"},
		{tag: "v1.2.3+build"},
		{tag: "V1.2.3"},
		{tag: "latest"},
		{tag: "v99999999999999999999.0.0"},
		{tag: ""},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			t.Parallel()

			got, ok := release.ParseVersion(tt.tag)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("ParseVersion(%q) = %v, %t; want %v, %t", tt.tag, got, ok, tt.want, tt.wantOK)
			}
			if ok && got.String() != tt.tag {
				t.Errorf("ParseVersion(%q).String() = %q", tt.tag, got.String())
			}
		})
	}
}

func TestNext(t *testing.T) {
	t.Parallel()

	plain := []release.Commit{{Subject: "a"}, {Subject: "b"}}
	breaking := []release.Commit{{Subject: "a"}, {Subject: "b", Breaking: []string{"drops an input"}}}

	tests := []struct {
		name     string
		previous release.Version
		released bool
		commits  []release.Commit
		want     string
	}{
		{name: "first", commits: plain, want: "v1.0.0"},
		// The first release is v1.0.0 whatever it carries.
		{name: "first-breaking", commits: breaking, want: "v1.0.0"},
		{name: "minor", previous: release.Version{Major: 1, Minor: 4}, released: true, commits: plain, want: "v1.5.0"},
		{name: "minor-drops-patch", previous: release.Version{Major: 1, Minor: 4, Patch: 2}, released: true, commits: plain, want: "v1.5.0"},
		{name: "major", previous: release.Version{Major: 1, Minor: 4, Patch: 2}, released: true, commits: breaking, want: "v2.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := release.Next(tt.previous, tt.released, tt.commits).String(); got != tt.want {
				t.Errorf("Next(%v, %t, …) = %s, want %s", tt.previous, tt.released, got, tt.want)
			}
		})
	}
}

func TestNotes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		commits []release.Commit
		want    string
	}{
		{
			name:    "plain",
			commits: []release.Commit{{Subject: "lint: share the recipes"}, {Subject: "go: start the module"}},
			want:    "## Changes\n\n- lint: share the recipes\n- go: start the module\n",
		},
		// Merges' subjects are left out, their breaking changes are not,
		// and the same text is listed once.
		{
			name: "merges-and-duplicates",
			commits: []release.Commit{
				{Subject: "lint: drop the php input", Breaking: []string{"lint.yml has no php input"}},
				{Subject: "Merge pull request #2 from divbast/lint", Merge: true, Breaking: []string{"lint.yml has no php input", "said by the merge"}},
				{Subject: "docs: say so"},
			},
			want: "## Breaking changes\n\n- lint.yml has no php input\n- said by the merge\n\n## Changes\n\n- lint: drop the php input\n- docs: say so\n",
		},
		{
			name: "breaking",
			commits: []release.Commit{
				{Subject: "scan: rename -layout", Breaking: []string{"divbast-scan's -layout is now -oci-layout"}},
				{Subject: "lint: drop the php input", Breaking: []string{"lint.yml has no php input", "PHPStan runs only from app-check.yml"}},
				{Subject: "docs: say so"},
			},
			want: "## Breaking changes\n\n" +
				"- divbast-scan's -layout is now -oci-layout\n" +
				"- lint.yml has no php input\n" +
				"- PHPStan runs only from app-check.yml\n" +
				"\n## Changes\n\n" +
				"- scan: rename -layout\n- lint: drop the php input\n- docs: say so\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := release.Notes(tt.commits); got != tt.want {
				t.Errorf("Notes() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// inDir runs every command with git's -C dir, so the git commands run
// against the repository in dir rather than the test's working directory.
type inDir struct{ dir string }

func (r inDir) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	return execx.OS{}.Run(ctx, name, append([]string{"-C", r.dir}, args...)...)
}

// repo is a clone with an origin, both on disk.
type repo struct {
	t           *testing.T
	dir, origin string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	base := t.TempDir()
	r := &repo{t: t, dir: filepath.Join(base, "work"), origin: filepath.Join(base, "origin.git")}
	gitIn(t, base, "init", "--quiet", "--bare", "--initial-branch=main", r.origin)
	gitIn(t, base, "init", "--quiet", "--initial-branch=main", r.dir)
	r.git("remote", "add", "origin", r.origin)
	return r
}

// gitIn runs a git command in dir that must succeed, and returns its
// stdout.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{
		"-c", "user.name=divbast test", "-c", "user.email=test@divbast.invalid",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null",
	}, args...)
	res, err := inDir{dir}.Run(t.Context(), "git", argv...)
	if err != nil || res.Code != 0 {
		t.Fatalf("git %q: %v, exit %d: %s", args, err, res.Code, res.Stderr)
	}
	return strings.TrimSpace(string(res.Stdout))
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	return gitIn(r.t, r.dir, args...)
}

// commit makes an empty commit with message msg and returns its SHA.
func (r *repo) commit(msg string) string {
	r.t.Helper()
	r.git("commit", "--quiet", "--allow-empty", "--message", msg)
	return r.git("rev-parse", "HEAD")
}

// push puts main, and any tags named, on origin.
func (r *repo) push(refs ...string) {
	r.t.Helper()
	r.git(append([]string{"push", "--quiet", "origin", "main"}, refs...)...)
}

const (
	trailers = "\n\nDeveloped-by: Aryan Ameri <github@aryan.ameri.coffee>\nAssisted-by: <Claude:claude-5.5-opus>"
	missing  = "0000000000000000000000000000000000000000"
)

// subjects are the subjects the notes list: every commit's but merges'.
func subjects(commits []release.Commit) []string {
	s := make([]string, 0, len(commits))
	for _, c := range commits {
		if !c.Merge {
			s = append(s, c.Subject)
		}
	}
	return s
}

// squashSubject is the subject of the commit squash makes.
const squashSubject = "ci: rename the input (#9)"

// squash returns a setup that releases v1.0.0, then makes a squash merge
// whose body lists two squashed commits' messages, with line in the
// first's trailers, a paragraph git does not parse as trailers, and pushes
// main and the tag.
func squash(line string) func(r *repo) string {
	return func(r *repo) string {
		r.commit("a: one" + trailers)
		r.git("tag", "v1.0.0")
		sha := r.commit(squashSubject + "\n\n" +
			"* lint: rename the input\n\nWhy.\n\n" + line + "\nDeveloped-by: X <x@x.invalid>\n\n" +
			"* docs: say so" + trailers)
		r.push("v1.0.0")
		return sha
	}
}

func TestPrepare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup builds the repository and returns the commit to release.
		setup        func(r *repo) string
		wantErr      error
		wantReleased string
		wantPrevious string
		wantVersion  string
		wantSubjects []string
		wantBreaking []string
		// wantTip is whether origin's main is the commit released.
		wantTip bool
		// wantSuperseded is whether a later commit on origin's main holds it.
		wantSuperseded bool
	}{
		{
			name: "first-release",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.commit("b: two" + trailers)
				sha := r.commit("c: three" + trailers)
				r.push()
				return sha
			},
			wantVersion:  "v1.0.0",
			wantSubjects: []string{"a: one", "b: two", "c: three"},
			wantTip:      true,
		},
		{
			name: "minor",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.commit("b: two" + trailers)
				sha := r.commit("c: three" + trailers)
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{"b: two", "c: three"},
			wantTip:      true,
		},
		{
			name: "major",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.3.2")
				r.commit("b: two\n\nWhy.\n\nBreaking-change: lint.yml drops its php input\n" + strings.TrimPrefix(trailers, "\n\n"))
				sha := r.commit("c: three" + trailers)
				r.push("v1.3.2")
				return sha
			},
			wantPrevious: "v1.3.2",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"b: two", "c: three"},
			wantBreaking: []string{"lint.yml drops its php input"},
			wantTip:      true,
		},
		// The words mid-line, which no line starts with, do not count.
		{
			name: "mention-in-the-body",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				sha := r.commit("b: two\n\nThis only says Breaking-change: mid-line, which no line starts with.\n\nMore prose." + trailers)
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{"b: two"},
			wantTip:      true,
		},
		{
			name: "folded-lower-case-and-two",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.commit("b: two\n\nWhy.\n\nbreaking-change: divbast-scan's -layout\n  is now -oci-layout\nDeveloped-by: X <x@x.invalid>")
				sha := r.commit("c: three\n\nWhy.\n\nBreaking-change: one\nBreaking-change: two\nDeveloped-by: X <x@x.invalid>")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"b: two", "c: three"},
			wantBreaking: []string{"divbast-scan's -layout is now -oci-layout", "one", "two"},
			wantTip:      true,
		},
		// The highest version tag the commit descends from, by number,
		// and nothing that is not vX.Y.Z or not on its history.
		{
			name: "highest-reachable-version",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.9.0")
				r.commit("b: two" + trailers)
				r.git("tag", "v1.10.0")
				for _, junk := range []string{"latest", "v2.0", "v2.0.0-rc.1", "v3"} {
					r.git("tag", junk)
				}
				r.git("checkout", "--quiet", "-b", "side")
				r.commit("s: side" + trailers)
				r.git("tag", "v3.0.0")
				r.git("checkout", "--quiet", "main")
				sha := r.commit("c: three" + trailers)
				r.push()
				return sha
			},
			wantPrevious: "v1.10.0",
			wantVersion:  "v1.11.0",
			wantSubjects: []string{"c: three"},
			wantTip:      true,
		},
		{
			name: "released-here",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				sha := r.commit("b: two" + trailers)
				r.git("tag", "v1.0.0")
				r.push("v1.0.0")
				return sha
			},
			wantReleased: "v1.0.0",
			wantTip:      true,
		},
		// Released on origin since this clone fetched.
		{
			name: "released-on-origin",
			setup: func(r *repo) string {
				sha := r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.push("v1.0.0")
				r.git("tag", "--delete", "v1.0.0")
				return sha
			},
			wantReleased: "v1.0.0",
			wantTip:      true,
		},
		// origin lists an annotated tag twice: the tag object, and the
		// commit it points at as <tag>^{}, which is the one that counts.
		{
			name: "annotated-released-on-origin",
			setup: func(r *repo) string {
				sha := r.commit("a: one" + trailers)
				r.git("tag", "--annotate", "--message", "v1.0.0", "v1.0.0")
				r.push("v1.0.0")
				r.git("tag", "--delete", "v1.0.0")
				return sha
			},
			wantReleased: "v1.0.0",
			wantTip:      true,
		},
		{
			name: "annotated-tag",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "--annotate", "--message", "v1.0.0", "v1.0.0")
				sha := r.commit("b: two" + trailers)
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{"b: two"},
			wantTip:      true,
		},
		// A later merge landed first: the run for main's tip releases it.
		{
			name: "superseded",
			setup: func(r *repo) string {
				sha := r.commit("a: one" + trailers)
				r.commit("b: two" + trailers)
				r.push()
				return sha
			},
			wantVersion:    "v1.0.0",
			wantSubjects:   []string{"a: one"},
			wantSuperseded: true,
		},
		// Landed after this clone fetched, so the clone fetches main to
		// see that it holds the commit.
		{
			name: "superseded-since-the-clone-fetched",
			setup: func(r *repo) string {
				sha := r.commit("a: one" + trailers)
				r.push()
				other := filepath.Join(filepath.Dir(r.dir), "other")
				gitIn(r.t, filepath.Dir(r.dir), "clone", "--quiet", r.origin, other)
				gitIn(r.t, other, "commit", "--quiet", "--allow-empty", "--message", "b: two")
				gitIn(r.t, other, "push", "--quiet", "origin", "main")
				return sha
			},
			wantVersion:    "v1.0.0",
			wantSubjects:   []string{"a: one"},
			wantSuperseded: true,
		},
		// Prepare reports a commit main does not hold; Create refuses it.
		{
			name: "not-on-main",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.commit("b: two" + trailers)
				r.push("v1.0.0")
				r.git("checkout", "--quiet", "-b", "side", "v1.0.0")
				return r.commit("s: side" + trailers)
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{"s: side"},
		},
		// Ruling R30: the notes list the changes, not the merges that
		// brought them.
		{
			name: "merge-subject-left-out",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.git("checkout", "--quiet", "-b", "feature")
				r.commit("b: two" + trailers)
				r.git("checkout", "--quiet", "main")
				r.commit("c: three" + trailers)
				r.git("merge", "--quiet", "--no-ff", "--message", "Merge pull request #2 from divbast/feature", "feature")
				sha := r.git("rev-parse", "HEAD")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{"b: two", "c: three"},
			wantTip:      true,
		},
		// Ruling R32: a merge's own Breaking-change trailer still counts.
		{
			name: "merge-trailer-counts",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.git("checkout", "--quiet", "-b", "feature")
				r.commit("b: two" + trailers)
				r.git("checkout", "--quiet", "main")
				r.commit("c: three" + trailers)
				r.git("merge", "--quiet", "--no-ff", "--message",
					"Merge pull request #2 from divbast/feature\n\nBreaking-change: said only by the merge", "feature")
				sha := r.git("rev-parse", "HEAD")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"b: two", "c: three"},
			wantBreaking: []string{"said only by the merge"},
			wantTip:      true,
		},
		// A squash merge lists each squashed commit's message in its body,
		// so their trailers sit in paragraphs git does not parse as
		// trailers. A line that starts with one counts, bulleted or not,
		// and the same text twice is listed once.
		{
			name: "squash-buried-trailer",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				sha := r.commit("ci: rework the lint job (#7)\n\n" +
					"* lint: drop the php input\n\nWhy.\n\nBreaking-change: lint.yml drops its php input\nDeveloped-by: X <x@x.invalid>\n\n" +
					"* docs: say so\n\nDeveloped-by: X <x@x.invalid>\n\n" +
					"Co-authored-by: Y <y@y.invalid>")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"ci: rework the lint job (#7)"},
			wantBreaking: []string{"lint.yml drops its php input"},
			wantTip:      true,
		},
		{
			name: "squash-repeats-its-trailer",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				sha := r.commit("ci: rework the lint job (#7)\n\n" +
					"* lint: drop the php input\n\nWhy.\n\nBreaking-change: lint.yml drops its php input\nDeveloped-by: X <x@x.invalid>\n\n" +
					"* docs: say so\n\nDeveloped-by: X <x@x.invalid>\n\n" +
					"Breaking-change: lint.yml drops its php input\nCo-authored-by: Y <y@y.invalid>")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"ci: rework the lint job (#7)"},
			wantBreaking: []string{"lint.yml drops its php input"},
			wantTip:      true,
		},
		{
			name: "squash-bullets",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				sha := r.commit("ci: rework the scan (#8)\n\n" +
					"* Breaking-change: divbast-scan's -layout is now -oci-layout\n" +
					"  - Breaking-change: divbast-scan needs -vex\n\n" +
					"* docs: say so" + trailers)
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"ci: rework the scan (#8)"},
			wantBreaking: []string{"divbast-scan's -layout is now -oci-layout", "divbast-scan needs -vex"},
			wantTip:      true,
		},
		// git's trailer parser takes blanks between a key and its colon,
		// and a bullet may be followed by any blanks, so a buried line
		// counts with either, in any case. The key mid-sentence or inside a
		// word does not.
		{
			name:         "squash-blank-before-the-colon",
			setup:        squash("* Breaking-change : the input was renamed"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{squashSubject},
			wantBreaking: []string{"the input was renamed"},
			wantTip:      true,
		},
		{
			name:         "squash-blanks-before-the-colon",
			setup:        squash("-\tBreaking-change \t: the input was renamed"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{squashSubject},
			wantBreaking: []string{"the input was renamed"},
			wantTip:      true,
		},
		{
			name:         "squash-tab-after-the-bullet",
			setup:        squash("*\tBreaking-change: the input was renamed"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{squashSubject},
			wantBreaking: []string{"the input was renamed"},
			wantTip:      true,
		},
		{
			name:         "squash-two-spaces-after-the-bullet",
			setup:        squash("-  Breaking-change: the input was renamed"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{squashSubject},
			wantBreaking: []string{"the input was renamed"},
			wantTip:      true,
		},
		{
			name:         "squash-lower-case",
			setup:        squash("* breaking-change: the input was renamed"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{squashSubject},
			wantBreaking: []string{"the input was renamed"},
			wantTip:      true,
		},
		{
			name:         "squash-key-mid-sentence",
			setup:        squash("* see the Breaking-change: rules in README"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{squashSubject},
			wantTip:      true,
		},
		{
			name:         "squash-key-inside-a-word",
			setup:        squash("NotBreaking-change: x"),
			wantPrevious: "v1.0.0",
			wantVersion:  "v1.1.0",
			wantSubjects: []string{squashSubject},
			wantTip:      true,
		},
		// A trailer that says nothing still breaks, and the notes name its
		// commit.
		{
			name: "bare-trailer",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				sha := r.commit("b: two\n\nWhy.\n\nBreaking-change:\nDeveloped-by: X <x@x.invalid>")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"b: two"},
			wantBreaking: []string{"b: two"},
			wantTip:      true,
		},
		{
			name: "breaking-under-a-merge",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.git("checkout", "--quiet", "-b", "feature")
				r.commit("b: two\n\nWhy.\n\nBreaking-change: lint.yml drops its php input\nDeveloped-by: X <x@x.invalid>")
				r.git("checkout", "--quiet", "main")
				r.git("merge", "--quiet", "--no-ff", "--message", "Merge pull request #2 from divbast/feature", "feature")
				sha := r.git("rev-parse", "HEAD")
				r.push("v1.0.0")
				return sha
			},
			wantPrevious: "v1.0.0",
			wantVersion:  "v2.0.0",
			wantSubjects: []string{"b: two"},
			wantBreaking: []string{"lint.yml drops its php input"},
			wantTip:      true,
		},
		{
			name: "next-tag-taken-here",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.git("checkout", "--quiet", "-b", "side")
				r.commit("s: side" + trailers)
				r.git("tag", "v1.1.0")
				r.git("checkout", "--quiet", "main")
				sha := r.commit("b: two" + trailers)
				r.push("v1.0.0")
				return sha
			},
			wantErr: release.ErrTagExists,
		},
		// A clone without origin's newest tags would count from an older
		// one, and could take a version origin already has, or a lower one.
		{
			name: "stale-clone",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.commit("b: two" + trailers)
				r.git("tag", "v1.1.0")
				r.commit("c: three" + trailers)
				r.git("tag", "v1.2.0")
				sha := r.commit("d: four" + trailers)
				r.push("v1.0.0", "v1.1.0", "v1.2.0")
				r.git("tag", "--delete", "v1.1.0", "v1.2.0")
				return sha
			},
			wantErr: release.ErrStaleTags,
		},
		{
			name: "next-tag-taken-on-origin",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.git("checkout", "--quiet", "-b", "side")
				r.commit("s: side" + trailers)
				r.git("push", "--quiet", "origin", "side:refs/tags/v1.1.0")
				r.git("checkout", "--quiet", "main")
				sha := r.commit("b: two" + trailers)
				r.push("v1.0.0")
				return sha
			},
			wantErr: release.ErrStaleTags,
		},
		// Once fetched, the same tag is taken, not stale.
		{
			name: "next-tag-taken-on-origin-fetched",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.git("tag", "v1.0.0")
				r.git("checkout", "--quiet", "-b", "side")
				r.commit("s: side" + trailers)
				r.git("push", "--quiet", "origin", "side:refs/tags/v1.1.0")
				r.git("checkout", "--quiet", "main")
				sha := r.commit("b: two" + trailers)
				r.push("v1.0.0")
				r.git("fetch", "--quiet", "--tags", "origin")
				return sha
			},
			wantErr: release.ErrTagExists,
		},
		{
			name: "not-a-commit",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.push()
				return missing
			},
			wantErr: release.ErrNoCommit,
		},
		{
			name: "a-tree-is-not-a-commit",
			setup: func(r *repo) string {
				r.commit("a: one" + trailers)
				r.push()
				return r.git("rev-parse", "HEAD^{tree}")
			},
			wantErr: release.ErrNoCommit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := newRepo(t)
			sha := tt.setup(r)
			plan, err := release.Prepare(t.Context(), inDir{r.dir}, sha)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Prepare() error = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if plan.SHA != sha {
				t.Errorf("Prepare().SHA = %s, want %s", plan.SHA, sha)
			}
			if plan.Released != tt.wantReleased {
				t.Errorf("Prepare().Released = %q, want %q", plan.Released, tt.wantReleased)
			}
			if got := plan.Tip == sha; got != tt.wantTip {
				t.Errorf("Prepare().Tip = %s; is the commit: %t, want %t", plan.Tip, got, tt.wantTip)
			}
			if plan.Superseded != tt.wantSuperseded {
				t.Errorf("Prepare().Superseded = %t, want %t", plan.Superseded, tt.wantSuperseded)
			}
			if tt.wantReleased != "" {
				return
			}
			if plan.Previous != tt.wantPrevious {
				t.Errorf("Prepare().Previous = %q, want %q", plan.Previous, tt.wantPrevious)
			}
			if got := plan.Version.String(); got != tt.wantVersion {
				t.Errorf("Prepare().Version = %s, want %s", got, tt.wantVersion)
			}
			if got := subjects(plan.Commits); !slices.Equal(got, tt.wantSubjects) {
				t.Errorf("Prepare() subjects = %q, want %q", got, tt.wantSubjects)
			}
			var breaking []string
			for _, c := range plan.Commits {
				breaking = append(breaking, c.Breaking...)
			}
			if !slices.Equal(breaking, tt.wantBreaking) {
				t.Errorf("Prepare() breaking = %q, want %q", breaking, tt.wantBreaking)
			}
		})
	}
}

// TestPrepareGitFails sees each git command's failure come back as an
// error, never as an answer.
func TestPrepareGitFails(t *testing.T) {
	t.Parallel()

	const sha = "51b68da129260de083e7c2ca36c4b1440378c527"
	var (
		catFile = execx.Call{Argv: []string{"git", "cat-file", "-e", sha + "^{commit}"}}
		remote  = []string{"git", "ls-remote", "origin", "refs/heads/main", "refs/tags/v*"}
		here    = []string{"git", "tag", "--points-at", sha, "--list", "v*"}
		local   = []string{"git", "tag", "--list", "v*"}
		merged  = []string{"git", "tag", "--merged", sha, "--list", "v*"}
		fatal   = execx.Result{Code: 128, Stderr: []byte("fatal: something broke\n")}
	)

	tests := []struct {
		name  string
		calls []execx.Call
		want  string
	}{
		{
			name:  "no-repository",
			calls: []execx.Call{{Argv: catFile.Argv, Result: execx.Result{Code: 128, Stderr: []byte("fatal: not a git repository\n")}}},
			want:  "not a git repository",
		},
		{
			name:  "origin-unreachable",
			calls: []execx.Call{catFile, {Argv: remote, Result: execx.Result{Code: 128, Stderr: []byte("fatal: unable to access 'https://github.com/divbast/ci/'\n")}}},
			want:  "unable to access",
		},
		{
			name:  "tags-unreadable",
			calls: []execx.Call{catFile, {Argv: remote}, {Argv: here, Result: fatal}},
			want:  "something broke",
		},
		{
			name:  "local-tags-unreadable",
			calls: []execx.Call{catFile, {Argv: remote}, {Argv: here}, {Argv: local, Result: fatal}},
			want:  "something broke",
		},
		{
			name:  "history-unreadable",
			calls: []execx.Call{catFile, {Argv: remote}, {Argv: here}, {Argv: local}, {Argv: merged, Result: fatal}},
			want:  "something broke",
		},
		{
			name:  "git-missing",
			calls: []execx.Call{{Argv: catFile.Argv, Err: errors.New("exec: \"git\": executable file not found in $PATH")}},
			want:  "executable file not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := release.Prepare(t.Context(), execx.NewFake(t, tt.calls...), sha)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Prepare() error = %v, want one containing %q", err, tt.want)
			}
			if errors.Is(err, release.ErrNoCommit) {
				t.Errorf("Prepare() error = %v; a git that could not answer is not a missing commit", err)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	t.Parallel()

	const sha = "51b68da129260de083e7c2ca36c4b1440378c527"
	plan := release.Plan{
		SHA:     sha,
		Tip:     sha,
		Version: release.Version{Major: 1, Minor: 1},
		Commits: []release.Commit{{Subject: "a: one"}},
	}
	argv := []string{"gh", "release", "create", "v1.1.0", "--target", sha, "--title", "v1.1.0", "--notes-file", "-"}
	notes := []byte(release.Notes(plan.Commits))

	tests := []struct {
		name    string
		plan    func(p release.Plan) release.Plan
		calls   []execx.Call
		wantErr error
		// wantMsg is what the error message must contain.
		wantMsg string
		wantOut string
	}{
		{
			name: "creates",
			plan: func(p release.Plan) release.Plan { return p },
			calls: []execx.Call{{
				Argv:   argv,
				Stdin:  notes,
				Result: execx.Result{Stdout: []byte("https://github.com/divbast/ci/releases/tag/v1.1.0\n")},
			}},
			wantOut: "https://github.com/divbast/ci/releases/tag/v1.1.0\n",
		},
		{
			name:    "not-the-tip",
			plan:    func(p release.Plan) release.Plan { p.Tip = missing; return p },
			wantErr: release.ErrNotTip,
			wantMsg: missing,
		},
		{
			name:    "already-released",
			plan:    func(p release.Plan) release.Plan { p.Released = "v1.0.0"; return p },
			wantErr: release.ErrReleased,
			wantMsg: "v1.0.0",
		},
		{
			name: "gh-fails",
			plan: func(p release.Plan) release.Plan { return p },
			calls: []execx.Call{{
				Argv:   argv,
				Stdin:  notes,
				Result: execx.Result{Code: 1, Stderr: []byte("HTTP 403: Resource not accessible by integration\n")},
			}},
			wantMsg: "Resource not accessible",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := tt.plan(plan)
			out, err := release.Create(t.Context(), execx.NewFake(t, tt.calls...), &p)
			switch {
			case tt.wantErr == nil && tt.wantMsg == "":
				if err != nil {
					t.Fatalf("Create() error = %v, want nil", err)
				}
			case err == nil:
				t.Fatal("Create() error = nil, want an error")
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Errorf("Create() error = %v, want %v", err, tt.wantErr)
			case !strings.Contains(err.Error(), tt.wantMsg):
				t.Errorf("Create() error = %q, want it to contain %q", err, tt.wantMsg)
			}
			if string(out) != tt.wantOut {
				t.Errorf("Create() output = %q, want %q", out, tt.wantOut)
			}
		})
	}
}
