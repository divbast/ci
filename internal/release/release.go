// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package release works out and publishes the release of a commit on a
// repository's main branch, for a repository that releases every green
// merge.
//
// The version is the latest vX.Y.Z tag the commit descends from with its
// minor number raised, or its major number raised when any commit since
// that tag, merges included, marks a breaking change. A repository with
// no such tag yet releases v1.0.0. A commit marks one with a
// Breaking-change trailer, even an empty one, or with any line of its
// message that starts, after optional blanks and an optional "*" or "-"
// bullet followed by blanks, with Breaking-change, in any case, then
// optional blanks and a colon. That second rule finds the trailers a
// squash merge buries in its body, where it lists each squashed commit's
// message, and errs towards a major release: a needless major waits for
// an approval, where a missed one would merge a break into every caller.
// A bullet counts only with a blank after it, as GitHub writes a squash
// body's.
//
// The notes list the text of each breaking change, once, a folded one
// with all its lines, then the subject of every commit since the last
// release but merges, which bring changes and say nothing of their own.
// Only origin's release tags count, never one the clone alone has.
package release

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// Trailer is the commit trailer that makes a release major. Its value
// says what broke.
const Trailer = "Breaking-change"

// Version is a release's vMAJOR.MINOR.PATCH.
type Version struct {
	Major, Minor, Patch int
}

// First is the version of a repository's first release.
var First = Version{Major: 1}

// tag is the only form a release tag takes: no leading zeros, nothing
// before the v or after the patch number.
var tag = regexp.MustCompile(`^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

// ParseVersion reads a release tag, reporting false for anything that is
// not exactly vX.Y.Z.
func ParseVersion(s string) (Version, bool) {
	m := tag.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	var n [3]int
	for i, part := range m[1:] {
		v, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, false
		}
		n[i] = v
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2]}, true
}

// String returns the version as its tag.
func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare returns -1, 0 or +1 as v is older than, the same as, or newer
// than w.
func (v Version) Compare(w Version) int {
	return slices.Compare([]int{v.Major, v.Minor, v.Patch}, []int{w.Major, w.Minor, w.Patch})
}

// Commit is one commit since the last release.
type Commit struct {
	SHA     string
	Subject string
	// Merge is whether the commit is a merge, whose subject the notes
	// leave out.
	Merge bool
	// Breaking holds what each breaking change the commit marks says, once
	// each: a trailer's value with folded lines joined, or the rest of a
	// line that marks one, after its colon. A mark that says nothing is the
	// commit's subject.
	Breaking []string
}

// Next returns the version that follows previous, given the commits since
// it: previous with its minor number raised, or with its major number
// raised when any commit, a merge or not, marks a breaking change. With
// no previous release, released false, it is [First].
func Next(previous Version, released bool, commits []Commit) Version {
	if !released {
		return First
	}
	for _, c := range commits {
		if len(c.Breaking) > 0 {
			return Version{Major: previous.Major + 1}
		}
	}
	return Version{Major: previous.Major, Minor: previous.Minor + 1}
}

// Notes returns a release's notes, in Markdown: what each breaking change
// says, when there is one, each text once, then the subject of each commit
// but merges, in the order given.
func Notes(commits []Commit) string {
	var b strings.Builder
	var breaking []string
	for _, c := range commits {
		for _, text := range c.Breaking {
			if !slices.Contains(breaking, text) {
				breaking = append(breaking, text)
			}
		}
	}
	if len(breaking) > 0 {
		b.WriteString("## Breaking changes\n\n")
		for _, text := range breaking {
			b.WriteString("- " + text + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## Changes\n\n")
	for _, c := range commits {
		if !c.Merge {
			b.WriteString("- " + c.Subject + "\n")
		}
	}
	return b.String()
}

// Plan is what releasing a commit would do.
type Plan struct {
	// SHA is the commit to release.
	SHA string
	// Tip is the commit origin's main points at, empty when origin has no
	// main.
	Tip string
	// Superseded is whether SHA is on origin's main but no longer its tip:
	// a later merge landed first, and the run for Tip releases SHA with it.
	Superseded bool
	// Released is the release tag already at SHA on origin, when there is
	// one. The fields below are then empty.
	Released string
	// ReleasedIn is the earliest release tag on origin that holds SHA,
	// when SHA is Superseded and a later merge's release already holds
	// it. The fields below are then empty.
	ReleasedIn string
	// Previous is the latest release tag SHA descends from, empty when
	// there is none.
	Previous string
	// Version is the release to make.
	Version Version
	// Commits are those since Previous, or all of SHA's history when there
	// is none, merges included, oldest first.
	Commits []Commit
}

var (
	// ErrNoCommit means the SHA names no commit in the repository.
	ErrNoCommit = errors.New("not a commit in this repository")
	// ErrTagExists means the next version's tag is already taken by a
	// commit the one being released does not descend from.
	ErrTagExists = errors.New("the next version's tag already exists")
	// ErrNotTip means the commit is not origin's main, so releasing it
	// could give an older commit a newer version than main has.
	ErrNotTip = errors.New("not the tip of origin's main")
	// ErrReleased means a release tag already points at the commit.
	ErrReleased = errors.New("already released")
	// ErrStaleTags means origin has release tags the clone has not
	// fetched, so the version cannot be counted from the clone's.
	ErrStaleTags = errors.New("origin has release tags this clone has not fetched")
	// ErrTagMismatch means gh made the release, but origin's tag of its
	// version does not point at the commit: a tag of that name was
	// already there, and the release took it.
	ErrTagMismatch = errors.New("the release's tag is not at the commit released")
)

// Prepare works out the release of sha in the clone git runs in, which
// must have fetched origin's tags. It reads origin's main and release tags
// from origin itself, and when main has moved past sha, whether main holds
// it, fetching main if the clone lacks it, and whether a later release
// holds it already. Only origin's release tags count: one the clone alone
// has releases nothing, takes no version and holds nothing. It refuses
// nothing but a version tag already taken elsewhere, or a clone missing
// origin's tags: [Create], and its caller, decide whether the plan may be
// carried out.
//
// The error wraps [ErrNoCommit] when sha is not a commit there,
// [ErrStaleTags] when origin has a release tag the clone has not fetched,
// and [ErrTagExists] when the next version's tag is taken. Any other error
// is git failing to answer.
func Prepare(ctx context.Context, git execx.Runner, sha string) (Plan, error) {
	plan := Plan{SHA: sha}
	g := runner{git}

	if _, err := g.out(ctx, "cat-file", "-e", sha+"^{commit}"); err != nil {
		if errors.Is(err, errNoObject) {
			return Plan{}, fmt.Errorf("%s: %w", sha, ErrNoCommit)
		}
		return Plan{}, err
	}

	var (
		remote map[string]string
		err    error
	)
	if plan.Tip, remote, err = g.origin(ctx); err != nil {
		return Plan{}, err
	}

	// Released already, by origin's tags, the only ones that count.
	var here []Version
	for name, target := range remote {
		if v, ok := ParseVersion(name); ok && target == sha {
			here = append(here, v)
		}
	}
	if len(here) > 0 {
		plan.Released = slices.MaxFunc(here, Version.Compare).String()
		return plan, nil
	}
	released := func(v Version) bool {
		_, ok := remote[v.String()]
		return ok
	}

	// Counted from the clone's tags, so they must be all of origin's.
	have, err := g.versions(ctx)
	if err != nil {
		return Plan{}, err
	}
	var missing []string
	for name := range remote {
		if v, ok := ParseVersion(name); ok && !slices.Contains(have, v) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return Plan{}, fmt.Errorf("%w: %s; fetch them with git fetch --tags origin", ErrStaleTags, strings.Join(missing, ", "))
	}

	if plan.Tip != "" && plan.Tip != sha {
		if plan.Superseded, err = g.holds(ctx, plan.Tip, sha); err != nil {
			return Plan{}, err
		}
	}
	// Released already, with a later merge whose run came first.
	if plan.Superseded {
		var later []Version
		if later, err = g.versions(ctx, "--contains", sha, "--merged", plan.Tip); err != nil {
			return Plan{}, err
		}
		if later = slices.DeleteFunc(later, func(v Version) bool { return !released(v) }); len(later) > 0 {
			plan.ReleasedIn = slices.MinFunc(later, Version.Compare).String()
			return plan, nil
		}
	}

	reachable, err := g.versions(ctx, "--merged", sha)
	if err != nil {
		return Plan{}, err
	}
	reachable = slices.DeleteFunc(reachable, func(v Version) bool { return !released(v) })
	since := sha
	var previous Version
	if len(reachable) > 0 {
		previous = slices.MaxFunc(reachable, Version.Compare)
		plan.Previous = previous.String()
		since = plan.Previous + ".." + sha
	}
	if plan.Commits, err = g.log(ctx, since); err != nil {
		return Plan{}, err
	}
	plan.Version = Next(previous, plan.Previous != "", plan.Commits)

	// Every tag sha descends from is older than the next version, so a
	// tag that already has its name is on some other history.
	if released(plan.Version) {
		return Plan{}, fmt.Errorf("%w: %s, on a commit %s does not descend from", ErrTagExists, plan.Version, sha)
	}
	return plan, nil
}

// Create carries the plan out through gh: it makes the GitHub release
// plan.Version, tagging plan.SHA, titled with the version and with [Notes]
// as its notes, and returns what gh printed. gh must be able to write the
// repository's contents. Create never moves or deletes a tag.
//
// It refuses, wrapping [ErrReleased], when a release tag already points at
// the commit or a later release holds it, and, wrapping [ErrNotTip],
// unless the commit is origin's main. Once gh has made the release, it
// reads the tag back from origin, through git, and fails, wrapping
// [ErrTagMismatch], unless the tag points at the commit: gh gives a
// release a tag of its name that is already there, wherever that points.
// A tag origin does not show yet is read again, up to tagReads times in
// all, tagWait apart.
func Create(ctx context.Context, git execx.Runner, gh execx.StdinRunner, plan *Plan) ([]byte, error) {
	switch {
	case plan.Released != "":
		return nil, fmt.Errorf("%s is %w as %s", plan.SHA, ErrReleased, plan.Released)
	case plan.ReleasedIn != "":
		return nil, fmt.Errorf("%s is %w in %s", plan.SHA, ErrReleased, plan.ReleasedIn)
	case plan.Tip != plan.SHA:
		return nil, fmt.Errorf("%s is %w, which is %q", plan.SHA, ErrNotTip, plan.Tip)
	}
	v := plan.Version.String()
	res, err := gh.RunStdin(ctx, strings.NewReader(Notes(plan.Commits)),
		"gh", "release", "create", v, "--target", plan.SHA, "--title", v, "--notes-file", "-")
	if err != nil {
		return nil, fmt.Errorf("gh release create: %w", err)
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("gh release create %s: exit status %d: %s", v, res.Code, bytes.TrimSpace(res.Stderr))
	}
	if err = (runner{git}).tagged(ctx, v, plan.SHA); err != nil {
		return nil, fmt.Errorf("gh made release %s, but %w", v, err)
	}
	return res.Stdout, nil
}

// errNoObject is git saying it has no such object, or none of that kind.
var errNoObject = errors.New("no such object")

// runner runs git commands and reads their output.
type runner struct {
	git execx.Runner
}

// out runs git with args and returns its stdout. A non-zero exit is an
// error naming the command, which wraps errNoObject when git says the
// object does not exist.
func (r runner) out(ctx context.Context, args ...string) ([]byte, error) {
	res, err := r.git.Run(ctx, "git", args...)
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	if res.Code != 0 {
		err = fmt.Errorf("git %s: exit status %d: %s", strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
		// git exits 128 both for an object it does not have, or one of
		// another kind, and for having no repository to look in. Only the
		// first is an answer.
		if bytes.Contains(res.Stderr, []byte("Not a valid object name")) {
			err = fmt.Errorf("%w: %w", errNoObject, err)
		}
		return nil, err
	}
	return res.Stdout, nil
}

// origin reads origin's main and its version tags, each with the commit
// it points at.
func (r runner) origin(ctx context.Context) (tip string, tags map[string]string, err error) {
	out, err := r.out(ctx, "ls-remote", "origin", "refs/heads/main", "refs/tags/v*")
	if err != nil {
		return "", nil, err
	}
	tags = map[string]string{}
	for line := range strings.Lines(string(out)) {
		sha, ref, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			return "", nil, fmt.Errorf("git ls-remote printed %q, not <sha> <tab> <ref>", line)
		}
		switch name, isTag := strings.CutPrefix(ref, "refs/tags/"); {
		case ref == "refs/heads/main":
			tip = sha
		case isTag && strings.HasSuffix(name, "^{}"):
			// An annotated tag's commit, which wins over the tag object.
			tags[strings.TrimSuffix(name, "^{}")] = sha
		case isTag:
			if _, peeled := tags[name]; !peeled {
				tags[name] = sha
			}
		}
	}
	return tip, tags, nil
}

// How often, and how far apart, Create reads origin for the tag gh has
// just made.
const (
	tagReads = 5
	tagWait  = 2 * time.Second
)

// tagged returns nil once origin's tag name points at sha, an error
// wrapping ErrTagMismatch when it points elsewhere, or when origin still
// shows no such tag after tagReads reads, and any other error when origin
// cannot be read or ctx ends.
func (r runner) tagged(ctx context.Context, name, sha string) error {
	for read := 1; ; read++ {
		_, tags, err := r.origin(ctx)
		if err != nil {
			return fmt.Errorf("its tag could not be read back: %w", err)
		}
		at, ok := tags[name]
		switch {
		case ok && at == sha:
			return nil
		case ok:
			return fmt.Errorf("%w: %s points at %s, not %s", ErrTagMismatch, name, at, sha)
		case read == tagReads:
			return fmt.Errorf("%w: origin has no tag %s after %d reads, %v apart", ErrTagMismatch, name, tagReads, tagWait)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("its tag could not be read back: %w", ctx.Err())
		case <-time.After(tagWait):
		}
	}
}

// holds reports whether tip's history holds sha. When the clone lacks
// tip, because origin's main moved after the clone fetched, it fetches
// origin's main first.
func (r runner) holds(ctx context.Context, tip, sha string) (bool, error) {
	if _, err := r.out(ctx, "cat-file", "-e", tip+"^{commit}"); err != nil {
		if !errors.Is(err, errNoObject) {
			return false, err
		}
		if _, err = r.out(ctx, "fetch", "--quiet", "--no-tags", "origin", "refs/heads/main"); err != nil {
			return false, err
		}
	}
	res, err := r.git.Run(ctx, "git", "merge-base", "--is-ancestor", sha, tip)
	if err != nil {
		return false, fmt.Errorf("git merge-base: %w", err)
	}
	// 1 is git's no. Anything else means it could not answer.
	switch res.Code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("git merge-base --is-ancestor %s %s: exit status %d: %s",
			sha, tip, res.Code, bytes.TrimSpace(res.Stderr))
	}
}

// breakingIn returns what each breaking change a commit marks says, once
// each, given its subject, its Breaking-change trailers as git prints them
// and its whole message. A line breakingLine matches takes the lines below
// it that start with a blank, and are not such a line themselves, joined
// as git joins a folded trailer's, so a buried folded trailer reads whole,
// and one git has read already reads as the same text and is not counted
// twice. A mark that says nothing is the subject.
func breakingIn(subject, trailers, message string) []string {
	var (
		texts  []string
		marked bool
	)
	add := func(text string) {
		if text != "" && !slices.Contains(texts, text) {
			texts = append(texts, text)
		}
	}
	for trailer := range strings.SplitSeq(trailers, trailerSep) {
		if strings.TrimSpace(trailer) == "" {
			continue
		}
		marked = true
		_, value, _ := strings.Cut(trailer, ":")
		add(strings.TrimSpace(value))
	}
	lines := strings.Split(message, "\n")
	for i := 0; i < len(lines); i++ {
		m := breakingLine.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		marked = true
		var text strings.Builder
		text.WriteString(m[1])
		for i+1 < len(lines) && folds(lines[i+1]) {
			i++
			text.WriteString(" " + strings.TrimLeft(lines[i], " \t"))
		}
		add(strings.TrimSpace(text.String()))
	}
	if marked && len(texts) == 0 {
		texts = []string{subject}
	}
	return texts
}

// folds reports whether line continues the trailer above it, as git reads
// a trailer: it starts with a blank and has more than blanks. A line that
// marks a breaking change of its own does not.
func folds(line string) bool {
	blank := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
	return blank && strings.TrimSpace(line) != "" && !breakingLine.MatchString(line)
}

// versions returns the release tags git tag lists, every one or those the
// filter picks, such as --merged <sha>, ignoring every tag that is not
// vX.Y.Z.
func (r runner) versions(ctx context.Context, filter ...string) ([]Version, error) {
	out, err := r.out(ctx, slices.Concat([]string{"tag"}, filter, []string{"--list", "v*"})...)
	if err != nil {
		return nil, err
	}
	var vs []Version
	for name := range strings.FieldsSeq(string(out)) {
		if v, ok := ParseVersion(name); ok {
			vs = append(vs, v)
		}
	}
	return vs, nil
}

// The separators log's format puts between commits, fields and trailer
// values: ASCII's record, unit and group separators, which no subject or
// trailer holds.
const (
	recordSep  = "\x1e"
	fieldSep   = "\x1f"
	trailerSep = "\x1d"
)

// logFormat has git print each commit's SHA, parents, subject,
// Breaking-change trailers and whole message. git parses the trailers as
// git interpret-trailers does, from the message's last paragraph alone,
// matching the key without regard to case and joining folded lines. It
// prints each as "Key: value", so one with no value still shows.
var logFormat = "--format=%H" + "%x1f" + "%P" + "%x1f" + "%s" + "%x1f" +
	"%(trailers:key=" + Trailer + ",unfold,separator=%x1d)" + "%x1f" + "%B" + "%x1e"

// breakingLine is a line of a message that starts, after optional blanks
// and an optional "*" or "-" bullet followed by blanks, with
// Breaking-change, in any case, then optional blanks and a colon, as a
// squash merge's body lists each squashed commit's message. It captures
// the rest of the line.
var breakingLine = regexp.MustCompile(`(?im)^[ \t]*(?:[*-][ \t]+)?` + Trailer + `[ \t]*:(.*)$`)

// log returns the commits in the revision range, merges included, oldest
// first.
func (r runner) log(ctx context.Context, revisions string) ([]Commit, error) {
	out, err := r.out(ctx, "log", "--reverse", logFormat, revisions)
	if err != nil {
		return nil, err
	}
	var commits []Commit
	for record := range strings.SplitSeq(string(out), recordSep) {
		record = strings.TrimLeft(record, "\n")
		if record == "" {
			continue
		}
		fields := strings.SplitN(record, fieldSep, 5)
		if len(fields) != 5 {
			return nil, fmt.Errorf("git log printed a commit as %q, not SHA, parents, subject, trailers and message", record)
		}
		c := Commit{SHA: fields[0], Merge: len(strings.Fields(fields[1])) > 1, Subject: fields[2]}
		c.Breaking = breakingIn(c.Subject, fields[3], fields[4])
		commits = append(commits, c)
	}
	return commits, nil
}
