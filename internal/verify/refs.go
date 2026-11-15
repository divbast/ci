// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package verify checks every image a Containerfile builds from before
// anything is built: that each is pinned by tag and digest, written out in
// full so Renovate can follow the tag and move the digest, and that each
// whose publisher signs it, as [Table] names them, is verified as that
// publisher's:
//
//	ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:<64 hex>
//	FROM ${RUNTIME_IMAGE}
//	COPY --from=ghcr.io/divbast/frankenphp:librespeed@sha256:<64 hex> --chmod=0755 /frankenphp /usr/local/bin/frankenphp
package verify

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Ref is one image a Containerfile builds from, and the line naming it.
type Ref struct {
	// Name is the image's repository, such as gcr.io/distroless/cc-debian13.
	Name string
	// Tag is its tag, such as nonroot.
	Tag string
	// Digest is its digest, as sha256:<64 hex>.
	Digest string
	// Line is the line of the instruction that takes it: a FROM, a COPY
	// --from= or a RUN --mount from=.
	Line int
}

// String returns the reference as the Containerfile writes it.
func (r Ref) String() string {
	return r.Name + ":" + r.Tag + "@" + r.Digest
}

// Image returns the reference by digest alone, the image that is verified.
func (r Ref) Image() string {
	return r.Name + "@" + r.Digest
}

var (
	// ErrNoFrom means the Containerfile has no FROM, so builds nothing.
	ErrNoFrom = errors.New("the Containerfile has no FROM")
	// ErrUnpinned means an image is named other than as
	// <name>:<tag>@sha256:<64 hex>, which Renovate needs to follow the tag
	// and move the digest.
	ErrUnpinned = errors.New("an image is not pinned as <name>:<tag>@sha256:<digest>")
	// ErrNotLiteral means a COPY --from= names a variable, which could
	// name any image and which Renovate cannot move, or a FROM is built
	// from a build argument with no default before the first FROM.
	ErrNotLiteral = errors.New("an image names a variable, not an image")
	// ErrStray means a [Table] image is named somewhere other than a FROM,
	// a COPY --from= or the default of a build argument a FROM uses: a
	// second way in for it, which no verification sees.
	ErrStray = errors.New("a verified image is named where no verification sees it")
)

var (
	// pinnedTag is a tag as the OCI distribution spec allows one, and
	// pinnedDigest a full sha256 digest.
	pinnedTag    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	pinnedDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// variable is a build argument as an image may use one, ${NAME} or
	// $NAME.
	variable = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

// Refs returns every image the Containerfile read from containerfile
// builds from, in order: each FROM that is neither scratch nor an earlier
// stage, each COPY --from= that is neither a stage's name nor its number,
// and each RUN --mount whose from= is an image. A FROM's image may be a
// build argument declared, with its default, before the first FROM, and
// is that default.
//
// It reads the Containerfile's instructions, with continued lines joined
// and comments dropped, as BuildKit reads them. Every mention of a [Table]
// image counts, wherever it stands, since each is a way in for it: it may
// stand only in a FROM, a COPY --from= or the default of a build argument
// a FROM uses.
//
// The error wraps [ErrNoFrom], [ErrUnpinned], [ErrNotLiteral] or
// [ErrStray], and names the line involved.
func Refs(containerfile io.Reader) ([]Ref, error) {
	var lines []instruction
	if err := instructions(containerfile, func(line int, text string) error {
		lines = append(lines, instruction{line, text})
		return nil
	}); err != nil {
		return nil, err
	}

	r := &reader{args: map[string]arg{}}
	for _, in := range lines {
		if err := r.read(in); err != nil {
			return nil, err
		}
	}
	if len(r.stages) == 0 {
		return nil, ErrNoFrom
	}
	if err := r.stray(lines); err != nil {
		return nil, err
	}
	return r.refs, nil
}

// instruction is one instruction and the line it starts on.
type instruction struct {
	line int
	text string
}

// arg is a build argument declared before the first FROM: its default,
// whether it has one, and whether a FROM uses it.
type arg struct {
	value       string
	hasDefault  bool
	usedByFrom  bool
	declaration int
}

// reader reads a Containerfile's instructions in order.
type reader struct {
	args   map[string]arg
	stages []string // each stage's name, lower-cased, empty for none
	refs   []Ref
	// explained counts, by line, the mentions of a Table image in the
	// places one may stand.
	explained map[int]int
}

func (r *reader) read(in instruction) error {
	fields := strings.Fields(in.text)
	if len(fields) == 0 {
		return nil
	}
	switch strings.ToUpper(fields[0]) {
	case "ARG":
		if len(r.stages) == 0 {
			r.declare(in.line, fields[1:])
		}
	case "FROM":
		return r.from(in.line, fields[1:])
	case "COPY":
		for _, f := range flagValues(fields[1:], "from") {
			if err := r.source(in.line, "--from="+f, f, true); err != nil {
				return err
			}
		}
	case "RUN":
		for _, m := range flagValues(fields[1:], "mount") {
			for opt := range strings.SplitSeq(m, ",") {
				if from, ok := strings.CutPrefix(opt, "from="); ok {
					if err := r.source(in.line, "--mount from="+from, from, false); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// declare records the build arguments an ARG before the first FROM
// declares, each NAME or NAME=default.
func (r *reader) declare(line int, words []string) {
	for _, w := range words {
		name, value, ok := strings.Cut(w, "=")
		r.args[name] = arg{value: strings.Trim(value, `"'`), hasDefault: ok, declaration: line}
	}
}

// from reads a FROM's flags, such as --platform, which name no image, its
// image, and AS and the stage's name, if it names one.
func (r *reader) from(line int, words []string) error {
	for len(words) > 0 && strings.HasPrefix(words[0], "--") {
		words = words[1:]
	}
	if len(words) == 0 {
		return fmt.Errorf("line %d: a FROM names no image", line)
	}
	written := words[0]
	image, err := r.expand(line, written)
	if err != nil {
		return err
	}
	if image == written {
		r.explain(line, written)
	}
	name := ""
	if len(words) >= 3 && strings.EqualFold(words[1], "AS") {
		name = strings.ToLower(words[2])
	}
	isStage := slices.Contains(r.stages, strings.ToLower(image))
	r.stages = append(r.stages, name)
	if strings.EqualFold(image, "scratch") || isStage {
		return nil
	}
	ref, err := parseRef(line, image)
	if err != nil {
		return err
	}
	r.refs = append(r.refs, ref)
	return nil
}

// expand returns image with each build argument it uses replaced by its
// default, which must be declared before the first FROM.
func (r *reader) expand(line int, image string) (string, error) {
	var err error
	out := variable.ReplaceAllStringFunc(image, func(v string) string {
		m := variable.FindStringSubmatch(v)
		name := m[1] + m[2]
		a, ok := r.args[name]
		if !ok || !a.hasDefault {
			if err == nil {
				err = fmt.Errorf("%w: line %d has FROM %s, and %s is an unresolved build argument: "+
					"declare it with its default before the first FROM", ErrNotLiteral, line, image, v)
			}
			return v
		}
		a.usedByFrom = true
		r.args[name] = a
		return a.value
	})
	return out, err
}

// source reads one image a COPY --from= or a RUN --mount from= takes,
// written as value in what: a stage's name or number, or an image. A
// table image counts as where it may stand only through COPY --from=.
func (r *reader) source(line int, what, value string, explains bool) error {
	if strings.Contains(value, "$") {
		return fmt.Errorf("%w: line %d has %s", ErrNotLiteral, line, what)
	}
	if n, err := strconv.Atoi(value); err == nil && n >= 0 && n < len(r.stages) {
		return nil
	}
	if slices.Contains(r.stages, strings.ToLower(value)) {
		return nil
	}
	if explains {
		r.explain(line, value)
	}
	ref, err := parseRef(line, value)
	if err != nil {
		return err
	}
	r.refs = append(r.refs, ref)
	return nil
}

// explain counts the mentions of a Table image in text, on line, as ones
// in a place where one may stand.
func (r *reader) explain(line int, text string) {
	if r.explained == nil {
		r.explained = map[int]int{}
	}
	r.explained[line] += countMentions(text)
}

// stray returns an error naming each line that mentions a Table image
// more often than its FROM, COPY --from= or used build argument explains.
func (r *reader) stray(lines []instruction) error {
	for _, a := range r.args {
		if a.usedByFrom {
			r.explain(a.declaration, a.value)
		}
	}
	var bad []string
	for _, in := range lines {
		if countMentions(in.text) > r.explained[in.line] {
			bad = append(bad, strconv.Itoa(in.line))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: on line %s", ErrStray, strings.Join(bad, ", line "))
	}
	return nil
}

// parseRef reads image, which must be <name>:<tag>@sha256:<64 hex>.
func parseRef(line int, image string) (Ref, error) {
	unpinned := fmt.Errorf("%w: line %d has %s", ErrUnpinned, line, image)
	named, digest, ok := strings.Cut(image, "@")
	if !ok || !pinnedDigest.MatchString(digest) {
		return Ref{}, unpinned
	}
	colon := strings.LastIndexByte(named, ':')
	if colon <= strings.LastIndexByte(named, '/') || colon == 0 {
		return Ref{}, unpinned
	}
	name, tag := named[:colon], named[colon+1:]
	if !pinnedTag.MatchString(tag) {
		return Ref{}, unpinned
	}
	return Ref{Name: name, Tag: tag, Digest: digest, Line: line}, nil
}

// flagValues returns the value of every --<name>= flag among words, which
// BuildKit takes, in any order, before an instruction's first argument.
func flagValues(words []string, name string) []string {
	var values []string
	for _, w := range words {
		flag, ok := strings.CutPrefix(w, "--")
		if !ok {
			break
		}
		if n, value, ok := strings.Cut(flag, "="); ok && strings.EqualFold(n, name) {
			values = append(values, value)
		}
	}
	return values
}

// maxLine bounds one physical line of a Containerfile.
const maxLine = 1 << 20

// instructions calls each with every instruction in r and the line it
// starts on, and stops at the first error each returns. A line ending in
// a backslash continues on the next. A comment line, one whose first
// non-blank character is #, is dropped, as is a blank line, even inside an
// instruction.
func instructions(r io.Reader, each func(line int, text string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, maxLine)

	var (
		text  strings.Builder
		start int
	)
	for n := 1; scanner.Scan(); n++ {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if text.Len() == 0 {
			start = n
		}
		if body, more := strings.CutSuffix(strings.TrimRight(line, " \t"), `\`); more {
			text.WriteString(body)
			text.WriteByte(' ')
			continue
		}
		text.WriteString(line)
		if err := each(start, text.String()); err != nil {
			return err
		}
		text.Reset()
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read the Containerfile: %w", err)
	}
	if text.Len() > 0 {
		return each(start, text.String())
	}
	return nil
}

// countMentions counts the mentions of every Table image in text, matched
// without regard to case: a registry's host name ignores case, and
// counting too many here only refuses more.
func countMentions(text string) int {
	lower := strings.ToLower(text)
	n := 0
	for _, rule := range Table {
		prefix := strings.ToLower(rule.Prefix)
		for at := 0; ; {
			i := strings.Index(lower[at:], prefix)
			if i < 0 {
				break
			}
			i += at
			at = i + len(prefix)
			if (i == 0 || !isHostByte(lower[i-1])) && (rule.under() || at == len(lower) || !isNameByte(lower[at])) {
				n++
			}
		}
	}
	return n
}

// isHostByte reports whether b can stand in a host name, so that a name
// ending in it before a Table image's host is some other host.
func isHostByte(b byte) bool {
	return 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '.' || b == '-' || b == '_'
}

// isNameByte reports whether b can continue a repository's path, so that
// a repository followed by it names some other repository.
func isNameByte(b byte) bool {
	return isHostByte(b) || b == '/'
}
