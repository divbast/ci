// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package frankenphpref finds the FrankenPHP binary an app's Containerfile
// takes from divbast/frankenphp, and asks gh whether frankenphp's own main
// build attested it.
//
// An app takes the binary with one COPY whose --from= names the image by
// tag and digest, written out in full, so Renovate can follow the tag and
// move the digest:
//
//	COPY --from=ghcr.io/divbast/frankenphp:librespeed@sha256:<64 hex> --chmod=0755 /frankenphp /usr/local/bin/frankenphp
package frankenphpref

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Repository is the image divbast/frankenphp publishes its binaries as.
const Repository = "ghcr.io/divbast/frankenphp"

// Ref is the binary a Containerfile takes from [Repository].
type Ref struct {
	// Tag names the app the binary was built for, such as librespeed.
	Tag string
	// Digest is the image's digest, as sha256:<64 hex>.
	Digest string
}

// String returns the reference as the Containerfile writes it.
func (r Ref) String() string {
	return Repository + ":" + r.Tag + "@" + r.Digest
}

// Image returns the reference by digest alone, the image that is verified.
func (r Ref) Image() string {
	return Repository + "@" + r.Digest
}

var (
	// ErrNoRef means no COPY --from= names [Repository].
	ErrNoRef = errors.New("no COPY --from= takes the binary from " + Repository)
	// ErrManyRefs means the Containerfile names [Repository] more than
	// once, and only one name could be verified.
	ErrManyRefs = errors.New("the Containerfile names " + Repository + " more than once")
	// ErrUnpinned means the COPY --from= names [Repository] other than as
	// <tag>@sha256:<64 hex>, which Renovate needs to follow the tag and
	// move the digest.
	ErrUnpinned = errors.New("the binary is not pinned as " + Repository + ":<tag>@sha256:<digest>")
	// ErrNotLiteral means a COPY --from= is built from a variable. It
	// could name [Repository] at anything, and Renovate cannot move it.
	ErrNotLiteral = errors.New("a COPY --from= names a variable, not an image")
)

// pinned is the one form a reference to Repository may take: a tag as the
// OCI distribution spec allows it, and a full sha256 digest.
var pinned = regexp.MustCompile(`^` + regexp.QuoteMeta(Repository) +
	`:([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})@(sha256:[0-9a-f]{64})$`)

// Find returns the binary the Containerfile read from containerfile takes
// from [Repository].
//
// It reads the Containerfile's instructions, with continued lines joined
// and comments dropped, as BuildKit reads them. Every mention of
// [Repository] counts, wherever it stands, since each is a way in for a
// binary: there must be exactly one, and it must be a COPY's --from= flag,
// among any other flags in any order. A name that merely starts the same,
// such as ghcr.io/divbast/frankenphp-dev, is another image and does not
// count.
//
// The error wraps [ErrNotLiteral] when any COPY --from= holds a variable,
// [ErrNoRef] when nothing, or nothing but another instruction, names
// [Repository], [ErrManyRefs] when more than one place does, and
// [ErrUnpinned] when the one COPY --from= is not <tag>@sha256:<64 hex>. Its
// message names the lines involved.
func Find(containerfile io.Reader) (Ref, error) {
	type from struct {
		line  int
		value string
	}
	var (
		// The line each mention of Repository starts on, once per mention.
		mentions []int
		// Each COPY --from= that names Repository.
		copies []from
	)

	err := instructions(containerfile, func(line int, text string) error {
		for range countMentions(text) {
			mentions = append(mentions, line)
		}
		for _, value := range copyFroms(text) {
			if strings.Contains(value, "$") {
				return fmt.Errorf("%w: line %d has --from=%s", ErrNotLiteral, line, value)
			}
			if names(value) {
				copies = append(copies, from{line, value})
			}
		}
		return nil
	})
	if err != nil {
		return Ref{}, err
	}

	switch {
	case len(mentions) == 0:
		return Ref{}, ErrNoRef
	case len(mentions) > 1:
		lines := make([]string, len(mentions))
		for i, l := range mentions {
			lines[i] = strconv.Itoa(l)
		}
		return Ref{}, fmt.Errorf("%w: on line %s", ErrManyRefs, strings.Join(lines, ", line "))
	case len(copies) == 0:
		return Ref{}, fmt.Errorf("%w: line %d names it, but not as a COPY's --from=", ErrNoRef, mentions[0])
	}

	c := copies[0]
	m := pinned.FindStringSubmatch(c.value)
	if m == nil {
		return Ref{}, fmt.Errorf("%w: line %d has --from=%s", ErrUnpinned, c.line, c.value)
	}
	return Ref{Tag: m[1], Digest: m[2]}, nil
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

// countMentions counts the mentions of Repository in text, matched
// without regard to case: a registry's host name ignores case, and
// counting too many here only refuses more.
func countMentions(text string) int {
	lower := strings.ToLower(text)
	n := 0
	for at := 0; ; {
		i := strings.Index(lower[at:], Repository)
		if i < 0 {
			return n
		}
		i += at
		at = i + len(Repository)
		if (i == 0 || !isHostByte(lower[i-1])) && (at == len(lower) || !isNameByte(lower[at])) {
			n++
		}
	}
}

// names reports whether an image reference names Repository, whatever
// follows it.
func names(ref string) bool {
	lower := strings.ToLower(ref)
	rest, ok := strings.CutPrefix(lower, Repository)
	return ok && (rest == "" || !isNameByte(rest[0]))
}

// isHostByte reports whether b can stand in a host name, so that a name
// ending in it before "ghcr.io" is some other host.
func isHostByte(b byte) bool {
	return 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '.' || b == '-' || b == '_'
}

// isNameByte reports whether b can continue a repository's path, so that
// "frankenphp" followed by it names some other repository.
func isNameByte(b byte) bool {
	return isHostByte(b) || b == '/'
}

// copyFroms returns the value of every --from= flag on a COPY instruction.
// BuildKit takes a COPY's flags, in any order, before its first source.
func copyFroms(text string) []string {
	fields := strings.Fields(text)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "COPY") {
		return nil
	}
	var values []string
	for _, f := range fields[1:] {
		flag, ok := strings.CutPrefix(f, "--")
		if !ok {
			break
		}
		if name, value, ok := strings.Cut(flag, "="); ok && strings.EqualFold(name, "from") {
			values = append(values, value)
		}
	}
	return values
}
