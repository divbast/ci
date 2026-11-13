// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package pin finds the one divbast/ci commit a repository's workflows pin.
//
// A repository calls ci's reusable workflows at a full commit SHA, and its
// setup checks ci out at that same commit, so its workflows must agree on
// one: a half-applied update or a hand edit would otherwise run one
// commit's workflows against another commit's recipes and tools.
package pin

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
)

var (
	// ErrNoPin means no workflow calls divbast/ci at a full commit SHA.
	ErrNoPin = errors.New("no workflow pins divbast/ci to a commit")
	// ErrMixedPins means the workflows call divbast/ci at more than one ref.
	ErrMixedPins = errors.New("workflows pin more than one divbast/ci commit")
)

var (
	// usesRef matches a uses: key that calls something in divbast/ci,
	// whether it starts a line in block style or follows a { or , in a
	// flow mapping, and captures the ref after the @ whatever it is, so
	// that a branch or a short SHA is reported rather than skipped. GitHub
	// reads the owner and repository in any case, and so does this.
	usesRef = regexp.MustCompile(`(?:^\s*(?:-\s+)?|[{,]\s*)uses:\s*["']?(?i:divbast/ci)/[^@\s"',}]+@([^\s"'#,}]+)`)
	// commit is the only ref that counts as a pin.
	commit = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// FromWorkflows returns the commit every workflow in dir that calls
// divbast/ci calls it at. It reads the *.yml and *.yaml files directly in
// dir, and only their uses: keys, in block or flow style, on lines that
// are not comments.
//
// It returns an error wrapping [ErrNoPin] when no workflow calls divbast/ci
// or the one ref they use is not a full commit SHA, and one wrapping
// [ErrMixedPins] when they use more than one ref. Either message names
// every ref found, sorted, with the files that use it.
func FromWorkflows(dir *os.Root) (string, error) {
	entries, err := fs.ReadDir(dir.FS(), ".")
	if err != nil {
		return "", fmt.Errorf("read workflows in %s: %w", dir.Name(), err)
	}

	// Each ref, and the files that use it, in name order.
	used := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !isWorkflow(e.Name()) {
			continue
		}
		data, err := dir.ReadFile(e.Name())
		if err != nil {
			return "", fmt.Errorf("read workflow %s: %w", e.Name(), err)
		}
		for line := range bytes.Lines(data) {
			if bytes.HasPrefix(bytes.TrimSpace(line), []byte("#")) {
				continue
			}
			for _, m := range usesRef.FindAllSubmatch(line, -1) {
				ref := string(m[1])
				if !slices.Contains(used[ref], e.Name()) {
					used[ref] = append(used[ref], e.Name())
				}
			}
		}
	}

	refs := slices.Sorted(maps.Keys(used))
	switch {
	case len(refs) == 0:
		return "", fmt.Errorf("%w: no workflow in %s calls it", ErrNoPin, dir.Name())
	case len(refs) > 1:
		where := make([]string, 0, len(refs))
		for _, ref := range refs {
			where = append(where, ref+" in "+strings.Join(used[ref], ", "))
		}
		return "", fmt.Errorf("%w: %s", ErrMixedPins, strings.Join(where, "; "))
	case !commit.MatchString(refs[0]):
		return "", fmt.Errorf("%w: it is called at %q in %s",
			ErrNoPin, refs[0], strings.Join(used[refs[0]], ", "))
	default:
		return refs[0], nil
	}
}

func isWorkflow(name string) bool {
	ext := path.Ext(name)
	return ext == ".yml" || ext == ".yaml"
}
