// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package publish

import (
	"bytes"
	"context"
	"fmt"

	"github.com/divbast/ci/internal/execx"
)

// ExecGit returns the [Git] that runs git through r, in the repository of
// the working directory.
func ExecGit(r execx.Runner) Git {
	return execGit{run: r}
}

type execGit struct {
	run execx.Runner
}

// CommitExists implements [Git] with git cat-file -e.
func (g execGit) CommitExists(ctx context.Context, sha string) (bool, error) {
	res, err := g.run.Run(ctx, "git", "cat-file", "-e", sha+"^{commit}")
	if err != nil {
		return false, fmt.Errorf("git cat-file: %w", err)
	}
	if res.Code == 0 {
		return true, nil
	}
	// git exits 128 both for an object it does not have, or one that is
	// not a commit, and for having no repository to look in. Only the
	// first is an answer.
	if bytes.Contains(res.Stderr, []byte("Not a valid object name")) {
		return false, nil
	}
	return false, fmt.Errorf("git cat-file -e %s^{commit}: exit status %d: %s", sha, res.Code, bytes.TrimSpace(res.Stderr))
}

// IsAncestor implements [Git] with git merge-base --is-ancestor.
func (g execGit) IsAncestor(ctx context.Context, ancestor, descendant string) (bool, error) {
	res, err := g.run.Run(ctx, "git", "merge-base", "--is-ancestor", ancestor, descendant)
	if err != nil {
		return false, fmt.Errorf("git merge-base: %w", err)
	}
	// 1 is git's no. Anything else, 128 for a commit or ref it does not
	// have, means it could not answer.
	switch res.Code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("git merge-base --is-ancestor %s %s: exit status %d: %s",
			ancestor, descendant, res.Code, bytes.TrimSpace(res.Stderr))
	}
}
