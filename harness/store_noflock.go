// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package harness

import (
	"context"
	"os"
)

// fileLocks says whether lockFile locks a file that other processes see:
// not here, where there is no flock, so only a process's own builds and
// removals keep out of each other's way.
const fileLocks = false

// lockFile locks nothing here, and returns no file to close.
func lockFile(context.Context, string, bool) (*os.File, error) {
	return nil, nil
}
