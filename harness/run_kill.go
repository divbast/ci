// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package harness

import (
	"errors"
	"syscall"
)

// processLookups says whether processAlive can tell a process that is
// there from one that is not.
const processLookups = true

// processAlive reports whether a process with the ID pid is there: kill
// with no signal finds it, or finds it is another user's. pid is never
// 0 or less, which would name a process group.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
