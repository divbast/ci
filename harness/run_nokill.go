// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package harness

// processLookups says whether processAlive can tell a process that is
// there from one that is not: not here, with no kill.
const processLookups = false

// processAlive reports every process as there, since nothing here tells:
// so Sweep removes only what carries no run label, and this run's own.
func processAlive(int) bool {
	return true
}
