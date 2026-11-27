// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package stall

import "testing"

// SetPageSize makes each page of a dashboard's history ask for n edits
// until t ends, so that a test can replay pages recorded that size. A test
// that calls it cannot run in parallel.
func SetPageSize(t *testing.T, n int) {
	t.Helper()
	old := pageSize
	pageSize = n
	t.Cleanup(func() { pageSize = old })
}

// Persistent is persistent, for its tests.
var Persistent = persistent

// PendingUpdates is pendingUpdates, for its tests, with each update's
// branch and text apart.
func PendingUpdates(body string) (branches, text, unreadable []string) {
	updates, unreadable := pendingUpdates(body)
	for _, u := range updates {
		branches = append(branches, u.branch)
		text = append(text, u.text)
	}
	return branches, text, unreadable
}
