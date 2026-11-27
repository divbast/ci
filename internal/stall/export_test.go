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
