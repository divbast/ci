// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package testfixture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// fetchAttempts is how many times Fetch runs a fetch in all while the
// registry answers it with a server error, and fetchPause how long it
// waits before each run after the first.
const (
	fetchAttempts = 3
	fetchPause    = 5 * time.Second
)

// serverError matches a registry's answer that it failed a request
// itself, in the words Podman, skopeo and Docker pass on, each of which
// ends with the status and its text: "received unexpected HTTP status:
// 500 Internal Server Error", or "unexpected status code <url>: 502 Bad
// Gateway".
var serverError = regexp.MustCompile(`\b(500 Internal Server Error|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout)\b`)

// failedOnServerError reports whether stderr, what a fetch that failed
// printed, ends with the registry's server error. Only its last line says
// how the fetch ended: Podman and skopeo warn of each 502, 503 or 504
// they retry on their own, on a line before it, so a fetch that met one
// and then failed for good, on a 401 or a digest that does not match,
// still has that server error in what it printed.
func failedOnServerError(stderr []byte) bool {
	lines := bytes.Split(bytes.TrimSpace(stderr), []byte("\n"))
	return serverError.Match(lines[len(lines)-1])
}

// Fetch runs fetch, a command that fetches from a registry, such as a
// pull of a fixture, and returns what it returned once it succeeds. It is
// for a transient external fetch: now and then ghcr.io answers a blob
// request with a server error, and serves the same blob moments later.
// Podman and skopeo retry only 502, 503 and 504 on their own, never a
// 500, which failed a pull of the LibreSpeed fixture, and a copy of it,
// and with each the test that made it.
//
// So a fetch that ended on the registry's server error is run again, after
// fetchPause, up to fetchAttempts times in all, and Fetch says so on log.
// fetch is told which attempt it makes, counting from 1, so it can clear
// what a failed one left. Any other failure ends it at once: an error
// fetch returns, which is wrapped, or a command that exits non-zero for
// another reason, or for a server error on the last attempt, which is an
// error naming what, the attempt, and the command's exit status and
// stderr.
func Fetch(ctx context.Context, log io.Writer, what string, fetch func(ctx context.Context, attempt int) (execx.Result, error)) (execx.Result, error) {
	for attempt := 1; ; attempt++ {
		res, err := fetch(ctx, attempt)
		switch {
		case err != nil:
			return res, fmt.Errorf("%s: %w", what, err)
		case res.Code == 0:
			return res, nil
		case attempt == fetchAttempts || !failedOnServerError(res.Stderr):
			return res, fmt.Errorf("%s, attempt %d of %d: exit status %d: %s", what, attempt, fetchAttempts, res.Code, bytes.TrimSpace(res.Stderr))
		}
		// A log that cannot be written to says nothing about the fetch
		_, _ = fmt.Fprintf(log, "%s, attempt %d of %d: the registry answered with a server error, so fetching again in %s: %s\n",
			what, attempt, fetchAttempts, fetchPause, bytes.TrimSpace(res.Stderr))
		select {
		case <-ctx.Done():
			return res, fmt.Errorf("%s: %w", what, ctx.Err())
		case <-time.After(fetchPause):
		}
	}
}
