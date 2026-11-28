// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package fetch

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// The words each tool passes on when the registry fails a blob request
// with a server error: Podman's, as ci's own CI logged them for a pull of
// the LibreSpeed fixture, skopeo's for a copy of it, and Docker's, as the
// containerd fetcher its store pulls through words them.
const (
	podman500 = "Error: unable to copy from source docker://ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909: " +
		"copying system image from manifest list: reading blob sha256:dd64bf2dd177757451a98fcdc999a339c35dee5d9872d8f4dc69c8f3c4dd0112: " +
		"fetching blob: received unexpected HTTP status: 500 Internal Server Error\n"
	skopeo503 = `time="2026-11-25T09:03:07Z" level=fatal msg="copying system image from manifest list: reading blob ` +
		`sha256:b839dfae01f66e15c6a8b63520557ed315bdfe036342fa7a0c537259f10d7a9a: fetching blob: received unexpected HTTP status: 503 Service Unavailable"` + "\n"
	docker502 = "Error response from daemon: failed to copy: httpReadSeeker: failed open: unexpected status code " +
		"https://ghcr.io/v2/divbast/librespeed/blobs/sha256:dd64bf2dd177757451a98fcdc999a339c35dee5d9872d8f4dc69c8f3c4dd0112: 502 Bad Gateway\n"
)

// TestRun runs a fetch again while the registry answers it with a
// server error, in any tool's words, on the last line of what the fetch
// printed, and only then: at most attempts times in all, pause apart,
// each again said on the log, and each told its attempt. Any other
// failure ends it at once, a server error that a tool retried and then
// failed past among them, as does an error from the fetch itself.
func TestRun(t *testing.T) {
	t.Parallel()

	failed := func(code int, stderr string) execx.Result { return execx.Result{Code: code, Stderr: []byte(stderr)} }
	fetched := execx.Result{Stdout: []byte("sha256:123d515e67002d5affbbbce43920d2b0ebe30e3da40e74c3a814e7bb457c9a8d\n")}
	unknown := failed(125, "Error: initializing source docker://ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909: "+
		"reading manifest sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909 in ghcr.io/divbast/librespeed: manifest unknown\n")
	notFound := failed(125, strings.Replace(podman500, "500 Internal Server Error", "404 Not Found", 1))
	// A 501 is a server error that is no passing fault
	notImplemented := failed(125, strings.Replace(podman500, "500 Internal Server Error", "501 Not Implemented", 1))
	docker504 := failed(1, strings.Replace(docker502, "502 Bad Gateway", "504 Gateway Timeout", 1))
	// The status in what was fetched is no answer from the registry
	saidInPassing := failed(1, "Error: the image's label says 500 Internal Server Errors are fine\n")
	// A fetch that could not run at all
	notRun := errors.New(`exec: "skopeo": executable file not found in $PATH`)
	// Podman's and skopeo's own retries warn of each server error they
	// retry. Only the last line says how the fetch ended: a 401, or a
	// digest that does not match, is no passing fault, whatever came before
	// it, and a 500 there is one.
	podmanWarned := "WARN[0003] Failed, retrying in 1s ... (1/3). Error: copying system image from manifest list: reading blob " +
		"sha256:dd64bf2dd177757451a98fcdc999a339c35dee5d9872d8f4dc69c8f3c4dd0112: fetching blob: received unexpected HTTP status: 503 Service Unavailable\n"
	warnedThen401 := failed(125, podmanWarned+"Error: unable to copy from source docker://ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909: "+
		"initializing source: reading manifest in ghcr.io/divbast/librespeed: received unexpected HTTP status: 401 Unauthorized\n")
	skopeoWarnedThenMismatch := failed(1, `time="2026-11-25T09:03:05Z" level=warning msg="Failed, retrying in 1s ... (1/3). Error: copying system image from manifest list: `+
		`reading blob sha256:b839dfae01f66e15c6a8b63520557ed315bdfe036342fa7a0c537259f10d7a9a: fetching blob: received unexpected HTTP status: 502 Bad Gateway"`+"\n"+
		`time="2026-11-25T09:03:07Z" level=fatal msg="copying system image from manifest list: writing blob: blob sha256:b839dfae01f66e15c6a8b63520557ed315bdfe036342fa7a0c537259f10d7a9a `+
		`digest mismatch: got sha256:0000000000000000000000000000000000000000000000000000000000000000"`+"\n")
	warnedThen500 := failed(125, podmanWarned+podman500+"\n")

	for _, tt := range []struct {
		name    string
		results []execx.Result
		err     error // what the fetch returns with the last result
		wantErr string
	}{
		{name: "at-once", results: []execx.Result{fetched}},
		{name: "after-a-500", results: []execx.Result{failed(125, podman500), fetched}},
		{name: "after-a-503-and-a-502", results: []execx.Result{failed(1, skopeo503), failed(1, docker502), fetched}},
		{name: "after-a-504", results: []execx.Result{docker504, fetched}},
		{
			name:    "server-errors-throughout",
			results: []execx.Result{failed(125, podman500), failed(1, skopeo503), failed(125, podman500)},
			wantErr: "a fetch, attempt 3 of 3: exit status 125: " + strings.TrimSpace(podman500),
		},
		{name: "manifest-unknown", results: []execx.Result{unknown}, wantErr: "a fetch, attempt 1 of 3: exit status 125: Error: initializing source"},
		{name: "a-404", results: []execx.Result{notFound}, wantErr: "404 Not Found"},
		{name: "a-501", results: []execx.Result{notImplemented}, wantErr: "501 Not Implemented"},
		{name: "a-status-in-passing", results: []execx.Result{saidInPassing}, wantErr: "attempt 1 of 3"},
		{name: "a-503-retried-then-a-401", results: []execx.Result{warnedThen401}, wantErr: "attempt 1 of 3: exit status 125: WARN[0003] Failed, retrying"},
		{name: "a-502-retried-then-a-digest-mismatch", results: []execx.Result{skopeoWarnedThenMismatch}, wantErr: "digest mismatch"},
		{name: "a-503-retried-then-a-500", results: []execx.Result{warnedThen500, fetched}},
		{
			name: "the-fetch-fails-after-a-500", results: []execx.Result{failed(125, podman500), {}},
			err: notRun, wantErr: "a fetch: " + notRun.Error(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var (
					log   bytes.Buffer
					made  []int
					times []time.Time
				)
				got, err := Run(t.Context(), &log, "a fetch", func(_ context.Context, attempt int) (execx.Result, error) {
					made = append(made, attempt)
					times = append(times, time.Now())
					if attempt > len(tt.results) {
						t.Errorf("Run() made attempt %d, want at most %d", attempt, len(tt.results))
						return execx.Result{Code: 125, Stderr: []byte("Error: nothing scripted for this attempt\n")}, nil
					}
					res := tt.results[attempt-1]
					if attempt == len(tt.results) {
						return res, tt.err
					}
					return res, nil
				})

				want := make([]int, len(tt.results))
				for i := range want {
					want[i] = i + 1
				}
				if !slices.Equal(made, want) {
					t.Errorf("Run() made attempts %v, want %v", made, want)
				}
				for i := 1; i < len(times); i++ {
					if gap := times[i].Sub(times[i-1]); gap != pause {
						t.Errorf("attempt %d came %s after the one before, want %s", i+1, gap, pause)
					}
				}
				if again := strings.Count(log.String(), "so fetching again in 5s"); again != len(tt.results)-1 {
					t.Errorf("Run() logged %d fetches again, want %d: %q", again, len(tt.results)-1, log.String())
				}
				if tt.wantErr == "" {
					if err != nil || !bytes.Equal(got.Stdout, fetched.Stdout) {
						t.Fatalf("Run() = %q, %v; want %q, nil", got.Stdout, err, fetched.Stdout)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Run() error = %v, want one holding %q", err, tt.wantErr)
				}
				if tt.err != nil && !errors.Is(err, tt.err) {
					t.Errorf("Run() error = %v, want it to wrap %v", err, tt.err)
				}
			})
		})
	}
}

// TestRunStopsWithContext ends a wait for the next attempt when the
// context is done, with the context's error.
func TestRunStopsWithContext(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), pause/2)
		defer cancel()
		calls := 0
		_, err := Run(ctx, &bytes.Buffer{}, "a fetch", func(context.Context, int) (execx.Result, error) {
			calls++
			return execx.Result{Code: 125, Stderr: []byte(podman500)}, nil
		})
		if calls != 1 || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Run() made %d attempts and returned %v, want 1, and the context's deadline", calls, err)
		}
	})
}
