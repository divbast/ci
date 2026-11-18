// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestPollPassesAtOnce(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		start := time.Now()
		err := Poll(t.Context(), 0, time.Second, func(context.Context) error {
			calls++
			return nil
		})
		if err != nil {
			t.Fatalf("Poll = %v, want nil", err)
		}
		if calls != 1 {
			t.Errorf("try ran %d times, want 1", calls)
		}
		if got := time.Since(start); got != 0 {
			t.Errorf("elapsed %s, want 0", got)
		}
	})
}

func TestPollRetriesUntilItPasses(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		start := time.Now()
		err := Poll(t.Context(), 0, time.Second, func(context.Context) error {
			calls++
			if calls <= 2 {
				return NotYet(errors.New("down"))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Poll = %v, want nil", err)
		}
		if calls != 3 {
			t.Errorf("try ran %d times, want 3", calls)
		}
		if got := time.Since(start); got != 2*time.Second {
			t.Errorf("elapsed %s, want 2s", got)
		}
	})
}

func TestPollReturnsOtherErrorsAtOnce(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		stop := errors.New("stopped")
		calls := 0
		err := Poll(t.Context(), 0, time.Second, func(context.Context) error {
			calls++
			return stop
		})
		if !errors.Is(err, stop) {
			t.Errorf("Poll = %v, want %v", err, stop)
		}
		if calls != 1 {
			t.Errorf("try ran %d times, want 1", calls)
		}
	})
}

func TestPollGivesUpAfterItsBudget(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		down := errors.New("down")
		start := time.Now()
		err := Poll(t.Context(), 5*time.Second, time.Second, func(context.Context) error {
			return NotYet(down)
		})
		if !errors.Is(err, down) {
			t.Errorf("Poll = %v, want it to wrap %v", err, down)
		}
		if err == nil || !strings.Contains(err.Error(), "still failing after 5s") {
			t.Errorf("Poll = %v, want it to say it was still failing after 5s", err)
		}
		if got := time.Since(start); got < 5*time.Second || got >= 6*time.Second {
			t.Errorf("elapsed %s, want from 5s to under 6s", got)
		}
	})
}

func TestPollStopsWhenTheContextEnds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		time.AfterFunc(2*time.Second, cancel)
		down := errors.New("down")
		err := Poll(ctx, 0, time.Second, func(context.Context) error {
			return NotYet(down)
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Poll = %v, want it to wrap context.Canceled", err)
		}
		if !errors.Is(err, down) {
			t.Errorf("Poll = %v, want it to wrap %v", err, down)
		}
	})
}

func TestPollBoundsTheTry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		err := Poll(t.Context(), 3*time.Second, time.Second, func(ctx context.Context) error {
			<-ctx.Done()
			return NotYet(ctx.Err())
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Poll = %v, want it to wrap context.DeadlineExceeded", err)
		}
		if got := time.Since(start); got > 3*time.Second {
			t.Errorf("elapsed %s, want at most 3s", got)
		}
	})
}

func TestNotYetOfNilIsNil(t *testing.T) {
	t.Parallel()
	if err := NotYet(nil); err != nil {
		t.Errorf("NotYet(nil) = %v, want nil", err)
	}
}
