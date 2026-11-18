// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"errors"
	"fmt"
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

// TestPollRetriesUntilItPasses checks that Poll tries again after an
// error marked by NotYet, wherever in the error's chain the mark is.
func TestPollRetriesUntilItPasses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		fail func() error
	}{
		{name: "marked", fail: func() error { return NotYet(errors.New("down")) }},
		{name: "marked inside a wrap", fail: func() error { return fmt.Errorf("probe: %w", NotYet(errors.New("down"))) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				start := time.Now()
				err := Poll(t.Context(), 0, time.Second, func(context.Context) error {
					calls++
					if calls <= 2 {
						return tt.fail()
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
		})
	}
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
		if err != stop { //nolint:errorlint // Poll returns try's error itself, unwrapped, so identity is the contract
			t.Errorf("Poll = %v, want %v itself", err, stop)
		}
		if calls != 1 {
			t.Errorf("try ran %d times, want 1", calls)
		}
	})
}

// TestPollGivesUpAfterItsBudget checks that Poll gives up when its budget
// runs out, without a last try at the deadline, where the budget's end
// and the pause's can come due together.
func TestPollGivesUpAfterItsBudget(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		down := errors.New("down")
		calls := 0
		start := time.Now()
		err := Poll(t.Context(), 5*time.Second, time.Second, func(context.Context) error {
			calls++
			return NotYet(down)
		})
		if !errors.Is(err, down) {
			t.Errorf("Poll = %v, want it to wrap %v", err, down)
		}
		if err == nil || err.Error() != "still failing after 5s: down" {
			t.Errorf("Poll = %v, want still failing after 5s: down", err)
		}
		if calls != 5 {
			t.Errorf("try ran %d times, want 5: at 0s to 4s, and not at 5s, when the budget has run out", calls)
		}
		if got := time.Since(start); got != 5*time.Second {
			t.Errorf("elapsed %s, want 5s", got)
		}
	})
}

// TestPollStopsWhenTheContextEnds checks that Poll stops when ctx ends,
// with or without a budget of its own, and says ctx ended rather than
// that the budget ran out.
func TestPollStopsWhenTheContextEnds(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		within time.Duration
	}{
		{name: "with no budget", within: 0},
		{name: "within its budget", within: 10 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				time.AfterFunc(2*time.Second, cancel)
				down := errors.New("down")
				err := Poll(ctx, tt.within, time.Second, func(context.Context) error {
					return NotYet(down)
				})
				if !errors.Is(err, context.Canceled) {
					t.Errorf("Poll = %v, want it to wrap context.Canceled", err)
				}
				if !errors.Is(err, down) {
					t.Errorf("Poll = %v, want it to wrap %v", err, down)
				}
				if err != nil && strings.Contains(err.Error(), "still failing after") {
					t.Errorf("Poll = %v, want it to say the context ended, not that the budget ran out", err)
				}
			})
		})
	}
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

// TestPollTakesANestedPollsFailureAsFinal checks that when a Poll inside
// another's try gives up, the outer one stops at once, with the inner
// one's error as it was: Poll's own failures carry no NotYet mark.
func TestPollTakesANestedPollsFailureAsFinal(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		inner func(ctx context.Context, try func(context.Context) error) error
		want  string
	}{
		{
			name: "out of budget",
			inner: func(ctx context.Context, try func(context.Context) error) error {
				return Poll(ctx, 3*time.Second, time.Second, try)
			},
			want: "still failing after 3s: down",
		},
		{
			name: "its context ended",
			inner: func(ctx context.Context, try func(context.Context) error) error {
				ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				return Poll(ctx, 0, time.Second, try)
			},
			want: "context deadline exceeded: down",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				down := errors.New("down")
				calls := 0
				start := time.Now()
				err := Poll(t.Context(), 10*time.Second, time.Second, func(ctx context.Context) error {
					calls++
					return tt.inner(ctx, func(context.Context) error { return NotYet(down) })
				})
				if calls != 1 {
					t.Errorf("the outer try ran %d times, want 1", calls)
				}
				if !errors.Is(err, down) {
					t.Errorf("Poll = %v, want it to wrap %v", err, down)
				}
				if err == nil || err.Error() != tt.want {
					t.Errorf("Poll = %v, want %s", err, tt.want)
				}
				if got := time.Since(start); got != 3*time.Second {
					t.Errorf("elapsed %s, want 3s", got)
				}
			})
		})
	}
}

// TestPollRefusesAnIntervalNotAboveZero checks that Poll refuses an
// interval of zero or less before it tries, rather than try without a
// pause.
func TestPollRefusesAnIntervalNotAboveZero(t *testing.T) {
	t.Parallel()
	for _, every := range []time.Duration{0, -time.Second} {
		t.Run(every.String(), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				err := Poll(t.Context(), 5*time.Second, every, func(context.Context) error {
					calls++
					return nil
				})
				if err == nil || !strings.Contains(err.Error(), every.String()) {
					t.Errorf("Poll = %v, want it to refuse the interval %s", err, every)
				}
				if calls != 0 {
					t.Errorf("try ran %d times, want 0", calls)
				}
			})
		})
	}
}

func TestNotYetOfNilIsNil(t *testing.T) {
	t.Parallel()
	if err := NotYet(nil); err != nil {
		t.Errorf("NotYet(nil) = %v, want nil", err)
	}
}
