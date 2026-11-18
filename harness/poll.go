// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// notYet marks an error as one worth trying again after.
type notYet struct{ err error }

func (n *notYet) Error() string { return n.err.Error() }
func (n *notYet) Unwrap() error { return n.err }

// NotYet marks err as a failure that Poll should try again after, rather
// than return. Poll finds the mark anywhere in an error's chain, so
// fmt.Errorf("probe: %w", NotYet(err)) is tried again too. errors.Is and
// errors.As still see err through the mark. NotYet(nil) is nil.
func NotYet(err error) error {
	if err == nil {
		return nil
	}
	return &notYet{err: err}
}

// gaveUp is the error Poll returns when it stops on a failure it would
// otherwise have tried again. It answers errors.Is and errors.As for
// the error it holds, all but that error's NotYet mark, in place of an
// Unwrap method, which would hand the mark on: a Poll whose try returns
// it, however wrapped, stops at once.
type gaveUp struct{ err error }

func (g *gaveUp) Error() string { return g.err.Error() }

// Is reports whether errors.Is finds target in the error g holds.
func (g *gaveUp) Is(target error) bool { return errors.Is(g.err, target) }

// As reports whether errors.As finds target in the error g holds, and
// refuses a target for the NotYet mark.
func (g *gaveUp) As(target any) bool {
	if _, mark := target.(**notYet); mark {
		return false
	}
	return errors.As(g.err, target)
}

// ended returns ctx's error, or context.DeadlineExceeded once ctx's
// deadline has passed, which ctx's own timer may not have reported yet:
// when it and Pause's come due together, Pause may return first.
func ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Poll calls try at once, then every `every`, pausing with Pause, until
// try returns nil, which Poll returns as nil. An interval of zero or
// below is refused with an error before any try.
//
// An error marked by NotYet, wherever the mark is in its chain, is kept
// as the last failure and Poll tries again. Any other error is returned
// at once, unchanged.
//
// When within is above zero it is the budget for the whole poll, and try
// gets a context that ends with it, so a try that heeds its context
// cannot outlast the budget; one that ignores it runs on, and Poll waits
// for it. When the budget runs out, Poll tries no more and returns
// "still failing after <within>", wrapping the last failure. With within
// at zero or below, try gets ctx itself and Poll runs until ctx ends.
//
// When ctx ends first, the result wraps both ctx's error and the last
// failure.
//
// Either result wraps the last failure for errors.Is and errors.As, but
// not its NotYet mark: when a Poll inside another's try gives up, the
// outer Poll returns that error at once, as it would any other.
func Poll(ctx context.Context, within, every time.Duration, try func(context.Context) error) error {
	if every <= 0 {
		return fmt.Errorf("poll every %s: the interval must be above zero, or Poll would try again without a pause", every)
	}
	tryCtx := ctx
	if within > 0 {
		var cancel context.CancelFunc
		tryCtx, cancel = context.WithTimeout(ctx, within)
		defer cancel()
	}
	for {
		err := try(tryCtx)
		if err == nil {
			return nil
		}
		if _, ok := errors.AsType[*notYet](err); !ok {
			return err
		}
		// Pause returns nil when its timer wins a tie with the deadline,
		// so the deadline is checked again before another try.
		if Pause(tryCtx, every) == nil && ended(tryCtx) == nil {
			continue
		}
		if cerr := ended(ctx); cerr != nil {
			return &gaveUp{fmt.Errorf("%w: %w", cerr, err)}
		}
		return &gaveUp{fmt.Errorf("still failing after %s: %w", within, err)}
	}
}
