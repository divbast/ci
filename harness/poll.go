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
// than return. errors.Is and errors.As still see err through the mark.
// NotYet(nil) is nil.
func NotYet(err error) error {
	if err == nil {
		return nil
	}
	return &notYet{err: err}
}

// Poll calls try at once, then every `every`, pausing with Pause, until
// try returns nil, which Poll returns as nil.
//
// An error made by NotYet is kept as the last failure and Poll tries
// again. Any other error is returned at once, unchanged.
//
// When within is above zero it is the budget for the whole poll, and try
// gets a context that ends with it, so a try that hangs cannot outlast
// the budget. When the budget runs out, Poll returns "still failing after
// <within>", wrapping the last failure. With within at zero or below, try
// gets ctx itself and Poll runs until ctx ends.
//
// When ctx ends first, the result wraps both ctx's error and the last
// failure.
func Poll(ctx context.Context, within, every time.Duration, try func(context.Context) error) error {
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
		last := err
		if tryCtx.Err() == nil {
			if perr := Pause(tryCtx, every); perr == nil {
				continue
			}
		}
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("%w: %w", cerr, last)
		}
		return fmt.Errorf("still failing after %s: %w", within, last)
	}
}
