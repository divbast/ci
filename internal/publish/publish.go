// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package publish decides whether a run publishes the image it built.
//
// A run publishes when main moved since the commit the published image
// was built from, when what goes into the image moved without a new
// commit, or when someone asks by hand. A caller can gate the first on
// the second, so that main moving publishes only when the image's content
// moved with it. It never moves the published image backwards: a run that
// built an older commit would take back whatever the newer image fixed.
package publish

import (
	"context"
	"fmt"
	"regexp"
)

// Event is the GitHub Actions event that started the run, as in
// github.event_name.
type Event string

// The events that may publish.
const (
	// EventPush is a push to main.
	EventPush Event = "push"
	// EventSchedule is the daily slot.
	EventSchedule Event = "schedule"
	// EventDispatch is a run started by hand.
	EventDispatch Event = "workflow_dispatch"
)

// Decision is whether to publish, and why.
type Decision struct {
	Publish bool
	Reason  string
}

// String renders d as the line the run's log and summary show, such as
// "publish: nothing is published yet" or "skip: already published".
func (d Decision) String() string {
	if d.Publish {
		return "publish: " + d.Reason
	}
	return "skip: " + d.Reason
}

// Git answers what Decide needs to know about the repository's history.
type Git interface {
	// CommitExists reports whether sha names a commit the repository has.
	CommitExists(ctx context.Context, sha string) (bool, error)
	// IsAncestor reports whether ancestor is descendant or one of its
	// ancestors. descendant may also be a ref, such as origin/main.
	IsAncestor(ctx context.Context, ancestor, descendant string) (bool, error)
}

// mainRef is main as the run fetched it, which a checkout of a pull
// request or of an older commit still has.
const mainRef = "origin/main"

var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Decide decides whether a run started by ev publishes built, the commit
// it built, given published, the commit the published image was built
// from, or "" when nothing is published yet. contentChange, when not
// empty, says what moved in the image's content since it was published,
// such as a library built from its branch's head.
//
// With main where it was published, a run publishes when contentChange
// says the content moved, and a push or the daily slot skips otherwise.
// With main moved past it, a run publishes whatever the content did,
// unless gated: then a push or the daily slot publishes only when
// contentChange says the content moved too, and skips a move of main that
// changed nothing in the image. A run started by hand publishes either
// way.
//
// Decide never publishes over a newer image, whatever moved. It returns an
// error, and so no decision, for an event that does not publish, a commit
// that is not a full SHA, a published commit that is not on main, a built
// commit that has diverged from it, and when git cannot answer.
func Decide(ctx context.Context, g Git, ev Event, built, published, contentChange string, gated bool) (Decision, error) {
	switch ev {
	case EventPush, EventSchedule, EventDispatch:
	default:
		return Decision{}, fmt.Errorf("only a push to main, the daily slot and a manual run publish, not a %s run", ev)
	}
	// Both go to git as arguments: neither may pass for an option.
	if !commit.MatchString(built) {
		return Decision{}, fmt.Errorf("the built commit %q is not a full commit SHA", built)
	}
	if published == "" {
		return publishing("nothing is published yet"), nil
	}
	if !commit.MatchString(published) {
		return Decision{}, fmt.Errorf("the published commit %q is not a full commit SHA", published)
	}

	onMain, err := g.CommitExists(ctx, published)
	if err == nil && onMain {
		onMain, err = g.IsAncestor(ctx, published, mainRef)
	}
	if err != nil {
		return Decision{}, fmt.Errorf("check that the published %s is on main: %w", published, err)
	}
	if !onMain {
		return Decision{}, fmt.Errorf("the published image was built from %s, which is not on main", published)
	}

	if published == built {
		switch {
		case ev == EventDispatch:
			return publishing("republishing %s by hand", published), nil
		case contentChange != "":
			return publishing("content moved: %s", contentChange), nil
		case ev == EventSchedule:
			return skipping("main has not moved since %s", published), nil
		default:
			return skipping("already published"), nil
		}
	}

	moved, err := g.IsAncestor(ctx, published, built)
	if err != nil {
		return Decision{}, fmt.Errorf("check that %s follows the published %s: %w", built, published, err)
	}
	if moved {
		switch {
		case !gated:
			return publishing("main moved from %s to %s", published, built), nil
		case contentChange != "":
			return publishing("main moved from %s to %s; content moved: %s", published, built, contentChange), nil
		case ev == EventDispatch:
			return publishing("main moved from %s to %s", published, built), nil
		default:
			return skipping("main moved from %s to %s, and no architecture's manifest did", published, built), nil
		}
	}
	older, err := g.IsAncestor(ctx, built, published)
	if err != nil {
		return Decision{}, fmt.Errorf("check that %s precedes the published %s: %w", built, published, err)
	}
	if older {
		return skipping("%s, published while this run built %s, is newer", published, built), nil
	}
	return Decision{}, fmt.Errorf("%s and the published %s have diverged", built, published)
}

func publishing(format string, args ...any) Decision {
	return Decision{Publish: true, Reason: fmt.Sprintf(format, args...)}
}

func skipping(format string, args ...any) Decision {
	return Decision{Publish: false, Reason: fmt.Sprintf(format, args...)}
}
