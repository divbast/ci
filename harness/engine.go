// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package harness is divbast's acceptance harness. It drives containers
// through the docker or podman CLI, with the same flags a user would type,
// so a check runs under exactly the confinement an image's contract claims
// and never a looser one an SDK might set up instead. It also ships the
// probe those checks run inside a container, as the container's own PHP.
//
// Every container, network and volume it makes carries the label
// divbast.harness=1, and is removed when the test that made it ends.
// [Engine.Sweep] removes whatever a run that died left behind.
package harness

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// Label is the label every container, network and volume the harness
// makes carries, as key=value, and what [Engine.Sweep] removes by.
const Label = "divbast.harness=1"

// cleanupTimeout bounds each removal a test's cleanup runs. The test's own
// context is done by then.
const cleanupTimeout = 2 * time.Minute

// Engine is the container engine's CLI: docker or podman.
type Engine struct {
	name string
	run  execx.StdinRunner
	// label is [Label], except in the test of Sweep itself, which must not
	// remove what tests running beside it made.
	label string
}

// EngineFromEnv returns the engine $ENGINE names: docker, the default when
// it is unset or empty, or podman. Anything else is an error.
func EngineFromEnv() (Engine, error) {
	switch name := cmp.Or(os.Getenv("ENGINE"), "docker"); name {
	case "docker", "podman":
		return newEngine(name, execx.OS{}), nil
	default:
		return Engine{}, fmt.Errorf("ENGINE is %q: it must be docker or podman", name)
	}
}

func newEngine(name string, run execx.StdinRunner) Engine {
	return Engine{name: name, run: run, label: Label}
}

// Name returns the engine's command: docker or podman.
func (e Engine) Name() string { return e.name }

// Sweep removes every container, network and volume that carries the
// harness's label: containers first, since a network or volume one still
// uses cannot go. Every failure is returned, joined, and none stops the
// rest. It removes another run's resources as readily as a dead one's, so
// it belongs before a suite starts, never beside one running.
func (e Engine) Sweep(ctx context.Context) error {
	filter := []string{"--filter", "label=" + e.label}
	kinds := []struct{ list, remove []string }{
		{list: []string{"ps", "-a", "-q"}, remove: []string{"rm", "-f", "-v"}},
		{list: []string{"network", "ls", "-q"}, remove: []string{"network", "rm"}},
		{list: []string{"volume", "ls", "-q"}, remove: []string{"volume", "rm"}},
	}

	var errs []error
	for _, k := range kinds {
		out, err := e.output(ctx, append(k.list, filter...)...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ids := strings.Fields(string(out))
		if len(ids) == 0 {
			continue
		}
		if _, err := e.output(ctx, append(k.remove, ids...)...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// output runs the engine and returns what it printed. A command that exits
// non-zero is an error naming it, with its exit status and stderr.
func (e Engine) output(ctx context.Context, args ...string) ([]byte, error) {
	res, err := e.run.RunStdin(ctx, nil, e.name, args...)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("%s %s: exit status %d: %s", e.name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}

// cleanupContext returns a context for a cleanup to remove something in.
// A test's context is done before its cleanups run, so this keeps ctx's
// values and drops its cancellation, then bounds the removal on its own.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

// remove runs the engine with args, which remove something tb made, for a
// cleanup. Something already gone is no failure; anything else that stops
// the removal fails the test.
func (e Engine) remove(ctx context.Context, tb testing.TB, args ...string) {
	tb.Helper()
	res, err := e.run.RunStdin(ctx, nil, e.name, args...)
	switch {
	case err != nil:
		tb.Errorf("cleanup: %v", err)
	case res.Code != 0 && !gone(res.Stderr):
		tb.Errorf("cleanup: %s %s: exit status %d: %s", e.name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
	}
}

// removeOnCleanup has tb's cleanup remove something it made, with args.
func (e Engine) removeOnCleanup(ctx context.Context, tb testing.TB, args ...string) {
	tb.Helper()
	tb.Cleanup(func() {
		rmCtx, cancel := cleanupContext(ctx)
		defer cancel()
		e.remove(rmCtx, tb, args...)
	})
}

// gone reports whether an engine's error says what it was asked to remove
// does not exist, in the words either engine uses.
func gone(stderr []byte) bool {
	s := bytes.ToLower(stderr)
	return bytes.Contains(s, []byte("no such container")) ||
		bytes.Contains(s, []byte("no such volume")) ||
		bytes.Contains(s, []byte("not found"))
}

// uniqueName returns a name no other run will have chosen, for a container,
// network or volume the caller left unnamed.
func uniqueName() string {
	return "divbast-" + strings.ToLower(rand.Text()[:12])
}
