// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package harness is divbast's acceptance harness. It drives containers
// through the docker or podman CLI, with the same flags a user would type,
// so a check runs under exactly the confinement an image's contract claims
// and never a looser one an SDK might set up instead. It also ships the
// probe those checks run inside a container, as the container's own PHP,
// which needs the posix extension: no-shell asks it why a path could not
// be looked up, to tell one that is absent from one it may not reach.
//
// Every container, image, network and volume it makes carries the label
// divbast.harness=<module>, where <module> is the path of the main module
// of the binary running it, and is removed when the test that made it
// ends. An app's acceptance suite is a test binary of the app's own
// module, so each repository's suite has a label of its own, and
// [Engine.Sweep] removes whatever a run of it that died left behind, and
// nothing another repository's suite on the same host made.
package harness

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// Label is the label the harness gave everything it made, whichever suite
// ran it, before it labelled by module.
//
// Deprecated: nothing the harness makes carries Label, and Sweep does not
// remove by it. [Engine.Label] returns the label it gives instead.
const Label = "divbast.harness=1"

// labelKey is the key of the label the harness gives everything it makes.
const labelKey = "divbast.harness"

// moduleLabel is the label this binary gives everything it makes,
// worked out once.
var moduleLabel = sync.OnceValue(func() string { return labelFor(debug.ReadBuildInfo()) })

// labelFor returns the label for a binary whose build info is bi, which ok
// says it records: labelKey, and the main module's path as its value. A
// binary that records no main module, as a test of files named on go
// test's command line does not, gets a unique value of its own instead, so
// its Sweep can only ever remove what it made itself.
func labelFor(bi *debug.BuildInfo, ok bool) string {
	if ok && bi.Main.Path != "" {
		return labelKey + "=" + bi.Main.Path
	}
	return labelKey + "=" + uniqueName()
}

// cleanupTimeout bounds each removal a test's cleanup runs. The test's own
// context is done by then.
const cleanupTimeout = 2 * time.Minute

// Engine is the container engine's CLI: docker or podman.
type Engine struct {
	name string
	run  execx.StdinRunner
	// label is the module's label, except in the test of Sweep itself,
	// which must not remove what tests running beside it made.
	label string
	// saves holds what its saves of images read. Every engine
	// EngineFromEnv returns shares one.
	saves *saveCache
}

// EngineFromEnv returns the engine $ENGINE names: docker, the default when
// it is unset or empty, or podman. Anything else is an error.
func EngineFromEnv() (Engine, error) {
	switch name := cmp.Or(os.Getenv("ENGINE"), "docker"); name {
	case "docker", "podman":
		e := newEngine(name, execx.OS{})
		e.saves = sharedSaves
		return e, nil
	default:
		return Engine{}, fmt.Errorf("ENGINE is %q: it must be docker or podman", name)
	}
}

func newEngine(name string, run execx.StdinRunner) Engine {
	return Engine{name: name, run: run, label: moduleLabel(), saves: newSaveCache()}
}

// Name returns the engine's command: docker or podman.
func (e Engine) Name() string { return e.name }

// Label returns the label, as key=value, that everything e makes carries,
// and that [Engine.Sweep] removes by: divbast.harness, and the path of the
// running binary's main module as its value.
func (e Engine) Label() string { return e.label }

// Sweep removes every container, image, network and volume that carries
// e's label: containers first, since an image, network or volume one still
// uses cannot go. That label is the module's, so whatever another module's
// suite made on the same host stays. Another run of this module's would
// not, so Sweep belongs before a suite starts, never beside one running.
// Every failure is returned, joined, and none stops the rest.
func (e Engine) Sweep(ctx context.Context) error {
	filter := []string{"--filter", "label=" + e.label}
	kinds := []struct{ list, remove []string }{
		{list: []string{"ps", "-a", "-q"}, remove: []string{"rm", "-f", "-v"}},
		{list: []string{"image", "ls", "-q"}, remove: []string{"image", "rm", "-f"}},
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
		// An image is listed once for each of its tags.
		seen := make(map[string]bool)
		ids := slices.DeleteFunc(strings.Fields(string(out)), func(id string) bool {
			dup := seen[id]
			seen[id] = true
			return dup
		})
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
		bytes.Contains(s, []byte("no such image")) ||
		bytes.Contains(s, []byte("image not known")) ||
		bytes.Contains(s, []byte("not found"))
}

// uniqueName returns a name no other run will have chosen, for a container,
// network or volume the caller left unnamed.
func uniqueName() string {
	return "divbast-" + strings.ToLower(rand.Text()[:12])
}
