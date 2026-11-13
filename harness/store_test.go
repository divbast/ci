// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// stillHeld is how long a test gives a removal that should wait to show
// that it does not: one that is not held runs at once.
const stillHeld = 300 * time.Millisecond

// blockingBuilds is an engine's runner whose builds each wait until
// release is closed, and which records, in order, when each build starts
// and ends and each image it is asked to remove.
type blockingBuilds struct {
	t        *testing.T
	release  chan struct{}
	building chan struct{}
	once     sync.Once

	mu     sync.Mutex
	events []string
}

// newBlockingBuilds returns a blockingBuilds. A test defers its finish,
// so that one that stops early leaves no build holding the store that the
// cleanups Build registered wait for.
func newBlockingBuilds(t *testing.T) *blockingBuilds {
	t.Helper()
	return &blockingBuilds{t: t, release: make(chan struct{}), building: make(chan struct{}, 8)}
}

// finish lets every build end, once.
func (b *blockingBuilds) finish() {
	b.once.Do(func() { close(b.release) })
}

func (b *blockingBuilds) record(event string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}

func (b *blockingBuilds) seen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.events)
}

func (b *blockingBuilds) run(argv []string) execx.Result {
	switch {
	case argv[1] == "build":
		b.record("build starts")
		b.building <- struct{}{}
		<-b.release
		b.record("build ends")
		return execx.Result{Stdout: []byte("abc\n")}
	case slices.Equal(argv[1:4], []string{"image", "rm", "-f"}):
		b.record("rm " + argv[len(argv)-1])
		return execx.Result{}
	case slices.Equal(argv[1:3], []string{"image", "ls"}):
		// What a sweep lists, of images: one
		return execx.Result{Stdout: []byte("swept\n")}
	case argv[1] == "ps", argv[2] == "ls":
		// And of containers, networks and volumes: none
		return execx.Result{}
	default:
		b.t.Errorf("unexpected command %q", argv)
		return execx.Result{Code: 125}
	}
}

// TestRemovalWaitsForBuilds removes an image while a build runs, on
// Podman, from the same process and from what stands for another one: an
// engine with a store lock of its own on the same file, as each go test
// binary has (backlog CI-S3-1). It removes it as a Build's cleanup does,
// and as a Sweep does. Podman's image rm -f also removes each dangling
// parent image and every container using one, a build's included, so the
// removal must wait for the build to end. On Docker it runs at once: its
// builder keeps what a build uses out of image rm's reach.
func TestRemovalWaitsForBuilds(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		engine string
		// separate gives the remover a store lock of its own on the
		// builder's file, as another process has.
		separate bool
		// sweep removes by Sweep rather than as a Build's cleanup does.
		sweep bool
		// noFile gives the store lock no file, as where there is no
		// flock: this process's lock alone keeps the two apart.
		noFile bool
		waits  bool
	}{
		{name: "podman-same-process", engine: "podman", waits: true},
		{name: "podman-same-process-no-file", engine: "podman", noFile: true, waits: true},
		{name: "podman-another-process", engine: "podman", separate: true, waits: true},
		{name: "podman-sweep", engine: "podman", sweep: true, waits: true},
		{name: "podman-sweep-another-process", engine: "podman", separate: true, sweep: true, waits: true},
		{name: "docker", engine: "docker"},
		{name: "docker-sweep", engine: "docker", sweep: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.separate && !fileLocks {
				t.Skip("this platform has no lock on a file that other processes see")
			}
			ctx := t.Context()
			b := newBlockingBuilds(t)
			defer b.finish()
			lock := filepath.Join(t.TempDir(), "store.lock")
			if tt.noFile {
				lock = ""
			}
			builder := newEngine(tt.engine, runFunc(b.run))
			builder.store = newStoreLock(lock)
			remover := builder
			if tt.separate {
				remover.store = newStoreLock(lock)
			}

			built := make(chan error, 1)
			go func() {
				_, err := builder.Build(ctx, t, "testdata/mutant/Containerfile", nil)
				built <- err
			}()
			<-b.building
			gone := "localhost/other:latest"
			if tt.sweep {
				gone = "swept"
			}
			removed := make(chan struct{})
			go func() {
				defer close(removed)
				if !tt.sweep {
					remover.removeImage(ctx, t, gone)
					return
				}
				if err := remover.Sweep(ctx); err != nil {
					t.Errorf("Sweep() error = %v", err)
				}
			}()

			select {
			case <-removed:
				if tt.waits {
					t.Errorf("the removal ran while a build was running: %q", b.seen())
				}
			case <-time.After(stillHeld):
				if !tt.waits {
					t.Errorf("the removal waited for a build on %s, whose builder needs no wait", tt.engine)
				}
			}
			b.finish()
			if err := <-built; err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			<-removed
			if tt.waits {
				if got, want := b.seen(), []string{"build starts", "build ends", "rm " + gone}; !slices.Equal(got, want) {
					t.Errorf("ran %q, want %q", got, want)
				}
			}
		})
	}
}

// TestBuildsShareTheStore runs two builds at once on Podman, from one
// process and from two, and sees both under way together: only a removal
// needs the store to itself, so builds are never put in a line.
func TestBuildsShareTheStore(t *testing.T) {
	t.Parallel()

	for _, separate := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-process", true: "another-process"}[separate], func(t *testing.T) {
			t.Parallel()
			if separate && !fileLocks {
				t.Skip("this platform has no lock on a file that other processes see")
			}
			ctx := t.Context()
			b := newBlockingBuilds(t)
			defer b.finish()
			lock := filepath.Join(t.TempDir(), "store.lock")
			first := newEngine("podman", runFunc(b.run))
			first.store = newStoreLock(lock)
			second := first
			if separate {
				second.store = newStoreLock(lock)
			}

			built := make(chan error, 2)
			for _, e := range []Engine{first, second} {
				go func() {
					_, err := e.Build(ctx, t, "testdata/mutant/Containerfile", nil)
					built <- err
				}()
			}
			for range 2 {
				select {
				case <-b.building:
				case err := <-built:
					t.Fatalf("a build ended before both were under way: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatalf("one build waited for the other: %q", b.seen())
				}
			}
			b.finish()
			for range 2 {
				if err := <-built; err != nil {
					t.Errorf("Build() error = %v", err)
				}
			}
		})
	}
}

// failures is a testing.TB that keeps what a test reports as failed,
// rather than failing the test.
type failures struct {
	testing.TB

	mu   sync.Mutex
	errs []string
}

func (f *failures) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

// TestRemovalGivesUp has a removal wait, on Podman, for a build in
// another process that outlasts the removal's context. The removal never
// runs, and the cleanup says why rather than passing for one that removed
// the image.
func TestRemovalGivesUp(t *testing.T) {
	t.Parallel()
	if !fileLocks {
		t.Skip("this platform has no lock on a file that other processes see")
	}
	b := newBlockingBuilds(t)
	defer b.finish()
	lock := filepath.Join(t.TempDir(), "store.lock")
	builder := newEngine("podman", runFunc(b.run))
	builder.store = newStoreLock(lock)
	remover := builder
	remover.store = newStoreLock(lock)

	built := make(chan error, 1)
	go func() {
		_, err := builder.Build(t.Context(), t, "testdata/mutant/Containerfile", nil)
		built <- err
	}()
	<-b.building
	ctx, cancel := context.WithTimeout(t.Context(), stillHeld)
	defer cancel()
	tb := &failures{TB: t}
	remover.removeImage(ctx, tb, "localhost/other:latest")
	b.finish()
	if err := <-built; err != nil {
		t.Fatal(err)
	}
	if slices.Contains(b.seen(), "rm localhost/other:latest") {
		t.Errorf("the removal ran though it gave up: %q", b.seen())
	}
	if len(tb.errs) != 1 || !strings.Contains(tb.errs[0], "cleanup") || !strings.Contains(tb.errs[0], context.DeadlineExceeded.Error()) {
		t.Errorf("the cleanup reported %q, want one failure saying it gave up waiting", tb.errs)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Errorf("the removal returned before its context ended: %v", ctx.Err())
	}
}

// contextRun is a runner that, unlike runFunc, sees each command's
// context.
type contextRun func(ctx context.Context, argv []string) execx.Result

func (f contextRun) RunStdin(ctx context.Context, _ io.Reader, name string, args ...string) (execx.Result, error) {
	return f(ctx, append([]string{name}, args...)), nil
}

// TestRemovalHasItsTimeOnceItCanRun has a Build's cleanup wait, on Podman,
// for a build in another process that outlasts the cleanup's budget of
// cleanupTimeout. The wait is as long as the builds beside it take, and
// the removal's own budget, all of cleanupTimeout, starts only once it can
// run, rather than being used up by the wait, or never set at all.
func TestRemovalHasItsTimeOnceItCanRun(t *testing.T) {
	t.Parallel()
	if !fileLocks {
		t.Skip("this platform has no lock on a file that other processes see")
	}
	synctest.Test(t, func(t *testing.T) {
		lock := filepath.Join(t.TempDir(), "store.lock")
		b := newBlockingBuilds(t)
		defer b.finish()
		other := newEngine("podman", runFunc(b.run))
		other.store = newStoreLock(lock)
		go func() {
			if _, err := other.Build(t.Context(), t, "testdata/mutant/Containerfile", nil); err != nil {
				t.Errorf("the other build: %v", err)
			}
		}()
		<-b.building

		// What each image rm had left of its context: none at all for one
		// with no deadline
		var mu sync.Mutex
		var removals []time.Duration
		e := newEngine("podman", contextRun(func(ctx context.Context, argv []string) execx.Result {
			if slices.Equal(argv[1:4], []string{"image", "rm", "-f"}) {
				left := time.Duration(0)
				if deadline, ok := ctx.Deadline(); ok {
					left = time.Until(deadline)
				}
				mu.Lock()
				removals = append(removals, left)
				mu.Unlock()
			}
			return execx.Result{}
		}))
		e.store = newStoreLock(lock)
		scope := &cleanups{TB: t}
		if _, err := e.Build(t.Context(), scope, "testdata/mutant/Containerfile", nil); err != nil {
			t.Fatal(err)
		}
		long := cleanupTimeout + time.Minute
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			defer b.finish()
			select {
			case <-time.After(long):
			case <-stop:
			}
		}()
		start := time.Now()
		scope.run()
		if waited := time.Since(start); waited < long {
			t.Errorf("the removal ran after %v, while the other build held the store for %v", waited, long)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(removals) != 1 || removals[0] != cleanupTimeout {
			t.Errorf("image rm ran %d times, with %v of their contexts left; want once, with all %v of its own", len(removals), removals, cleanupTimeout)
		}
	})
}
