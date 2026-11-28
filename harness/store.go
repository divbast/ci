// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// storeLock keeps the removal of an image in Podman's store from
// overlapping any build there. podman image rm -f also removes each
// parent image it leaves dangling, and, being forced, every container
// still using one: Buildah's build containers among them. A step one
// build took from another's cache is such a parent once the other's image
// goes, so a build running beside that removal loses its container, or
// an image it is reading in its look for a cached step, and fails.
//
// Builds share the store, since one build takes nothing from another
// that it uses, and a suite's builds run together; a removal takes it
// alone, and takes a moment. Within a process that is mu. Across
// processes, such as the go test binaries of two packages that build at
// once, it is a flock of the file at path, shared or exclusive the same
// way, on the platforms that have one.
type storeLock struct {
	// mu is this process's: a build read-locks it, a removal locks it.
	// The file's lock alone would keep the two apart within a process
	// too, but a removal waiting on it only looks again now and then,
	// and builds that keep coming could keep it waiting; mu lets no
	// build of the process start while one of its removals waits.
	mu sync.RWMutex
	// path is the file every process on the host locks, or "" for none.
	path string
}

// newStoreLock returns a store lock on the file at path, or one of this
// process's alone when path is "".
func newStoreLock(path string) *storeLock {
	return &storeLock{path: path}
}

// sharedStore is the store lock every engine EngineFromEnv returns holds:
// one file for every process of this user on the host, as rootless
// Podman keeps one store for each user.
var sharedStore = sync.OnceValue(func() *storeLock {
	return newStoreLock(storeFile(os.Getenv))
})

// storeFile returns the path of the file sharedStore locks, reading the
// environment through getenv: in $XDG_RUNTIME_DIR when it is set, the
// user's own directory, where rootless Podman keeps its runtime state and
// no other user can enter, or else in the temporary directory. There,
// on a /tmp every user shares, another user could make the file first
// and keep it from opening, which fails each build and removal rather
// than letting them overlap.
func storeFile(getenv func(string) string) string {
	dir := getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, fmt.Sprintf("divbast-harness-podman-store-%d.lock", os.Getuid()))
}

// sweepLock keeps two sweeps of an engine from running at once: within
// a process, a token that one holds at a time, and across processes an
// exclusive flock of the file at path, on the platforms that have one.
// A wait for either ends when its context does.
//
// The file is in the directory storeFile chooses, from $XDG_RUNTIME_DIR
// or the temporary directory, and named for the user, so only processes
// that share that directory take turns. Two runs whose directories differ,
// as two with different TMPDIRs, can sweep at once: one may then fail to
// remove what the other is removing already, as "removal already in
// progress", but neither removes what a run still going made.
type sweepLock struct {
	token chan struct{}
	path  string
}

// newSweepLock returns a sweep lock on the file at path, or one of this
// process's alone when path is "".
func newSweepLock(path string) *sweepLock {
	return &sweepLock{token: make(chan struct{}, 1), path: path}
}

// hold takes l and returns what releases it, waiting for a sweep that
// holds it, in this process or another, until ctx is done. The release
// releases once, however often it is called: a second call would wait on
// the token no one holds, or take the next holder's.
func (l *sweepLock) hold(ctx context.Context) (func(), error) {
	select {
	case l.token <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if l.path == "" {
		return sync.OnceFunc(func() { <-l.token }), nil
	}
	f, err := lockFile(ctx, l.path, true)
	if err != nil {
		<-l.token
		return nil, err
	}
	return sync.OnceFunc(func() {
		if f != nil {
			// Closing the file releases its lock, as for the store's
			_ = f.Close()
		}
		<-l.token
	}), nil
}

// sharedSweeps holds the sweep lock of each engine EngineFromEnv returns:
// one file for every process of this user that shares the directory, so
// that two runs that sweep as they start sweep one after the other.
var sharedSweeps = map[string]func() *sweepLock{
	"docker": sync.OnceValue(func() *sweepLock { return newSweepLock(sweepFile(os.Getenv, "docker")) }),
	"podman": sync.OnceValue(func() *sweepLock { return newSweepLock(sweepFile(os.Getenv, "podman")) }),
}

// sweepFile returns the path of the file engine's sweeps lock, in the
// directory storeFile chooses, reading the environment through getenv.
func sweepFile(getenv func(string) string, engine string) string {
	return filepath.Join(filepath.Dir(storeFile(getenv)), fmt.Sprintf("divbast-harness-%s-sweep-%d.lock", engine, os.Getuid()))
}

// storePoll is how often a wait for another process's hold on the store
// looks again.
const storePoll = 50 * time.Millisecond

// hold takes e's store for a build, which other builds may share, or, with
// removal set, for the removal of an image, which no build may overlap,
// and returns what releases it. It waits until it can, or until ctx is
// done. Only Podman's store is held: Docker's builder keeps what a build
// uses out of image rm's reach.
func (e Engine) hold(ctx context.Context, removal bool) (func(), error) {
	if e.name != "podman" || e.store == nil {
		return func() {}, nil
	}
	return e.store.hold(ctx, removal)
}

// hold takes s, shared or, with exclusive set, exclusive: this process's
// lock first, then the file's, so that each process waits on the file as
// one. A wait for this process's lock is short, as long as a build or a
// removal, and is not cut short by ctx; one for another process's is.
func (s *storeLock) hold(ctx context.Context, exclusive bool) (func(), error) {
	unlock := s.mu.RUnlock
	if exclusive {
		s.mu.Lock()
		unlock = s.mu.Unlock
	} else {
		s.mu.RLock()
	}
	if s.path == "" {
		return unlock, nil
	}
	f, err := lockFile(ctx, s.path, exclusive)
	if err != nil {
		unlock()
		return nil, err
	}
	return func() {
		if f != nil {
			// Closing the file releases its lock. One that fails to close
			// keeps it until the process ends, which is all that is left
			// to do about it.
			_ = f.Close()
		}
		unlock()
	}, nil
}

// removeImage removes the image ref, for a cleanup, once no build holds
// the store, and fails tb if it cannot, as [Engine.remove] does. ctx
// bounds the wait for the builds; the removal itself then has
// cleanupTimeout, counted from when it can run, so that a long wait never
// leaves it a context already used up.
func (e Engine) removeImage(ctx context.Context, tb testing.TB, ref string) {
	tb.Helper()
	release, err := e.hold(ctx, true)
	if err != nil {
		tb.Errorf("cleanup: %s image rm -f %s: waiting for the builds beside it to end: %v", e.name, ref, err)
		return
	}
	defer release()
	rmCtx, cancel := cleanupContext(ctx)
	defer cancel()
	e.remove(rmCtx, tb, "image", "rm", "-f", ref)
}
