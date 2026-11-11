// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package execx runs external commands behind the [Runner] interface, so
// that code which drives git, gh, skopeo or a container engine can be
// tested against scripted results instead of the real tools.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

// Result is what a command that ran left behind.
type Result struct {
	Stdout, Stderr []byte
	// Code is the exit status: 0 for success, the status the process
	// exited with otherwise, or -1 when a signal ended it.
	Code int
}

// Runner runs a command to completion.
//
// The contract every implementation keeps: a command that ran returns its
// Result and a nil error, whatever its exit status, so a non-zero Code is
// the caller's to judge. The error is only for a command that could not be
// run or seen through: not found, not executable, or its context done.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// waitDelay bounds how long Run waits, once the process has exited or its
// context is done, for anything it left holding stdout or stderr open.
const waitDelay = 10 * time.Second

// OS is the [Runner] that runs commands on the host, looked up on PATH,
// with the caller's environment and working directory and no stdin.
//
// A command that exits non-zero yields a Result with that Code and a nil
// error. Run returns an error, wrapping [exec.ErrNotFound],
// [context.Canceled] or [context.DeadlineExceeded] where one applies, only
// when the command could not run or its context ended it.
type OS struct{}

// Run implements [Runner].
func (OS) Run(ctx context.Context, name string, args ...string) (Result, error) {
	var stdout, stderr bytes.Buffer
	// G204 objects to a subprocess named by a variable, which is what a
	// Runner is for. exec runs it without a shell, so no argument can
	// smuggle in a second command.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: running the caller's command is the point, with no shell
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return res, nil
	}
	// Checked before the exit status: a process the context killed exits
	// non-zero too, and that status is not the command's verdict.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, fmt.Errorf("run %s: %w", name, ctxErr)
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		res.Code = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("run %s: %w", name, err)
}

// TB is the part of [testing.TB] a [Fake] reports through.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Cleanup(f func())
}

// Call is one scripted invocation: the whole argv, command name first, and
// what running it returns.
type Call struct {
	Argv   []string
	Result Result
	Err    error
}

// Fake is a [Runner] that replays scripted calls, for tests.
//
// Calls are keyed by their whole argv, not by their order: each scripted
// Call answers one invocation with exactly that argv, and several Calls
// with the same argv answer successive invocations in the order given.
// An invocation the script has no Call left for fails the test and returns
// an error, as does, when the test ends, a Call that never ran.
type Fake struct {
	tb TB

	mu      sync.Mutex
	pending map[string][]Call
}

// NewFake returns a Fake that replays calls and reports through tb.
func NewFake(tb TB, calls ...Call) *Fake {
	tb.Helper()
	f := &Fake{tb: tb, pending: make(map[string][]Call, len(calls))}
	for _, c := range calls {
		k := key(c.Argv)
		f.pending[k] = append(f.pending[k], c)
	}
	tb.Cleanup(f.checkAllRan)
	return f
}

// Run implements [Runner].
func (f *Fake) Run(_ context.Context, name string, args ...string) (Result, error) {
	argv := append([]string{name}, args...)
	k := key(argv)

	f.mu.Lock()
	queue := f.pending[k]
	if len(queue) == 0 {
		f.mu.Unlock()
		f.tb.Errorf("execx.Fake: unexpected call %q", argv)
		return Result{}, fmt.Errorf("execx.Fake: unexpected call %q", argv)
	}
	c := queue[0]
	f.pending[k] = queue[1:]
	f.mu.Unlock()

	return c.Result, c.Err
}

func (f *Fake) checkAllRan() {
	f.tb.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range slices.Sorted(maps.Keys(f.pending)) {
		for _, c := range f.pending[k] {
			f.tb.Errorf("execx.Fake: scripted call never ran: %q", c.Argv)
		}
	}
}

// key joins an argv with NUL, which no argument can hold, so that "a b"
// and "a", "b" stay apart.
func key(argv []string) string {
	return strings.Join(argv, "\x00")
}
