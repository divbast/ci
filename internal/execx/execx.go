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
	"io"
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

// StdinRunner is [Runner]'s companion for a command that reads its stdin,
// such as `docker exec -i`. It keeps the same contract on Result and error,
// and a nil stdin is no stdin at all, as Run gives.
type StdinRunner interface {
	RunStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error)
}

// waitDelay bounds how long Run waits, once the process has exited or its
// context is done, for anything it left holding stdout or stderr open.
const waitDelay = 10 * time.Second

// OS is the [Runner] and [StdinRunner] that runs commands on the host,
// looked up on PATH, with the caller's environment and working directory,
// and no stdin unless RunStdin is given one.
//
// A command that exits non-zero yields a Result with that Code and a nil
// error. Run returns an error, wrapping [exec.ErrNotFound],
// [context.Canceled] or [context.DeadlineExceeded] where one applies, only
// when the command could not run or its context ended it.
type OS struct{}

// Run implements [Runner].
func (o OS) Run(ctx context.Context, name string, args ...string) (Result, error) {
	return o.RunStdin(ctx, nil, name, args...)
}

// RunStdin implements [StdinRunner].
func (OS) RunStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	var stdout, stderr bytes.Buffer
	// G204 objects to a subprocess named by a variable, which is what a
	// Runner is for. exec runs it without a shell, so no argument can
	// smuggle in a second command.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: running the caller's command is the point, with no shell
	cmd.Stdin = stdin
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

// Call is one scripted invocation: the whole argv, command name first, the
// stdin it must be fed, and what running it returns.
type Call struct {
	Argv []string
	// Stdin is what the invocation must be fed, all of it. An invocation
	// through Run, or RunStdin with a nil reader, is fed nothing.
	Stdin  []byte
	Result Result
	Err    error
}

// Fake is a [Runner] and [StdinRunner] that replays scripted calls, for
// tests.
//
// Calls are keyed by their whole argv, not by their order: each scripted
// Call answers one invocation with exactly that argv, and several Calls
// with the same argv answer successive invocations in the order given.
// An invocation the script has no Call left for fails the test and returns
// an error, as does one fed other than its Call's Stdin, and, when the
// test ends, a Call that never ran.
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
func (f *Fake) Run(ctx context.Context, name string, args ...string) (Result, error) {
	return f.RunStdin(ctx, nil, name, args...)
}

// RunStdin implements [StdinRunner]. It reads stdin to its end before it
// answers, as a command that consumed it would.
func (f *Fake) RunStdin(_ context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	argv := append([]string{name}, args...)
	k := key(argv)

	var fed []byte
	if stdin != nil {
		var err error
		if fed, err = io.ReadAll(stdin); err != nil {
			f.tb.Errorf("execx.Fake: reading the stdin of %q: %v", argv, err)
			return Result{}, fmt.Errorf("execx.Fake: reading the stdin of %q: %w", argv, err)
		}
	}

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

	if !bytes.Equal(fed, c.Stdin) {
		f.tb.Errorf("execx.Fake: %q was fed %s, want %s", argv, clip(fed), clip(c.Stdin))
		return Result{}, fmt.Errorf("execx.Fake: %q was fed other than its scripted stdin", argv)
	}
	return c.Result, c.Err
}

// clip quotes the start of b, enough to tell two stdins apart in a report
// without pasting a whole file into it.
func clip(b []byte) string {
	const keep = 120
	if len(b) <= keep {
		return fmt.Sprintf("%q", b)
	}
	return fmt.Sprintf("%q... (%d bytes)", b[:keep], len(b))
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
