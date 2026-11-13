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
	"os"
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

// StreamRunner is [StdinRunner]'s companion for a command whose stdout is
// read as the command writes it, rather than held whole in memory, such
// as a decompressor. Its stdout goes to the writer, so the Result's
// Stdout is empty; the contract on Result and error is otherwise the
// same, and a nil stdin is no stdin at all.
type StreamRunner interface {
	RunStream(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) (Result, error)
}

// waitDelay bounds how long Run waits, once the process has exited or its
// context is done, for anything it left holding stdout or stderr open.
const waitDelay = 10 * time.Second

// OS is the [Runner], [StdinRunner] and [StreamRunner] that runs commands
// on the host, looked up on PATH, with the caller's environment and
// working directory, and no stdin unless RunStdin or RunStream is given
// one.
//
// A command that exits non-zero yields a Result with that Code and a nil
// error. Run returns an error, wrapping [exec.ErrNotFound],
// [context.Canceled] or [context.DeadlineExceeded] where one applies, only
// when the command could not run or its context ended it.
type OS struct {
	// Env holds NAME=value entries every command gets on top of the
	// caller's environment. An entry overrides the caller's value for its
	// name, and a later entry an earlier one.
	Env []string
}

// Run implements [Runner].
func (o OS) Run(ctx context.Context, name string, args ...string) (Result, error) {
	return o.RunStdin(ctx, nil, name, args...)
}

// RunStdin implements [StdinRunner].
func (o OS) RunStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	var stdout bytes.Buffer
	res, err := o.run(ctx, stdin, &stdout, name, args...)
	res.Stdout = stdout.Bytes()
	return res, err
}

// RunStream implements [StreamRunner].
func (o OS) RunStream(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) (Result, error) {
	return o.run(ctx, stdin, stdout, name, args...)
}

// run runs the command with its stdout going to stdout, and returns a
// Result without it.
func (o OS) run(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) (Result, error) {
	var stderr bytes.Buffer
	// G204 objects to a subprocess named by a variable, which is what a
	// Runner is for. exec runs it without a shell, so no argument can
	// smuggle in a second command.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: running the caller's command is the point, with no shell
	if len(o.Env) > 0 {
		// exec keeps the last value it is given for a name.
		cmd.Env = append(os.Environ(), o.Env...)
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	res := Result{Stderr: stderr.Bytes()}
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
	// through Run, or RunStdin or RunStream with a nil reader, is fed
	// nothing.
	Stdin []byte
	// Result is what the invocation returns. Through RunStream, its
	// Stdout goes to the writer instead.
	Result Result
	Err    error
}

// Fake is a [Runner], [StdinRunner] and [StreamRunner] that replays
// scripted calls, for tests.
//
// Calls are keyed by their whole argv, not by their order: each scripted
// Call answers one invocation with exactly that argv, and several Calls
// with the same argv answer successive invocations in the order given.
// An invocation the script has no Call left for fails the test and returns
// an error, as does one fed other than its Call's Stdin, and, when the
// test ends, a Call that never ran.
//
// An invocation whose context is already done runs nothing, as [OS] runs
// nothing: it returns an error wrapping the context's, takes no Call,
// reads no stdin and reports nothing.
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
func (f *Fake) RunStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("run %s: %w", name, err)
	}
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

// RunStream implements [StreamRunner]. It answers as RunStdin does, but
// writes the Call's Stdout to stdout, unless the Call has an Err, and
// returns the Result without it.
func (f *Fake) RunStream(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) (Result, error) {
	res, err := f.RunStdin(ctx, stdin, name, args...)
	if err != nil {
		return Result{Stderr: res.Stderr, Code: res.Code}, err
	}
	if _, err = stdout.Write(res.Stdout); err != nil {
		err = fmt.Errorf("run %s: %w", name, err)
	}
	res.Stdout = nil
	return res, err
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
