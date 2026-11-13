// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package execx_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

func TestOS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		argv       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "success",
			argv:       []string{"sh", "-c", "printf out; printf err >&2"},
			wantStdout: "out",
			wantStderr: "err",
		},
		{
			name:       "non-zero-exit-is-a-result",
			argv:       []string{"sh", "-c", "printf out; printf err >&2; exit 3"},
			wantCode:   3,
			wantStdout: "out",
			wantStderr: "err",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, err := execx.OS{}.Run(t.Context(), tt.argv[0], tt.argv[1:]...)
			if err != nil {
				t.Fatalf("Run(%q) error = %v, want nil", tt.argv, err)
			}
			if res.Code != tt.wantCode {
				t.Errorf("Run(%q).Code = %d, want %d", tt.argv, res.Code, tt.wantCode)
			}
			if got := string(res.Stdout); got != tt.wantStdout {
				t.Errorf("Run(%q).Stdout = %q, want %q", tt.argv, got, tt.wantStdout)
			}
			if got := string(res.Stderr); got != tt.wantStderr {
				t.Errorf("Run(%q).Stderr = %q, want %q", tt.argv, got, tt.wantStderr)
			}
		})
	}
}

func TestOSEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  []string
		// script prints what the command sees.
		script string
		want   string
	}{
		{
			name:   "added",
			env:    []string{"DIVBAST_EXECX_TEST=set"},
			script: `printf %s "${DIVBAST_EXECX_TEST}"`,
			want:   "set",
		},
		{
			name:   "later-wins",
			env:    []string{"DIVBAST_EXECX_TEST=first", "DIVBAST_EXECX_TEST=second"},
			script: `printf %s "${DIVBAST_EXECX_TEST}"`,
			want:   "second",
		},
		{
			name:   "overrides-the-caller",
			env:    []string{"HOME=/divbast-execx-home"},
			script: `printf %s "${HOME}"`,
			want:   "/divbast-execx-home",
		},
		{
			name:   "keeps-the-caller",
			env:    []string{"DIVBAST_EXECX_TEST=set"},
			script: `[ "${PATH}" = "$1" ] && printf kept`,
			want:   "kept",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, err := execx.OS{Env: tt.env}.Run(t.Context(), "sh", "-c", tt.script, "sh", os.Getenv("PATH"))
			if err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}
			if got := string(res.Stdout); res.Code != 0 || got != tt.want {
				t.Errorf("Run() = code %d, stdout %q; want code 0, stdout %q", res.Code, got, tt.want)
			}
		})
	}
}

func TestOSRunStdin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stdin      io.Reader
		wantStdout string
	}{
		{name: "fed", stdin: strings.NewReader("line one\nline two\n"), wantStdout: "line one\nline two\n"},
		// nil is no stdin at all, as Run gives, not a reader to block on.
		{name: "nil-is-none", stdin: nil, wantStdout: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, err := execx.OS{}.RunStdin(t.Context(), tt.stdin, "cat")
			if err != nil {
				t.Fatalf("RunStdin(cat) error = %v, want nil", err)
			}
			if res.Code != 0 || string(res.Stdout) != tt.wantStdout {
				t.Errorf("RunStdin(cat) = code %d, stdout %q; want code 0, stdout %q", res.Code, res.Stdout, tt.wantStdout)
			}
		})
	}
}

// TestOSRunStream (CI-22) checks that RunStream hands the command's stdout
// to the writer as the command writes it, not once it has exited: the
// command prints a line, then waits for one on stdin, which the writer
// sends only once it has seen the first. Were stdout held back until the
// command exits, each would wait on the other until the deadline. The
// Result keeps the exit status and stderr, and no stdout.
func TestOSRunStream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stdin, feed := io.Pipe()
	// exec reads stdin on a goroutine Wait waits for, which a pipe no one
	// writes to would hold forever once the deadline has killed the
	// command
	defer context.AfterFunc(ctx, func() { _ = feed.CloseWithError(ctx.Err()) })()
	out := &replier{feed: feed}
	res, err := execx.OS{}.RunStream(ctx, stdin, out, "sh", "-c", `echo first; read -r line; echo "second ${line}"; printf err >&2; exit 3`)
	if err != nil {
		t.Fatalf("RunStream() error = %v, want nil", err)
	}
	if res.Code != 3 || len(res.Stdout) != 0 || string(res.Stderr) != "err" {
		t.Errorf("RunStream() = code %d, stdout %q, stderr %q; want code 3, no stdout, stderr err", res.Code, res.Stdout, res.Stderr)
	}
	if got := out.String(); got != "first\nsecond reply\n" {
		t.Errorf("the writer got %q, want %q", got, "first\nsecond reply\n")
	}
}

// replier is a writer that keeps what it is written and, once that holds
// a first line, writes a reply line to feed and closes it.
type replier struct {
	feed *io.PipeWriter

	mu      sync.Mutex
	got     strings.Builder
	replied bool
}

func (r *replier) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got.Write(p)
	if !r.replied && strings.Contains(r.got.String(), "first\n") {
		r.replied = true
		// The command's stdin is read on another goroutine than its stdout
		// is written on, which waits for this Write to return
		go func() {
			// A reply that cannot be sent leaves the command waiting, and
			// the test fails on its deadline
			_, _ = io.WriteString(r.feed, "reply\n")
			_ = r.feed.Close()
		}()
	}
	return len(p), nil
}

func (r *replier) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got.String()
}

func TestOSCouldNotRun(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name    string
		ctx     func(t *testing.T) context.Context
		argv    []string
		wantErr error
	}{
		{
			name:    "not-found",
			ctx:     func(t *testing.T) context.Context { t.Helper(); return t.Context() },
			argv:    []string{"divbast-execx-no-such-command"},
			wantErr: exec.ErrNotFound,
		},
		{
			name:    "cancelled-before-start",
			ctx:     func(*testing.T) context.Context { return cancelled },
			argv:    []string{"sh", "-c", "exit 0"},
			wantErr: context.Canceled,
		},
		{
			name: "deadline-while-running",
			ctx: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			argv:    []string{"sleep", "10"},
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := execx.OS{}.Run(tt.ctx(t), tt.argv[0], tt.argv[1:]...)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run(%q) error = %v, want %v", tt.argv, err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.argv[0]) {
				t.Errorf("Run(%q) error = %q, want it to name %q", tt.argv, err, tt.argv[0])
			}
		})
	}
}

// recorder is an execx.TB that keeps what a Fake reports instead of failing
// the test running it.
type recorder struct {
	errors   []string
	cleanups []func()
}

func (*recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *recorder) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }

func (r *recorder) runCleanups() {
	for _, f := range slices.Backward(r.cleanups) {
		f()
	}
}

func TestFakeReplays(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")
	rec := &recorder{}
	fake := execx.NewFake(rec,
		execx.Call{Argv: []string{"git", "rev-parse", "HEAD"}, Result: execx.Result{Stdout: []byte("abc\n")}},
		execx.Call{Argv: []string{"skopeo", "inspect"}, Result: execx.Result{Code: 1, Stderr: []byte("first")}},
		execx.Call{Argv: []string{"skopeo", "inspect"}, Result: execx.Result{Stderr: []byte("second")}},
		execx.Call{Argv: []string{"gh", "api", "a b"}, Err: errBoom},
	)

	// Out of script order: replies are keyed by argv, not by position.
	res, err := fake.Run(t.Context(), "skopeo", "inspect")
	if err != nil || res.Code != 1 || string(res.Stderr) != "first" {
		t.Errorf("first skopeo call = %+v, %v; want code 1, stderr first", res, err)
	}
	res, err = fake.Run(t.Context(), "git", "rev-parse", "HEAD")
	if err != nil || string(res.Stdout) != "abc\n" {
		t.Errorf("git call = %+v, %v; want stdout abc", res, err)
	}
	res, err = fake.Run(t.Context(), "skopeo", "inspect")
	if err != nil || res.Code != 0 || string(res.Stderr) != "second" {
		t.Errorf("second skopeo call = %+v, %v; want code 0, stderr second", res, err)
	}
	// An argument holding a space is not two arguments.
	if _, err := fake.Run(t.Context(), "gh", "api", "a", "b"); err == nil {
		t.Error(`Run("gh", "api", "a", "b") error = nil, want an unexpected call`)
	}
	if _, err := fake.Run(t.Context(), "gh", "api", "a b"); !errors.Is(err, errBoom) {
		t.Errorf("gh call error = %v, want %v", err, errBoom)
	}

	rec.runCleanups()
	if len(rec.errors) != 1 || !strings.Contains(rec.errors[0], `["gh" "api" "a" "b"]`) {
		t.Errorf("reported %q, want exactly the one unexpected call", rec.errors)
	}
}

func TestFakeStdin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		want  []byte
		run   func(t *testing.T, f *execx.Fake) error
		wantR []string
	}{
		{
			name: "fed-what-was-scripted",
			want: []byte("<?php\n"),
			run: func(t *testing.T, f *execx.Fake) error {
				t.Helper()
				_, err := f.RunStdin(t.Context(), strings.NewReader("<?php\n"), "docker", "exec", "-i", "c")
				return err
			},
		},
		{
			name: "fed-something-else",
			want: []byte("<?php\n"),
			run: func(t *testing.T, f *execx.Fake) error {
				t.Helper()
				_, err := f.RunStdin(t.Context(), strings.NewReader("other"), "docker", "exec", "-i", "c")
				return err
			},
			wantR: []string{`["docker" "exec" "-i" "c"] was fed "other", want "<?php\n"`},
		},
		{
			name: "run-without-the-stdin-scripted",
			want: []byte("<?php\n"),
			run: func(t *testing.T, f *execx.Fake) error {
				t.Helper()
				_, err := f.Run(t.Context(), "docker", "exec", "-i", "c")
				return err
			},
			wantR: []string{`["docker" "exec" "-i" "c"] was fed "", want "<?php\n"`},
		},
		{
			name: "nil-stdin-matches-none-scripted",
			run: func(t *testing.T, f *execx.Fake) error {
				t.Helper()
				_, err := f.RunStdin(t.Context(), nil, "docker", "exec", "-i", "c")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := &recorder{}
			fake := execx.NewFake(rec, execx.Call{
				Argv:   []string{"docker", "exec", "-i", "c"},
				Stdin:  tt.want,
				Result: execx.Result{Stdout: []byte("done")},
			})
			err := tt.run(t, fake)
			rec.runCleanups()

			if (err != nil) != (len(tt.wantR) > 0) {
				t.Errorf("error = %v, want one only when the stdin differs", err)
			}
			if len(rec.errors) != len(tt.wantR) {
				t.Fatalf("reported %q, want %q", rec.errors, tt.wantR)
			}
			for i, want := range tt.wantR {
				if !strings.Contains(rec.errors[i], want) {
					t.Errorf("report %d = %q, want it to contain %q", i, rec.errors[i], want)
				}
			}
		})
	}
}

// TestFakeRunStream checks that RunStream replays a Call as RunStdin
// does, but writes its Stdout to the writer it is given rather than into
// the Result, and still holds the invocation to the Call's Stdin.
func TestFakeRunStream(t *testing.T) {
	t.Parallel()

	argv := []string{"zstd", "-dcq"}
	call := execx.Call{Argv: argv, Stdin: []byte("compressed"), Result: execx.Result{Stdout: []byte("plain"), Stderr: []byte("note"), Code: 1}}
	tests := []struct {
		name    string
		stdin   string
		wantOut string
		wantR   []string
	}{
		{name: "fed-what-was-scripted", stdin: "compressed", wantOut: "plain"},
		{name: "fed-something-else", stdin: "other", wantR: []string{`["zstd" "-dcq"] was fed "other", want "compressed"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := &recorder{}
			fake := execx.NewFake(rec, call)
			var out strings.Builder
			res, err := fake.RunStream(t.Context(), strings.NewReader(tt.stdin), &out, argv[0], argv[1:]...)
			rec.runCleanups()

			if got := out.String(); got != tt.wantOut {
				t.Errorf("the writer got %q, want %q", got, tt.wantOut)
			}
			if tt.wantR == nil && (err != nil || res.Code != 1 || len(res.Stdout) != 0 || string(res.Stderr) != "note") {
				t.Errorf("RunStream() = %+v, %v; want code 1, no stdout, stderr note", res, err)
			}
			if (err != nil) != (tt.wantR != nil) {
				t.Errorf("error = %v, want one only when the stdin differs", err)
			}
			if len(rec.errors) != len(tt.wantR) || (len(tt.wantR) > 0 && !strings.Contains(rec.errors[0], tt.wantR[0])) {
				t.Errorf("reported %q, want %q", rec.errors, tt.wantR)
			}
		})
	}
}

// TestFakeHonoursContext (CI-04) checks that a Fake given a context that
// is already done runs nothing, as OS runs nothing: it returns an error
// that wraps the context's and names the command, takes no scripted call,
// so a later call with a live context still gets it, and reports nothing,
// a call it has no script for included.
func TestFakeHonoursContext(t *testing.T) {
	t.Parallel()

	for name, run := range map[string]func(ctx context.Context, f *execx.Fake, argv ...string) (execx.Result, error){
		"run": func(ctx context.Context, f *execx.Fake, argv ...string) (execx.Result, error) {
			return f.Run(ctx, argv[0], argv[1:]...)
		},
		"run-stdin": func(ctx context.Context, f *execx.Fake, argv ...string) (execx.Result, error) {
			return f.RunStdin(ctx, strings.NewReader("fed"), argv[0], argv[1:]...)
		},
		"run-stream": func(ctx context.Context, f *execx.Fake, argv ...string) (execx.Result, error) {
			var out strings.Builder
			res, err := f.RunStream(ctx, strings.NewReader("fed"), &out, argv[0], argv[1:]...)
			if out.Len() > 0 {
				return res, fmt.Errorf("wrote %q to stdout", out.String())
			}
			return res, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, done := range []struct {
				why  string
				ctx  func() context.Context
				want error
			}{
				{why: "cancelled", want: context.Canceled, ctx: func() context.Context {
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					return ctx
				}},
				{why: "past its deadline", want: context.DeadlineExceeded, ctx: func() context.Context {
					ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
					t.Cleanup(cancel)
					return ctx
				}},
			} {
				rec := &recorder{}
				fake := execx.NewFake(rec, execx.Call{Argv: []string{"git", "status"}, Result: execx.Result{Stdout: []byte("clean")}})

				for _, argv := range [][]string{{"git", "status"}, {"git", "push"}} {
					_, err := run(done.ctx(), fake, argv...)
					if !errors.Is(err, done.want) || !strings.Contains(fmt.Sprint(err), argv[0]) {
						t.Errorf("%s: %q error = %v, want one naming %s and wrapping %v", done.why, argv, err, argv[0], done.want)
					}
				}
				res, err := fake.Run(t.Context(), "git", "status")
				if err != nil || string(res.Stdout) != "clean" {
					t.Errorf("%s: with a live context after, git status = %+v, %v; want the scripted call", done.why, res, err)
				}
				rec.runCleanups()
				if len(rec.errors) != 0 {
					t.Errorf("%s: reported %q, want nothing", done.why, rec.errors)
				}
			}
		})
	}
}

func TestFakeFailsTheTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script []execx.Call
		run    [][]string
		want   []string
	}{
		{
			name:   "unexpected-call",
			script: []execx.Call{{Argv: []string{"git", "status"}}},
			run:    [][]string{{"git", "status"}, {"git", "push"}},
			want:   []string{`unexpected call ["git" "push"]`},
		},
		{
			name:   "called-too-often",
			script: []execx.Call{{Argv: []string{"git", "status"}}},
			run:    [][]string{{"git", "status"}, {"git", "status"}},
			want:   []string{`unexpected call ["git" "status"]`},
		},
		{
			name:   "never-called",
			script: []execx.Call{{Argv: []string{"git", "status"}}, {Argv: []string{"git", "fetch"}}},
			run:    [][]string{{"git", "status"}},
			want:   []string{`scripted call never ran: ["git" "fetch"]`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := &recorder{}
			fake := execx.NewFake(rec, tt.script...)
			for _, argv := range tt.run {
				// The returned error is checked by TestFakeReplays; this
				// test is about what reaches the test log.
				_, _ = fake.Run(t.Context(), argv[0], argv[1:]...)
			}
			rec.runCleanups()

			if len(rec.errors) != len(tt.want) {
				t.Fatalf("reported %q, want %d failure(s) %q", rec.errors, len(tt.want), tt.want)
			}
			for i, want := range tt.want {
				if !strings.Contains(rec.errors[i], want) {
					t.Errorf("report %d = %q, want it to contain %q", i, rec.errors[i], want)
				}
			}
		})
	}
}
