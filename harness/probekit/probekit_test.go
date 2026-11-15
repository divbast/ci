// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package probekit_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/divbast/ci/harness/probekit"
)

// run runs Main over commands with args, and returns its exit status and
// what it printed on each stream.
func run(t *testing.T, commands map[string]probekit.Command, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	code = probekit.Main(t.Context(), commands, args, &out, &errs)
	return code, out.String(), errs.String()
}

func TestRecordFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(*probekit.Output)
		want string
	}{
		{
			name: "ok-with-separators-flattened-and-trimmed",
			run:  func(o *probekit.Output) { o.Record(true, "a\tb", "x\ny", " z ") },
			want: "ok\ta b\tx y\tz\n",
		},
		{
			name: "fail",
			run:  func(o *probekit.Output) { o.Record(false, "what", "want", "got") },
			want: "FAIL\twhat\twant\tgot\n",
		},
		{
			name: "carriage-return-is-a-separator-too",
			run:  func(o *probekit.Output) { o.Record(true, "a\rb", "", "") },
			want: "ok\ta b\t\t\n",
		},
		{
			name: "equal-ok",
			run:  func(o *probekit.Output) { o.Equal("same", "1", "1") },
			want: "ok\tsame\t1\t1\n",
		},
		{
			name: "equal-fail",
			run:  func(o *probekit.Output) { o.Equal("differs", "1", "0") },
			want: "FAIL\tdiffers\t1\t0\n",
		},
		{
			name: "raw-write",
			run: func(o *probekit.Output) {
				if _, err := o.Write([]byte("tcp 8080\n")); err != nil {
					panic(err)
				}
			},
			want: "tcp 8080\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			commands := map[string]probekit.Command{
				"sub": {Run: func(_ context.Context, out *probekit.Output, _ []string) error {
					tt.run(out)
					return nil
				}},
			}
			_, stdout, _ := run(t, commands, "sub")
			if stdout != tt.want {
				t.Errorf("stdout = %q, want %q", stdout, tt.want)
			}
		})
	}
}

func TestMainExitCodes(t *testing.T) {
	t.Parallel()

	commands := map[string]probekit.Command{
		"pass": {Run: func(_ context.Context, out *probekit.Output, _ []string) error {
			out.Record(true, "a", "b", "b")
			out.Record(true, "c", "d", "d")
			return nil
		}},
		"fail": {Run: func(_ context.Context, out *probekit.Output, _ []string) error {
			out.Record(true, "a", "b", "b")
			out.Record(false, "c", "d", "e")
			return nil
		}},
		"boom": {Run: func(context.Context, *probekit.Output, []string) error {
			return errors.New("boom")
		}},
		"two":  {Args: []string{"x", "y"}, Run: func(context.Context, *probekit.Output, []string) error { return nil }},
		"some": {Args: []string{"port"}, Variadic: true, Run: func(context.Context, *probekit.Output, []string) error { return nil }},
		"any":  {Variadic: true, Run: func(context.Context, *probekit.Output, []string) error { return nil }},
	}

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "all-ok", args: []string{"pass"}, wantCode: 0},
		{name: "any-fail", args: []string{"fail"}, wantCode: 1},
		{
			name:       "error-is-a-failed-record",
			args:       []string{"boom"},
			wantCode:   1,
			wantStdout: "FAIL\tboom completed\tno exception\tboom\n",
		},
		{name: "no-subcommand", args: nil, wantCode: 2, wantStderr: "no subcommand given\n"},
		{name: "unknown-subcommand", args: []string{"nope"}, wantCode: 2, wantStderr: "unknown subcommand 'nope'\n"},
		{name: "usage-lists-subcommands", args: []string{"nope"}, wantCode: 2, wantStderr: "  two <x> <y>\n"},
		{name: "usage-variadic", args: []string{"nope"}, wantCode: 2, wantStderr: "  some <port>...\n"},
		{name: "usage-variadic-unnamed", args: []string{"nope"}, wantCode: 2, wantStderr: "  any [arguments...]\n"},
		{name: "too-few", args: []string{"two", "a"}, wantCode: 2, wantStderr: "two takes <x> <y>, got 1\n"},
		{name: "too-many", args: []string{"pass", "a"}, wantCode: 2, wantStderr: "pass takes no arguments, got 1\n"},
		{name: "variadic-needs-one", args: []string{"some"}, wantCode: 2, wantStderr: "some takes <port>..., got 0\n"},
		{name: "variadic-takes-many", args: []string{"some", "1", "2", "3"}, wantCode: 0},
		{name: "variadic-unnamed-takes-none", args: []string{"any"}, wantCode: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := run(t, commands, tt.args...)
			if code != tt.wantCode {
				t.Errorf("Main(%q) = %d, want %d; stdout %q, stderr %q", tt.args, code, tt.wantCode, stdout, stderr)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("Main(%q) stdout = %q, want it to hold %q", tt.args, stdout, tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("Main(%q) stderr = %q, want it to hold %q", tt.args, stderr, tt.wantStderr)
			}
		})
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestMainWriteFailure(t *testing.T) {
	t.Parallel()

	commands := map[string]probekit.Command{
		"pass": {Run: func(_ context.Context, out *probekit.Output, _ []string) error {
			out.Record(true, "a", "b", "b")
			return nil
		}},
	}
	var errs bytes.Buffer
	if code := probekit.Main(t.Context(), commands, []string{"pass"}, failingWriter{}, &errs); code != 1 {
		t.Errorf("Main() with a failing stdout = %d, want 1", code)
	}
	if !strings.Contains(errs.String(), "disk full") {
		t.Errorf("stderr = %q, want it to say why the write failed", errs.String())
	}
}
