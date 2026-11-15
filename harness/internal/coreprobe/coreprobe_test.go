// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/fstest"
)

// status is a PID 1 status file with every capability set clear, uid and
// gid 65532, and the fields the new assertions read.
const status = "Name:\tfrankenphp\n" +
	"Uid:\t65532\t65532\t65532\t65532\n" +
	"Gid:\t65532\t65532\t65532\t65532\n" +
	"CapInh:\t0000000000000000\n" +
	"CapPrm:\t0000000000000000\n" +
	"CapEff:\t0000000000000000\n" +
	"CapBnd:\t0000000000000000\n" +
	"CapAmb:\t0000000000000000\n" +
	"NoNewPrivs:\t1\n" +
	"Seccomp:\t2\n"

// testEnv returns an Env over proc, with root as its "/" and nothing to
// dial.
func testEnv(t *testing.T, proc fstest.MapFS, root string) *Env {
	t.Helper()
	if root == "" {
		root = t.TempDir()
	}
	return &Env{
		Proc: proc,
		Root: root,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no network in this test")
		},
		Access: func(string, uint32) error { return errors.New("no access in this test") },
	}
}

// file is a MapFS file holding s.
func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

// probe runs Main in env with args, and returns its exit status and what
// it printed on each stream.
func probe(t *testing.T, env *Env, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	code = Main(t.Context(), env, args, &out, &errs)
	return code, out.String(), errs.String()
}

// record is one record line, as probekit writes it.
func record(ok bool, what, expected, found string) string {
	status := "ok"
	if !ok {
		status = "FAIL"
	}
	return status + "\t" + what + "\t" + expected + "\t" + found + "\n"
}

func TestDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string // the start of stdout, or of stderr when wantCode is 2
	}{
		{name: "no-subcommand", wantCode: 2, want: "no subcommand given"},
		{name: "unknown", args: []string{"assert-everything"}, wantCode: 2, want: "unknown subcommand 'assert-everything'"},
		{name: "variadic-needs-one", args: []string{"assert-pid1"}, wantCode: 2, want: "assert-pid1 takes <argv>..., got 0"},
		{name: "fixed-arity", args: []string{"probe-egress", "extra"}, wantCode: 2, want: "probe-egress takes no arguments, got 1"},
		{name: "user-takes-nothing", args: []string{"user", "65532"}, wantCode: 2, want: "user takes no arguments, got 1"},
		{name: "is-file-takes-one", args: []string{"is-file"}, wantCode: 2, want: "is-file takes <path>, got 0"},
		{
			name:     "a-port-that-is-not",
			args:     []string{"assert-listeners", "80a"},
			wantCode: 1,
			want:     "FAIL\tassert-listeners completed\tno exception\t'80a' is not a TCP port",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := probe(t, testEnv(t, fstest.MapFS{}, ""), tt.args...)
			got := stdout
			if tt.wantCode == 2 {
				got = stderr
			}
			if code != tt.wantCode || !strings.HasPrefix(got, tt.want) {
				t.Errorf("probe %q = exit %d, stdout %q, stderr %q; want exit %d, starting %q",
					tt.args, code, stdout, stderr, tt.wantCode, tt.want)
			}
		})
	}
}

func TestCommandsAreCorePHPs(t *testing.T) {
	t.Parallel()

	want := []string{
		"assert-caps", "assert-listeners", "assert-no-shell", "assert-pid1", "assert-read-only",
		"http-request", "is-file", "parse-listeners", "probe-egress", "user",
	}
	commands := Commands(HostEnv())
	for _, name := range want {
		if _, ok := commands[name]; !ok {
			t.Errorf("Commands() has no %s", name)
		}
	}
}
