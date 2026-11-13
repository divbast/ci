// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"strings"
	"testing"
)

const (
	start = `{"Action":"start","Package":"example.com/a"}` + "\n"
	pass  = `{"Action":"pass","Package":"example.com/a","Test":"TestA"}` + "\n"
	skip  = `{"Action":"skip","Package":"example.com/a","Test":"TestA"}` + "\n"
	done  = `{"Action":"pass","Package":"example.com/a"}` + "\n"
)

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		stdin      string
		wantCode   int
		wantStdout string
		wantStderr string // a line stderr must hold
	}{
		{
			name:       "passed",
			stdin:      start + pass + done,
			wantStdout: "divbast-testcount: 1 passed, 0 skipped, 0 failed in 1 package(s)\n",
		},
		{
			name:       "skipped",
			stdin:      start + skip + done,
			wantCode:   1,
			wantStdout: "divbast-testcount: 0 passed, 1 skipped, 0 failed in 1 package(s)\n",
			wantStderr: "divbast-testcount: skipped: TestA in example.com/a\n",
		},
		{
			name:       "not a stream",
			stdin:      "ok  \texample.com/a\t0.004s\n",
			wantCode:   2,
			wantStderr: "divbast-testcount: not a go test -json stream: line 1 is not an event",
		},
		{
			name:       "nothing on stdin",
			wantCode:   2,
			wantStderr: "divbast-testcount: not a go test -json stream: no events, so no test ran\n",
		},
		{
			name:       "an argument",
			args:       []string{"./..."},
			stdin:      start + pass + done,
			wantCode:   2,
			wantStderr: `divbast-testcount: unexpected argument "./...": the events come on stdin` + "\n",
		},
		{
			name:       "an unknown flag",
			args:       []string{"-min", "1"},
			wantCode:   2,
			wantStderr: "usage: go test -json ./... | divbast-testcount\n",
		},
		{
			name:       "help",
			args:       []string{"-h"},
			wantStderr: "usage: go test -json ./... | divbast-testcount\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit %d, want %d\nstderr:\n%s", code, tt.wantCode, stderr.String())
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout\n%s\nwant\n%s", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr\n%s\nwant it to hold %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantCode == 0 && tt.wantStderr == "" && stderr.Len() > 0 {
				t.Errorf("stderr\n%s\nwant nothing", stderr.String())
			}
		})
	}
}
