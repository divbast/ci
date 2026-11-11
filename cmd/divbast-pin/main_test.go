// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sha1 = "3d3c42e5aac5ba805825da76410c181273ba90b1"
	sha2 = "0f6bb7320c4b4a9e3a1d5c3b2a1f0e9d8c7b6a59"
)

func workflows(t *testing.T, refs ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, ref := range refs {
		body := "jobs:\n  lint:\n    uses: divbast/ci/.github/workflows/lint.yml@" + ref + " # v1.0.0\n"
		name := filepath.Join(dir, "w"+string(rune('a'+i))+".yml")
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		refs       []string
		args       func(dir string) []string
		wantCode   int
		wantStdout string
		// wantStderr lists what stderr must contain.
		wantStderr []string
	}{
		{
			name:       "prints-the-pin",
			refs:       []string{sha1, sha1},
			args:       func(dir string) []string { return []string{"-dir", dir} },
			wantStdout: sha1 + "\n",
		},
		{
			name:       "matches-expect",
			refs:       []string{sha1},
			args:       func(dir string) []string { return []string{"-dir", dir, "-expect", sha1} },
			wantStdout: sha1 + "\n",
		},
		{
			name:       "mismatch",
			refs:       []string{sha1},
			args:       func(dir string) []string { return []string{"-dir", dir, "-expect", sha2} },
			wantCode:   1,
			wantStderr: []string{sha1, sha2},
		},
		{
			name:       "mixed",
			refs:       []string{sha1, sha2},
			args:       func(dir string) []string { return []string{"-dir", dir, "-expect", sha1} },
			wantCode:   1,
			wantStderr: []string{sha1, sha2},
		},
		{
			name:       "none",
			args:       func(dir string) []string { return []string{"-dir", dir} },
			wantCode:   1,
			wantStderr: []string{"no workflow pins divbast/ci"},
		},
		{
			name:       "missing-dir",
			args:       func(dir string) []string { return []string{"-dir", filepath.Join(dir, "absent")} },
			wantCode:   1,
			wantStderr: []string{"absent"},
		},
		{
			name:       "stray-argument",
			args:       func(dir string) []string { return []string{"-dir", dir, "extra"} },
			wantCode:   2,
			wantStderr: []string{`unexpected argument "extra"`},
		},
		{
			name:       "unknown-flag",
			args:       func(string) []string { return []string{"-nope"} },
			wantCode:   2,
			wantStderr: []string{"-nope"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := run(tt.args(workflows(t, tt.refs...)), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run() = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}
		})
	}
}
