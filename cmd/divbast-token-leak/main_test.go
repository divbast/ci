// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// writeTar writes files, name then body, as a tar archive and returns its
// path.
func writeTar(t *testing.T, files ...[2]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f[0], Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f[1]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func gz(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// failingWriter is a stdout whose every write fails.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is closed") }

// TestRunVerdictUnwritable (CI-21) checks that a clean verdict that cannot
// be written exits 2, as an archive that could not be read does: never 1,
// which says the token was found.
func TestRunVerdictUnwritable(t *testing.T) {
	t.Parallel()

	token := "divbast-synthetic-token-" + rand.Text()
	clean := writeTar(t, [2]string{"index.json", "{}"})
	getenv := func(key string) string {
		if key == "GITHUB_TOKEN" {
			return token
		}
		return ""
	}
	var stderr bytes.Buffer
	if code := run(t.Context(), []string{clean}, getenv, execx.OS{}, failingWriter{}, &stderr); code != 2 {
		t.Errorf("run() = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write the verdict: stdout is closed") {
		t.Errorf("stderr = %q, want it to say the verdict could not be written", stderr.String())
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	// Made up for this test, and in no real token's format
	token := "divbast-synthetic-token-" + rand.Text()
	corrupt := "\x1f\x8b\x08\x00 not gzip after all"

	clean := writeTar(t, [2]string{"index.json", "{}"}, [2]string{"blobs/sha256/aa", gz(t, "layer")})
	leaky := writeTar(t, [2]string{"index.json", "{}"}, [2]string{"blobs/sha256/aa", gz(t, "ARG GITHUB_TOKEN="+token)},
		[2]string{"blobs/sha256/bb", "history: " + token})
	unreadable := writeTar(t, [2]string{"blobs/sha256/aa", corrupt})
	leakyThenUnreadable := writeTar(t, [2]string{"blobs/sha256/aa", token}, [2]string{"blobs/sha256/bb", corrupt})
	empty := writeTar(t)

	tests := []struct {
		name       string
		args       []string
		token      string
		wantCode   int
		wantStdout string
		wantStderr []string
	}{
		{
			name:       "clean",
			args:       []string{clean},
			token:      token,
			wantStdout: "no trace of the token in any of the 2 files in " + clean + "\n",
		},
		{
			name:     "found",
			args:     []string{leaky},
			token:    token,
			wantCode: 1,
			wantStderr: []string{
				"blobs/sha256/aa contains the GitHub token the build was given.\n",
				"blobs/sha256/bb contains the GitHub token the build was given.\n",
				"The token must reach the build only as a secret mount, never as an ARG or ENV.\n",
			},
		},
		{
			name:     "unreadable",
			args:     []string{unreadable},
			token:    token,
			wantCode: 2,
			wantStderr: []string{
				"could not read blobs/sha256/aa",
				"a blob this check cannot read is not a blob it has cleared",
			},
		},
		{
			// As the shell, which said so as it went, then stopped
			name:     "found-then-unreadable",
			args:     []string{leakyThenUnreadable},
			token:    token,
			wantCode: 2,
			wantStderr: []string{
				"blobs/sha256/aa contains the GitHub token the build was given.\n",
				"could not read blobs/sha256/bb",
			},
		},
		{
			name:       "empty",
			args:       []string{empty},
			token:      token,
			wantCode:   2,
			wantStderr: []string{empty + " holds no files to read"},
		},
		{
			name:       "missing",
			args:       []string{filepath.Join(t.TempDir(), "nope.tar")},
			token:      token,
			wantCode:   2,
			wantStderr: []string{"nope.tar"},
		},
		{
			name:       "no-token",
			args:       []string{clean},
			wantCode:   2,
			wantStderr: []string{"GITHUB_TOKEN"},
		},
		{name: "no-archive", token: token, wantCode: 2, wantStderr: []string{"want one ARCHIVE"}},
		{name: "two-archives", args: []string{clean, leaky}, token: token, wantCode: 2, wantStderr: []string{"want one ARCHIVE"}},
		{name: "help", args: []string{"-h"}, wantStderr: []string{"usage: divbast-token-leak ARCHIVE"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			getenv := func(key string) string {
				if key == "GITHUB_TOKEN" {
					return tt.token
				}
				return ""
			}
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), tt.args, getenv, execx.OS{}, &stdout, &stderr)
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
			// The one thing it must never print
			if strings.Contains(stdout.String()+stderr.String(), token) {
				t.Error("the token was printed")
			}
		})
	}
}
