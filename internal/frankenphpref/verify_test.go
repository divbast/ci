// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package frankenphpref_test

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/frankenphpref"
)

// verifyArgv is the one gh command Verify may run, in full.
var verifyArgv = []string{
	"gh", "attestation", "verify", "oci://ghcr.io/divbast/frankenphp@" + digest,
	"--repo", "divbast/frankenphp",
	"--signer-workflow", "divbast/frankenphp/.github/workflows/build.yml@refs/heads/main",
	"--source-ref", "refs/heads/main",
}

// ghVersion is `gh --version` answering as gh of version v does.
func ghVersion(v string) execx.Call {
	return execx.Call{
		Argv:   []string{"gh", "--version"},
		Result: execx.Result{Stdout: []byte("gh version " + v + " (2026-10-21)\nhttps://github.com/cli/cli/releases/tag/v" + v + "\n")},
	}
}

// verify is gh attestation verify answering with code and stderr.
func verify(code int, stderr string) execx.Call {
	return execx.Call{Argv: verifyArgv, Result: execx.Result{Code: code, Stderr: []byte(stderr)}}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	const denied = "\nError: the provided token was denied access to the requested resource\n"

	tests := []struct {
		name    string
		calls   []execx.Call
		wantErr error
		// wantMsg lists what the error message must contain.
		wantMsg []string
		wantLog string
	}{
		{
			name:  "verified",
			calls: []execx.Call{ghVersion("2.103.3"), verify(0, "")},
		},
		{
			name:  "oldest-gh-allowed",
			calls: []execx.Call{ghVersion("2.102.0"), verify(0, "")},
		},
		{
			name:  "newer-major",
			calls: []execx.Call{ghVersion("3.0.0"), verify(0, "")},
		},
		{
			name:    "not-attested",
			calls:   []execx.Call{ghVersion("2.103.3"), verify(1, denied)},
			wantErr: frankenphpref.ErrNotVerified,
			wantMsg: []string{"exited 1"},
			wantLog: denied,
		},
		{
			name:    "old-gh",
			calls:   []execx.Call{ghVersion("2.101.9")},
			wantErr: frankenphpref.ErrOldGH,
			wantMsg: []string{"2.101.9"},
		},
		// Compared by number: as strings, 2.99.99 would sort after 2.102.0.
		{
			name:    "old-gh-by-number",
			calls:   []execx.Call{ghVersion("2.99.99")},
			wantErr: frankenphpref.ErrOldGH,
		},
		{
			name: "unreadable-version",
			calls: []execx.Call{{
				Argv:   []string{"gh", "--version"},
				Result: execx.Result{Stdout: []byte("gh version DEV\n")},
			}},
			wantMsg: []string{"no version of the form X.Y.Z", "DEV"},
		},
		{
			name: "no-version-line",
			calls: []execx.Call{{
				Argv:   []string{"gh", "--version"},
				Result: execx.Result{Stdout: []byte("something else entirely\n")},
			}},
			wantMsg: []string{"printed no version"},
		},
		{
			name: "version-fails",
			calls: []execx.Call{{
				Argv:   []string{"gh", "--version"},
				Result: execx.Result{Code: 4, Stderr: []byte("gh: broken\n")},
			}},
			wantMsg: []string{"exited 4", "gh: broken"},
		},
		{
			name: "no-gh",
			calls: []execx.Call{{
				Argv: []string{"gh", "--version"},
				Err:  exec.ErrNotFound,
			}},
			wantErr: exec.ErrNotFound,
		},
		{
			name: "verify-could-not-run",
			calls: []execx.Call{ghVersion("2.103.3"), {
				Argv: verifyArgv,
				Err:  context.DeadlineExceeded,
			}},
			wantErr: context.DeadlineExceeded,
		},
	}

	ref := frankenphpref.Ref{Tag: "librespeed", Digest: digest}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log strings.Builder
			err := frankenphpref.Verify(t.Context(), execx.NewFake(t, tt.calls...), ref, &log)
			if tt.wantErr == nil && tt.wantMsg == nil {
				if err != nil {
					t.Fatalf("Verify() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatal("Verify() error = nil, want an error")
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("Verify() error = %v, want %v", err, tt.wantErr)
				}
				for _, s := range tt.wantMsg {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("Verify() error = %q, want it to contain %q", err, s)
					}
				}
			}
			if got := log.String(); got != tt.wantLog {
				t.Errorf("Verify() logged %q, want %q", got, tt.wantLog)
			}
		})
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("log gone") }

func TestVerifyUnwritableLog(t *testing.T) {
	t.Parallel()

	ref := frankenphpref.Ref{Tag: "librespeed", Digest: digest}
	fake := execx.NewFake(t, ghVersion("2.103.3"), verify(0, ""))
	err := frankenphpref.Verify(t.Context(), fake, ref, failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "log gone") {
		t.Fatalf("Verify() error = %v, want the failed write", err)
	}
}
