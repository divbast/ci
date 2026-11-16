// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package verify_test

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/verify"
)

var (
	frankenphp = verify.Ref{Name: "ghcr.io/divbast/frankenphp", Tag: "librespeed", Digest: digest, Line: 8}
	distroless = verify.Ref{Name: "gcr.io/distroless/cc-debian13", Tag: "nonroot", Digest: other, Line: 7}
	golang     = verify.Ref{Name: "golang", Tag: "1.27.4-trixie", Digest: other, Line: 1}
)

// attestArgv is the one gh command that verifies frankenphp, in full.
var attestArgv = []string{
	"gh", "attestation", "verify", "oci://ghcr.io/divbast/frankenphp@" + digest,
	"--repo", "divbast/frankenphp",
	"--signer-workflow", "divbast/frankenphp/.github/workflows/build.yml@refs/heads/main",
	"--source-ref", "refs/heads/main",
}

// cosignArgv is the one cosign command that verifies distroless, in full.
var cosignArgv = []string{
	"cosign", "verify", "gcr.io/distroless/cc-debian13@" + other,
	"--certificate-identity", "keyless@distroless.iam.gserviceaccount.com",
	"--certificate-oidc-issuer", "https://accounts.google.com",
}

// ghVersion is `gh --version` answering as gh of version v does.
func ghVersion(v string) execx.Call {
	return execx.Call{
		Argv:   []string{"gh", "--version"},
		Result: execx.Result{Stdout: []byte("gh version " + v + " (2026-10-21)\nhttps://github.com/cli/cli/releases/tag/v" + v + "\n")},
	}
}

// attest is gh attestation verify answering with code and stderr.
func attest(code int, stderr string) execx.Call {
	return execx.Call{Argv: attestArgv, Result: execx.Result{Code: code, Stderr: []byte(stderr)}}
}

// cosign is cosign verify answering with code and stderr.
func cosign(code int, stderr string) execx.Call {
	return execx.Call{Argv: cosignArgv, Result: execx.Result{Code: code, Stderr: []byte(stderr)}}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	const (
		denied   = "\nError: the provided token was denied access to the requested resource\n"
		mismatch = "Error: no matching signatures: none of the expected identities matched what was in the certificate\n"
	)
	tests := []struct {
		name    string
		refs    []verify.Ref
		calls   []execx.Call
		wantErr error
		// wantMsg lists what the error message must contain.
		wantMsg []string
		wantLog string
	}{
		{
			name:  "frankenphp-attested",
			refs:  []verify.Ref{frankenphp},
			calls: []execx.Call{ghVersion("2.103.3"), attest(0, "")},
		},
		{
			name:  "oldest-gh-allowed",
			refs:  []verify.Ref{frankenphp},
			calls: []execx.Call{ghVersion("2.102.0"), attest(0, "")},
		},
		{
			name:  "newer-major",
			refs:  []verify.Ref{frankenphp},
			calls: []execx.Call{ghVersion("3.0.0"), attest(0, "")},
		},
		{
			name:    "not-attested",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{ghVersion("2.103.3"), attest(1, denied)},
			wantErr: verify.ErrNotVerified,
			wantMsg: []string{"exited 1", "ghcr.io/divbast/frankenphp"},
			wantLog: denied,
		},
		{
			name:    "old-gh",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{ghVersion("2.101.9")},
			wantErr: verify.ErrOldGH,
			wantMsg: []string{"2.101.9"},
		},
		{
			// Compared by number: as strings, 2.99.99 would sort after 2.102.0.
			name:    "old-gh-by-number",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{ghVersion("2.99.99")},
			wantErr: verify.ErrOldGH,
		},
		{
			name:    "unreadable-version",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{{Argv: []string{"gh", "--version"}, Result: execx.Result{Stdout: []byte("gh version DEV\n")}}},
			wantMsg: []string{"no version of the form X.Y.Z", "DEV"},
		},
		{
			name:    "version-fails",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{{Argv: []string{"gh", "--version"}, Result: execx.Result{Code: 4, Stderr: []byte("gh: broken\n")}}},
			wantMsg: []string{"exited 4", "gh: broken"},
		},
		{
			name:    "no-gh",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{{Argv: []string{"gh", "--version"}, Err: exec.ErrNotFound}},
			wantErr: exec.ErrNotFound,
		},
		{
			name:    "attest-could-not-run",
			refs:    []verify.Ref{frankenphp},
			calls:   []execx.Call{ghVersion("2.103.3"), {Argv: attestArgv, Err: context.DeadlineExceeded}},
			wantErr: context.DeadlineExceeded,
		},
		{
			name:  "distroless-signed",
			refs:  []verify.Ref{distroless},
			calls: []execx.Call{cosign(0, "Verification for gcr.io/distroless/cc-debian13@"+other+" --\n")},
			// cosign's report goes to the log
			wantLog: "Verification for gcr.io/distroless/cc-debian13@" + other + " --\n",
		},
		{
			// A wrong identity is exit 12 and an unsigned image 10: any
			// status but 0 is a refusal
			name:    "distroless-another-identity",
			refs:    []verify.Ref{distroless},
			calls:   []execx.Call{cosign(12, mismatch)},
			wantErr: verify.ErrNotVerified,
			wantMsg: []string{"exited 12", "gcr.io/distroless/cc-debian13"},
			wantLog: mismatch,
		},
		{
			name:  "both-and-a-pinned-third-party-image",
			refs:  []verify.Ref{golang, distroless, frankenphp},
			calls: []execx.Call{cosign(0, ""), ghVersion("2.103.3"), attest(0, "")},
		},
		{
			// One verification for an image named twice
			name:  "distroless-twice",
			refs:  []verify.Ref{distroless, distroless},
			calls: []execx.Call{cosign(0, "")},
		},
		{
			name:    "frankenphp-twice",
			refs:    []verify.Ref{frankenphp, {Name: frankenphp.Name, Tag: "baikal", Digest: other, Line: 9}},
			wantErr: verify.ErrManyRefs,
			wantMsg: []string{"line 8", "line 9"},
		},
		{
			name:    "an-unlisted-divbast-image",
			refs:    []verify.Ref{{Name: "ghcr.io/divbast/other", Tag: "1", Digest: digest, Line: 3}},
			wantErr: verify.ErrUnlisted,
			wantMsg: []string{"ghcr.io/divbast/other", "line 3"},
		},
		{
			// Another repository whose name starts as frankenphp's does
			name:    "a-look-alike",
			refs:    []verify.Ref{{Name: "ghcr.io/divbast/frankenphp-dev", Tag: "x", Digest: digest, Line: 3}},
			wantErr: verify.ErrUnlisted,
		},
		{
			// Pinned and outside the table: nothing to run
			name: "third-party-only",
			refs: []verify.Ref{golang},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log strings.Builder
			fake := execx.NewFake(t, tt.calls...)
			err := verify.Verify(t.Context(), fake, fake, tt.refs, &log)
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

func TestListed(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		r    verify.Ref
		want bool
	}{
		{frankenphp, true},
		{distroless, true},
		{golang, false},
		{verify.Ref{Name: "GCR.io/distroless/static-debian13"}, true},
		{verify.Ref{Name: "gcr.io/distroless-other/x"}, false},
	} {
		if got := verify.Listed(tt.r); got != tt.want {
			t.Errorf("Listed(%s) = %t, want %t", tt.r.Name, got, tt.want)
		}
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("log gone") }

func TestVerifyUnwritableLog(t *testing.T) {
	t.Parallel()

	fake := execx.NewFake(t, ghVersion("2.103.3"), attest(0, ""))
	err := verify.Verify(t.Context(), fake, fake, []verify.Ref{frankenphp}, failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "log gone") {
		t.Fatalf("Verify() error = %v, want the failed write", err)
	}
}
