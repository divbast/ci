// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

const (
	digest = "sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
	pinned = "ghcr.io/divbast/frankenphp:librespeed@" + digest
	denied = "\nError: the provided token was denied access to the requested resource\n"
)

var (
	version = execx.Call{
		Argv:   []string{"gh", "--version"},
		Result: execx.Result{Stdout: []byte("gh version 2.103.3 (2026-10-21)\n")},
	}
	verifyArgv = []string{
		"gh", "attestation", "verify", "oci://ghcr.io/divbast/frankenphp@" + digest,
		"--repo", "divbast/frankenphp",
		"--signer-workflow", "divbast/frankenphp/.github/workflows/build.yml@refs/heads/main",
		"--source-ref", "refs/heads/main",
	}
)

// gh hands run a Fake that replays calls, and records what run asked it
// for.
type gh struct {
	t     *testing.T
	calls []execx.Call

	asked bool
	env   []string
	// dir is the directory DOCKER_CONFIG named, and empty whether it held
	// nothing at the moment run asked for gh.
	dir   string
	empty bool
}

func (g *gh) runner(env []string) execx.Runner {
	g.asked, g.env = true, env
	if len(env) == 1 {
		if dir, ok := strings.CutPrefix(env[0], "DOCKER_CONFIG="); ok {
			entries, err := os.ReadDir(dir)
			g.dir, g.empty = dir, err == nil && len(entries) == 0
		}
	}
	return execx.NewFake(g.t, g.calls...)
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		containerfile string
		calls         []execx.Call
		// args, when set, replaces the -containerfile argument.
		args       []string
		wantCode   int
		wantStdout string
		// wantStderr lists what stderr must contain.
		wantStderr []string
		// wantGH is whether run must ask for gh at all.
		wantGH bool
	}{
		{
			name:          "verified",
			containerfile: "FROM scratch\nCOPY --from=" + pinned + " --chmod=0755 /frankenphp /usr/local/bin/frankenphp\n",
			calls:         []execx.Call{version, {Argv: verifyArgv}},
			wantStdout: "verifying " + pinned + "\n" +
				"verified: divbast/frankenphp's main build attested ghcr.io/divbast/frankenphp@" + digest + "\n",
			wantGH: true,
		},
		{
			name:          "not-attested",
			containerfile: "FROM scratch\nCOPY --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp\n",
			calls:         []execx.Call{version, {Argv: verifyArgv, Result: execx.Result{Code: 1, Stderr: []byte(denied)}}},
			wantCode:      1,
			wantStdout:    "verifying " + pinned + "\n",
			wantStderr:    []string{"denied access", "did not verify", pinned},
			wantGH:        true,
		},
		{
			name:          "old-gh",
			containerfile: "FROM scratch\nCOPY --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp\n",
			calls: []execx.Call{{
				Argv:   []string{"gh", "--version"},
				Result: execx.Result{Stdout: []byte("gh version 2.101.0 (2026-09-01)\n")},
			}},
			wantCode:   1,
			wantStdout: "verifying " + pinned + "\n",
			wantStderr: []string{"older than 2.102.0", "2.101.0"},
			wantGH:     true,
		},
		{
			name:          "no-ref",
			containerfile: "FROM scratch\nCOPY --from=build /frankenphp /usr/local/bin/frankenphp\n",
			wantCode:      1,
			wantStderr:    []string{"no COPY --from= takes the binary"},
		},
		{
			name:          "not-literal",
			containerfile: "FROM scratch\nCOPY --from=${FP} /frankenphp /usr/local/bin/frankenphp\n",
			wantCode:      1,
			wantStderr:    []string{"names a variable", "line 2"},
		},
		{
			name:       "missing-containerfile",
			args:       []string{"-containerfile", "absent/Containerfile"},
			wantCode:   1,
			wantStderr: []string{"absent"},
		},
		{
			name:       "stray-argument",
			args:       []string{"Containerfile"},
			wantCode:   2,
			wantStderr: []string{`unexpected argument "Containerfile"`, "Usage of " + name},
		},
		{
			name:       "unknown-flag",
			args:       []string{"-dir", "."},
			wantCode:   2,
			wantStderr: []string{"flag provided but not defined: -dir"},
		},
		{
			name:       "help",
			args:       []string{"-h"},
			wantStderr: []string{"-containerfile FILE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			args := tt.args
			if args == nil {
				path := filepath.Join(dir, "Containerfile")
				if err := os.WriteFile(path, []byte(tt.containerfile), 0o600); err != nil {
					t.Fatal(err)
				}
				args = []string{"-containerfile", path}
			} else if len(args) == 2 && args[0] == "-containerfile" {
				args = []string{"-containerfile", filepath.Join(dir, args[1])}
			}

			g := &gh{t: t, calls: tt.calls}
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, g.runner, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d; stderr:\n%s", args, code, tt.wantCode, stderr.String())
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("run(%q) stdout = %q, want %q", args, got, tt.wantStdout)
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("run(%q) stderr = %q, want it to contain %q", args, stderr.String(), s)
				}
			}

			if g.asked != tt.wantGH {
				t.Fatalf("run(%q) asked for gh: %t, want %t", args, g.asked, tt.wantGH)
			}
			if !tt.wantGH {
				return
			}
			// gh gets DOCKER_CONFIG and nothing else, naming a directory
			// that was empty when gh ran and is gone once run returns.
			if g.dir == "" || len(g.env) != 1 {
				t.Fatalf("run(%q) gave gh the environment %q, want only DOCKER_CONFIG", args, g.env)
			}
			if !g.empty {
				t.Errorf("run(%q): DOCKER_CONFIG=%s was not an empty directory when gh ran", args, g.dir)
			}
			if _, err := os.Stat(g.dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("run(%q) left DOCKER_CONFIG=%s behind: stat error = %v", args, g.dir, err)
			}
		})
	}
}
