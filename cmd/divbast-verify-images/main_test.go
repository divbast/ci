// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/verify"
)

const (
	digest = "sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
	other  = "sha256:4dcdd53971ba1f373c3eb90e393dd3944687938c5c03494ab684921594905fc7"
	pinned = "ghcr.io/divbast/frankenphp:librespeed@" + digest
	static = "gcr.io/distroless/static-debian13:nonroot@" + other
	golang = "golang:1.27.4-trixie@" + other
	dhiRef = "dhi.io/aspnetcore:10.0.15-debian13@" + digest
	ffmpeg = "ghcr.io/divbast/ffmpeg:bazarr@" + digest
	denied = "\nError: the provided token was denied access to the requested resource\n"
)

var (
	version = execx.Call{
		Argv:   []string{"gh", "--version"},
		Result: execx.Result{Stdout: []byte("gh version 2.103.3 (2026-10-21)\n")},
	}
	attestArgv = []string{
		"gh", "attestation", "verify", "oci://ghcr.io/divbast/frankenphp@" + digest,
		"--repo", "divbast/frankenphp",
		"--signer-workflow", "divbast/frankenphp/.github/workflows/build.yml@refs/heads/main",
		"--source-ref", "refs/heads/main",
	}
	nativeArgv = func(pkg, digest string) []string {
		return []string{
			"gh", "attestation", "verify", "oci://ghcr.io/divbast/" + pkg + "@" + digest,
			"--repo", "divbast/native-tools",
			"--signer-workflow", "divbast/native-tools/.github/workflows/build.yml@refs/heads/main",
			"--source-ref", "refs/heads/main",
		}
	}
	// dhiArgv names the key in the temporary directory as {DIR}/dhi-2.pub:
	// the directory is only known once run has made it.
	dhiArgv = []string{
		"cosign", "verify", "--key", "{DIR}/dhi-2.pub", "--experimental-oci11", dhiRef,
	}
	cosignArgv = []string{
		"cosign", "verify", "gcr.io/distroless/static-debian13@" + other,
		"--certificate-identity", "keyless@distroless.iam.gserviceaccount.com",
		"--certificate-oidc-issuer", "https://accounts.google.com",
	}
)

// tools hands run a Fake that replays calls, for gh and cosign alike, and
// records what run asked it for. {DIR} in a call's argv stands for the
// directory DOCKER_CONFIG names.
type tools struct {
	t     *testing.T
	calls []execx.Call

	asked bool
	env   []string
	// dir is the directory DOCKER_CONFIG named, and files what it held, by
	// name, when the tools first ran, or when run asked for them if they
	// never did.
	dir   string
	files map[string][]byte
}

func (g *tools) runner(env []string) execx.Runner {
	g.asked, g.env = true, env
	if len(env) == 1 {
		if dir, ok := strings.CutPrefix(env[0], "DOCKER_CONFIG="); ok {
			g.dir = dir
		}
	}
	g.snapshot()
	calls := slices.Clone(g.calls)
	for i := range calls {
		calls[i].Argv = slices.Clone(calls[i].Argv)
		for j, arg := range calls[i].Argv {
			calls[i].Argv[j] = strings.ReplaceAll(arg, "{DIR}", g.dir)
		}
	}
	return &snapshotter{g: g, Runner: execx.NewFake(g.t, calls...)}
}

// snapshot records what DOCKER_CONFIG's directory holds now.
func (g *tools) snapshot() {
	g.files = map[string][]byte{}
	entries, err := os.ReadDir(g.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		g.files[e.Name()], _ = os.ReadFile(filepath.Join(g.dir, e.Name()))
	}
}

// snapshotter notes what the directory holds as each command runs.
type snapshotter struct {
	g *tools
	execx.Runner
}

func (s *snapshotter) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	s.g.snapshot()
	return s.Runner.Run(ctx, name, args...)
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
		// wantTools is whether run must ask for gh and cosign at all.
		wantTools bool
		// env is the environment run sees.
		env map[string]string
		// wantDHI is whether the directory must hold dhi.io's login and
		// key while the tools run, and nothing else.
		wantDHI bool
	}{
		{
			name:          "frankenphp-attested",
			containerfile: "FROM scratch\nCOPY --from=" + pinned + " --chmod=0755 /frankenphp /usr/local/bin/frankenphp\n",
			calls:         []execx.Call{version, {Argv: attestArgv}},
			wantStdout:    "verified: " + pinned + "\n",
			wantTools:     true,
		},
		{
			name:          "native-tools-attested",
			containerfile: "FROM scratch\nCOPY --from=" + ffmpeg + " /ffmpeg /usr/local/bin/ffmpeg\n",
			calls:         []execx.Call{version, {Argv: nativeArgv("ffmpeg", digest)}},
			wantStdout:    "verified: " + ffmpeg + "\n",
			wantTools:     true,
		},
		{
			name: "native-tools-each-package",
			containerfile: "FROM scratch\n" +
				"COPY --from=ghcr.io/divbast/unrar:v7@" + digest + " /unrar /usr/local/bin/unrar\n" +
				"COPY --from=ghcr.io/divbast/ffmpeg:bazarr@" + other + " /ffmpeg /usr/local/bin/ffmpeg\n" +
				"COPY --from=ghcr.io/divbast/mediainfo:v25@" + digest + " /mediainfo /usr/local/bin/mediainfo\n",
			calls: []execx.Call{
				version,
				{Argv: nativeArgv("unrar", digest)},
				version,
				{Argv: nativeArgv("ffmpeg", other)},
				version,
				{Argv: nativeArgv("mediainfo", digest)},
			},
			wantStdout: "verified: ghcr.io/divbast/unrar:v7@" + digest + "\n" +
				"verified: ghcr.io/divbast/ffmpeg:bazarr@" + other + "\n" +
				"verified: ghcr.io/divbast/mediainfo:v25@" + digest + "\n",
			wantTools: true,
		},
		{
			name: "native-tools-same-digest-once",
			containerfile: "FROM scratch\n" +
				"COPY --from=" + ffmpeg + " /ffmpeg /usr/local/bin/ffmpeg\n" +
				"COPY --from=" + ffmpeg + " /ffprobe /usr/local/bin/ffprobe\n",
			calls:      []execx.Call{version, {Argv: nativeArgv("ffmpeg", digest)}},
			wantStdout: "verified: " + ffmpeg + "\n",
			wantTools:  true,
		},
		{
			name:          "divbast-unknown-refused",
			containerfile: "FROM scratch\nCOPY --from=ghcr.io/divbast/sevenzip:x@" + digest + " /7z /usr/local/bin/7z\n",
			wantCode:      1,
			wantStderr:    []string{"not in the table of verified images", "ghcr.io/divbast/sevenzip:x@" + digest},
			wantTools:     true,
		},
		{
			name:          "a-go-image",
			containerfile: "FROM " + golang + " AS build\nFROM " + static + "\nCOPY --from=build /out/app /usr/local/bin/app\n",
			calls:         []execx.Call{{Argv: cosignArgv}},
			wantStdout:    "pinned: " + golang + "\nverified: " + static + "\n",
			wantTools:     true,
		},
		{
			name:          "third-party-only",
			containerfile: "FROM " + golang + "\n",
			wantStdout:    "pinned: " + golang + "\n",
			wantTools:     true,
		},
		{
			name:          "not-attested",
			containerfile: "FROM scratch\nCOPY --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp\n",
			calls:         []execx.Call{version, {Argv: attestArgv, Result: execx.Result{Code: 1, Stderr: []byte(denied)}}},
			wantCode:      1,
			wantStderr:    []string{"denied access", "did not verify", pinned},
			wantTools:     true,
		},
		{
			name:          "not-signed",
			containerfile: "FROM " + static + "\n",
			calls:         []execx.Call{{Argv: cosignArgv, Result: execx.Result{Code: 10, Stderr: []byte("Error: no signatures found\n")}}},
			wantCode:      1,
			wantStderr:    []string{"no signatures found", "did not verify", static},
			wantTools:     true,
		},
		{
			name:          "old-gh",
			containerfile: "FROM scratch\nCOPY --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp\n",
			calls: []execx.Call{{
				Argv:   []string{"gh", "--version"},
				Result: execx.Result{Stdout: []byte("gh version 2.101.0 (2026-09-01)\n")},
			}},
			wantCode:   1,
			wantStderr: []string{"older than 2.102.0", "2.101.0"},
			wantTools:  true,
		},
		{
			name:          "dhi-signed",
			containerfile: "FROM " + dhiRef + "\n",
			calls:         []execx.Call{{Argv: dhiArgv}},
			env:           map[string]string{"DHI_USERNAME": "ada", "DHI_TOKEN": "s3cret"},
			wantStdout:    "verified: " + dhiRef + "\n",
			wantTools:     true,
			wantDHI:       true,
		},
		{
			name:          "dhi-not-signed",
			containerfile: "FROM " + dhiRef + "\n",
			calls:         []execx.Call{{Argv: dhiArgv, Result: execx.Result{Code: 10, Stderr: []byte("Error: no signatures found\n")}}},
			env:           map[string]string{"DHI_USERNAME": "ada", "DHI_TOKEN": "s3cret"},
			wantCode:      1,
			wantStderr:    []string{"no signatures found", "Docker signed it with dhi-2.pub", dhiRef},
			wantTools:     true,
			wantDHI:       true,
		},
		{
			name:          "dhi-and-distroless",
			containerfile: "FROM " + dhiRef + " AS build\nFROM " + static + "\n",
			calls:         []execx.Call{{Argv: dhiArgv}, {Argv: cosignArgv}},
			env:           map[string]string{"DHI_USERNAME": "ada", "DHI_TOKEN": "s3cret"},
			wantStdout:    "verified: " + dhiRef + "\nverified: " + static + "\n",
			wantTools:     true,
			wantDHI:       true,
		},
		{
			name:          "dhi-without-a-login",
			containerfile: "FROM " + dhiRef + "\n",
			wantCode:      1,
			wantStderr:    []string{verify.ErrNoDHILogin.Error()},
		},
		{
			name:          "dhi-without-a-token",
			containerfile: "FROM " + dhiRef + "\n",
			env:           map[string]string{"DHI_USERNAME": "ada"},
			wantCode:      1,
			wantStderr:    []string{verify.ErrNoDHILogin.Error()},
		},
		{
			name:          "dhi-without-a-username",
			containerfile: "FROM " + dhiRef + "\n",
			env:           map[string]string{"DHI_TOKEN": "s3cret"},
			wantCode:      1,
			wantStderr:    []string{verify.ErrNoDHILogin.Error()},
		},
		{
			// No dhi.io image, no login needed, and none written
			name:          "login-set-but-not-needed",
			containerfile: "FROM " + golang + "\n",
			env:           map[string]string{"DHI_USERNAME": "ada", "DHI_TOKEN": "s3cret"},
			wantStdout:    "pinned: " + golang + "\n",
			wantTools:     true,
		},
		{
			name:          "unpinned",
			containerfile: "FROM debian:13-slim\n",
			wantCode:      1,
			wantStderr:    []string{"not pinned", "line 1", "debian:13-slim"},
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

			g := &tools{t: t, calls: tt.calls}
			var stdout, stderr bytes.Buffer
			getenv := func(key string) string { return tt.env[key] }
			code := run(t.Context(), args, getenv, g.runner, &stdout, &stderr)

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

			if g.asked != tt.wantTools {
				t.Fatalf("run(%q) asked for the tools: %t, want %t", args, g.asked, tt.wantTools)
			}
			if !tt.wantTools {
				return
			}
			// The tools get DOCKER_CONFIG and nothing else, naming a
			// directory that was empty when they ran and is gone once run
			// returns.
			if g.dir == "" || len(g.env) != 1 {
				t.Fatalf("run(%q) gave the tools the environment %q, want only DOCKER_CONFIG", args, g.env)
			}
			if !tt.wantDHI {
				if len(g.files) != 0 {
					t.Errorf("run(%q): DOCKER_CONFIG=%s was not an empty directory when the tools ran", args, g.dir)
				}
			} else {
				auth := base64.StdEncoding.EncodeToString([]byte("ada:s3cret"))
				if got, want := string(g.files["config.json"]), `{"auths":{"dhi.io":{"auth":"`+auth+`"}}}`; got != want {
					t.Errorf("run(%q): config.json = %q when the tools ran, want %q", args, got, want)
				}
				if !bytes.Equal(g.files["dhi-2.pub"], verify.DHIPublicKey) {
					t.Errorf("run(%q): dhi-2.pub = %q when the tools ran, want DHIPublicKey", args, g.files["dhi-2.pub"])
				}
				if len(g.files) != 2 {
					t.Errorf("run(%q): DOCKER_CONFIG held %d files when the tools ran, want config.json and dhi-2.pub", args, len(g.files))
				}
			}
			if strings.Contains(stdout.String()+stderr.String(), "s3cret") {
				t.Errorf("run(%q) printed the token", args)
			}
			if _, err := os.Stat(g.dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("run(%q) left DOCKER_CONFIG=%s behind: stat error = %v", args, g.dir, err)
			}
		})
	}
}
