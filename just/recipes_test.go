// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package just_test runs the shared recipes in common.just through ci's own
// justfile, which imports them as a caller's does, and reads app.just's
// through a justfile set up as an app's.
package just_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// secret stands in for the part of a token after its prefix, which no
// refusal may print.
const secret = "Secret0123456789abcdefSECRET"

// refusal is the one line the token guard prints for a GITHUB_TOKEN of the
// given kind.
func refusal(kind string) string {
	return "GITHUB_TOKEN is " + kind + "; these recipes take a fine-grained personal access token (github_pat_)" +
		" or CI's job token (ghs_): see https://github.com/divbast/ci#local-github-token"
}

// TestGitHubTokenGuard runs the guard every recipe that calls GitHub runs
// first, with each kind of GITHUB_TOKEN. It must pass a fine-grained
// personal access token or a job token in silence, and refuse anything
// else with one line naming its kind, never the token.
func TestGitHubTokenGuard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		env  []string
		kind string // empty for a token the guard accepts
	}{
		{name: "fine-grained", env: []string{"GITHUB_TOKEN=github_pat_" + secret}},
		{name: "job token", env: []string{"GITHUB_TOKEN=ghs_" + secret}},
		{name: "gh", env: []string{"GITHUB_TOKEN=gho_" + secret}, kind: "a gh/OAuth token (gho_)"},
		{name: "classic", env: []string{"GITHUB_TOKEN=ghp_" + secret}, kind: "a classic personal access token (ghp_)"},
		{name: "app user", env: []string{"GITHUB_TOKEN=ghu_" + secret}, kind: "a GitHub App user token (ghu_)"},
		{name: "refresh", env: []string{"GITHUB_TOKEN=ghr_" + secret}, kind: "a GitHub App refresh token (ghr_)"},
		{name: "unknown", env: []string{"GITHUB_TOKEN=" + secret}, kind: "not a GitHub token of any known kind"},
		{name: "prefix without its underscore", env: []string{"GITHUB_TOKEN=ghs" + secret}, kind: "not a GitHub token of any known kind"},
		{name: "empty", env: []string{"GITHUB_TOKEN="}, kind: "unset or empty"},
		{name: "unset", kind: "unset or empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, code := just(t, "_github-token", tt.env)
			if tt.kind == "" {
				if code != 0 || out != "" {
					t.Errorf("exit %d, printed %q; want 0 and nothing", code, out)
				}
				return
			}
			if code == 0 {
				t.Errorf("exit 0, want a refusal\n%s", out)
			}
			if want := refusal(tt.kind); !strings.HasPrefix(out, want+"\n") {
				t.Errorf("printed\n%s\nwant first the line %q", out, want)
			}
			if strings.Contains(out, secret) {
				t.Errorf("printed the token:\n%s", out)
			}
		})
	}
}

// TestGitHubRecipesRefuseWithoutAGuardedToken runs each recipe that calls
// GitHub with GITHUB_TOKEN unset, empty, and gh's own token, while GH_TOKEN
// is set and a gh on PATH would hand out a token. Each must refuse, say
// where to read about the token, and never run gh.
func TestGitHubRecipesRefuseWithoutAGuardedToken(t *testing.T) {
	t.Parallel()
	for _, recipe := range []string{"actions-check", "actions-pin", "actions-update", "workflow-audit"} {
		for _, token := range []struct {
			name, kind string
			env        []string
		}{
			{name: "unset", kind: "unset or empty"},
			{name: "empty", kind: "unset or empty", env: []string{"GITHUB_TOKEN="}},
			{name: "gh", kind: "a gh/OAuth token (gho_)", env: []string{"GITHUB_TOKEN=gho_" + secret}},
		} {
			t.Run(recipe+"/"+token.name, func(t *testing.T) {
				t.Parallel()
				out, code := just(t, recipe, token.env)
				if code == 0 {
					t.Errorf("just %s: exit 0, want a refusal\n%s", recipe, out)
				}
				if want := refusal(token.kind); !strings.Contains(out, want+"\n") {
					t.Errorf("just %s printed\n%s\nwant the line %q", recipe, out, want)
				}
				if strings.Contains(out, "gh ran") {
					t.Errorf("just %s ran gh:\n%s", recipe, out)
				}
			})
		}
	}
}

// TestAcceptancePipesThroughTestcount reads the commands app.just's
// acceptance recipe would run, in a justfile set up as an app's, without
// running them. go test exits 0 when every test skipped, so the recipe must
// pipe go test -json into divbast-testcount, which fails such a run, as
// the pipeline's last command; and since a shared recipe is run from a
// recipe's body, never named as a dependency, it builds ci's tools from its
// own body when .ci/bin lacks that one.
func TestAcceptancePipesThroughTestcount(t *testing.T) {
	t.Parallel()
	ci, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(t.TempDir(), "justfile")
	body := `set shell := ["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]

ENGINE := "docker"
IMAGE := "localhost/app:dev"
ARCHIVE := "/tmp/app-image.tar"
PUBLISHED := "ghcr.io/divbast/app:latest"

import '` + filepath.Join(ci, "just", "common.just") + `'
import '` + filepath.Join(ci, "just", "app.just") + `'
`
	if err = os.WriteFile(app, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// G204 objects to a subprocess whose arguments are variables. They are
	// this test's own: the justfile it wrote and a recipe it names.
	cmd := exec.CommandContext(t.Context(), "just", "--justfile", app, "--dry-run", "acceptance") //nolint:gosec // G204: the arguments are this test's own
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("just --dry-run acceptance: %v\n%s", err, out)
	}
	commands := strings.Split(strings.TrimSpace(string(out)), "\n")

	build := regexp.MustCompile(`^\[ -x \.ci/bin/divbast-testcount \] \|\| \S*just ci-tools$`)
	pipe := "ENGINE=docker IMAGE=localhost/app:dev go test -json -count=1 -timeout 90m ./test/acceptance/... | .ci/bin/divbast-testcount"
	if len(commands) != 2 || !build.MatchString(commands[0]) || commands[1] != pipe {
		t.Errorf("acceptance runs\n%s\nwant a line matching\n%s\nthen\n%s", out, build, pipe)
	}
}

// just runs `just recipe` against ci's justfile, with GITHUB_TOKEN and
// GH_TOKEN taken out of the environment and then env added, GH_TOKEN set,
// and first on PATH a gh that says it ran and hands out a token. It returns
// what just printed, stdout and stderr together, and its exit code.
func just(t *testing.T, recipe string, env []string) (out string, code int) {
	t.Helper()
	justfile, err := filepath.Abs(filepath.Join("..", "justfile"))
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	gh := "#!/bin/sh\necho 'gh ran' >&2\necho gho_from_gh\n"
	if err = os.WriteFile(filepath.Join(bin, "gh"), []byte(gh), 0o700); err != nil { //nolint:gosec // G306: the stub must be executable, and only by its owner
		t.Fatal(err)
	}
	base := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "GH_TOKEN=gh_token_from_env"}
	for _, kv := range os.Environ() {
		switch name, _, _ := strings.Cut(kv, "="); name {
		case "PATH", "GITHUB_TOKEN", "GH_TOKEN":
		default:
			base = append(base, kv)
		}
	}

	// G204 objects to a subprocess whose arguments are variables. They are
	// this test's own: the justfile beside it and a recipe it names.
	cmd := exec.CommandContext(t.Context(), "just", "--justfile", justfile, recipe) //nolint:gosec // G204: the arguments are this test's own constants
	cmd.Env = slices.Concat(base, env)
	b, err := cmd.CombinedOutput()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return string(b), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("just %s: %v\n%s", recipe, err, b)
	}
	return string(b), 0
}
