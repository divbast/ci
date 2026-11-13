// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package just_test runs the shared recipes in common.just through ci's own
// justfile, which imports them as a caller's does, and reads app.just's
// through a justfile set up as an app's. Each test needs just and mise on
// PATH, as `just ci` has them, and skips, saying so, where they are not.
package just_test

import (
	"errors"
	"fmt"
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

// needJustAndMise skips the test unless just and mise are both on PATH:
// just runs the recipes, and ci's justfile runs them through mise's shell.
// `just ci` runs the tests under mise, which puts both there; a bare go
// test from a shell without them would otherwise fail on every recipe.
func needJustAndMise(t *testing.T) {
	t.Helper()
	for _, program := range []string{"just", "mise"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Skipf("%s is not on PATH: run these tests through `just ci`, which runs them with ci's toolchain", program)
		}
	}
}

// TestGitHubTokenGuard runs the guard every recipe that calls GitHub runs
// first, with each kind of GITHUB_TOKEN. It must pass a fine-grained
// personal access token or a job token in silence, and refuse anything
// else with one line naming its kind, never the token.
func TestGitHubTokenGuard(t *testing.T) {
	t.Parallel()
	needJustAndMise(t)
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
	needJustAndMise(t)
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

// TestAcceptancePipesThroughTestcount checks app.just's acceptance recipe
// in a justfile set up as an app's. go test exits 0 when every test
// skipped, so the recipe must pipe go test -json into divbast-testcount,
// which fails such a run, as the pipeline's last command; and since a
// shared recipe is run from a recipe's body, never named as a dependency,
// it builds ci's tools from its own body when .ci/bin lacks that one.
//
// The tool sees only the events go test printed before it stopped. A go
// test killed between packages leaves a stream that passes, and only its
// own exit status says otherwise, so the recipe must keep that status
// under a caller's shell that sets no pipefail.
func TestAcceptancePipesThroughTestcount(t *testing.T) {
	t.Parallel()
	needJustAndMise(t)
	ci, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("commands", func(t *testing.T) {
		t.Parallel()
		app := appJustfile(t, ci, `["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]`)
		// G204 objects to a subprocess whose arguments are variables. They
		// are this test's own: the justfile it wrote and a recipe it names.
		cmd := exec.CommandContext(t.Context(), "just", "--justfile", app, "--dry-run", "acceptance") //nolint:gosec // G204: the arguments are this test's own
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("just --dry-run acceptance: %v\n%s", err, out)
		}
		commands := strings.Split(strings.TrimSpace(string(out)), "\n")

		build := regexp.MustCompile(`^\[ -x \.ci/bin/divbast-testcount \] \|\| \S*just ci-tools$`)
		pipe := "set -o pipefail; ENGINE=docker IMAGE=localhost/app:dev go test -json -count=1 -timeout 90m ./test/acceptance/... | .ci/bin/divbast-testcount"
		if len(commands) != 2 || !build.MatchString(commands[0]) || commands[1] != pipe {
			t.Errorf("acceptance runs\n%s\nwant a line matching\n%s\nthen\n%s", out, build, pipe)
		}
	})

	// The real tool, which passes the stream the stub go prints below
	tool := filepath.Join(t.TempDir(), "divbast-testcount")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", tool, "./cmd/divbast-testcount") //nolint:gosec // G204: the arguments are this test's own
	build.Dir = ci
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, tt := range []struct {
		name, shell string
	}{
		{name: "pipefail shell", shell: `["bash", "-euo", "pipefail", "-c"]`},
		{name: "plain bash", shell: `["bash", "-c"]`},
	} {
		for _, goExit := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/go test exits %d", tt.name, goExit), func(t *testing.T) {
				t.Parallel()
				app := appJustfile(t, ci, tt.shell)
				dir := filepath.Dir(app)
				if err := os.MkdirAll(filepath.Join(dir, ".ci", "bin"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tool, filepath.Join(dir, ".ci", "bin", "divbast-testcount")); err != nil {
					t.Fatal(err)
				}
				// A go that prints a stream divbast-testcount passes, then
				// exits as the case says
				stub := t.TempDir()
				goScript := "#!/bin/sh\ncat <<'EOF'\n" +
					`{"Action":"start","Package":"example.com/app/test/acceptance"}` + "\n" +
					`{"Action":"run","Package":"example.com/app/test/acceptance","Test":"TestServes"}` + "\n" +
					`{"Action":"pass","Package":"example.com/app/test/acceptance","Test":"TestServes"}` + "\n" +
					`{"Action":"pass","Package":"example.com/app/test/acceptance"}` + "\n" +
					"EOF\n" + fmt.Sprintf("exit %d\n", goExit)
				if err := os.WriteFile(filepath.Join(stub, "go"), []byte(goScript), 0o700); err != nil { //nolint:gosec // G306: the stub must be executable, and only by its owner
					t.Fatal(err)
				}

				cmd := exec.CommandContext(t.Context(), "just", "--justfile", app, "acceptance") //nolint:gosec // G204: the arguments are this test's own
				cmd.Env = append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"))
				out, err := cmd.CombinedOutput()
				if !strings.Contains(string(out), "divbast-testcount: 1 passed, 0 skipped, 0 failed in 1 package(s)\n") {
					t.Errorf("divbast-testcount did not pass the stream:\n%s", out)
				}
				switch _, failed := errors.AsType[*exec.ExitError](err); {
				case err != nil && !failed:
					t.Fatalf("just acceptance: %v\n%s", err, out)
				case goExit == 0 && failed:
					t.Errorf("just acceptance failed though go test passed:\n%s", out)
				case goExit != 0 && !failed:
					t.Errorf("just acceptance passed though go test exited %d:\n%s", goExit, out)
				}
			})
		}
	}
}

// TestBuildFormat checks app.just's build under each engine. Podman builds
// in OCI's format by default, which has no place for a HEALTHCHECK and
// drops the image's, so the image a local `ENGINE=podman just test` built
// would fail the contract's healthcheck-config check however right its
// Containerfile was. Docker has only its own format.
func TestBuildFormat(t *testing.T) {
	t.Parallel()
	needJustAndMise(t)
	ci, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	app := appJustfile(t, ci, `["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]`)
	for _, tt := range []struct{ engine, want string }{
		{engine: "docker", want: "docker build -t localhost/app:dev -f Containerfile ."},
		{engine: "podman", want: "podman build --format docker -t localhost/app:dev -f Containerfile ."},
	} {
		t.Run(tt.engine, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), "just", "--justfile", app, "--dry-run", "ENGINE="+tt.engine, "build") //nolint:gosec // G204: the arguments are this test's own
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("just --dry-run ENGINE=%s build: %v\n%s", tt.engine, err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tt.want {
				t.Errorf("ENGINE=%s just build runs\n%s\nwant\n%s", tt.engine, got, tt.want)
			}
		})
	}
}

// TestCIFresh runs common.just's ci-fresh in a repository set up as a
// caller's, whose workflows pin one commit while .ci holds another, as
// after a git pull that moved the pin without a `just setup`, or the same
// one. It must fail naming both commits and saying that just setup moves
// .ci, or pass. Workflows that pin more than one commit, or none, must
// fail it too, without that hint, since setup refuses them as well. A
// shared recipe is run from a recipe's body, never named as a dependency,
// so it builds divbast-pin from its own body when .ci/bin lacks it, and
// only then. In ci itself, its own checkout, there is no pin to check.
func TestCIFresh(t *testing.T) {
	t.Parallel()
	needJustAndMise(t)
	ci, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "divbast-pin")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", tool, "./cmd/divbast-pin") //nolint:gosec // G204: the arguments are this test's own
	build.Dir = ci
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	// A commit no fixture's .ci holds
	const other = "3d3c42e5aac5ba805825da76410c181273ba90b1"

	// What the fixture's workflows pin, against the commit .ci holds
	const (
		fresh = "fresh" // that commit
		stale = "stale" // another one
		mixed = "mixed" // that commit and another
		none  = "none"  // no commit at all
	)
	for _, tt := range []struct {
		name, pins string
		built      bool
		want       string // what the output must say, beside the commits
	}{
		{name: "stale", pins: stale, built: true},
		{name: "fresh", pins: fresh, built: true},
		{name: "stale, divbast-pin not built", pins: stale},
		{name: "fresh, divbast-pin not built", pins: fresh},
		{name: "mixed", pins: mixed, built: true, want: "workflows pin more than one divbast/ci commit"},
		{name: "none", pins: none, built: true, want: "no workflow pins divbast/ci to a commit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			git(t, dir, "init", "--quiet", ".ci")
			git(t, filepath.Join(dir, ".ci"), "commit", "--quiet", "--allow-empty", "--message", "ci")
			have := git(t, filepath.Join(dir, ".ci"), "rev-parse", "HEAD")
			calls := func(sha string) string {
				return "jobs:\n  lint:\n    uses: divbast/ci/.github/workflows/lint.yml@" + sha + " # v1.0.0\n"
			}
			workflows := filepath.Join(dir, ".github", "workflows")
			if err := os.MkdirAll(workflows, 0o700); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				filepath.Join(dir, "justfile"): `set shell := ["bash", "-euo", "pipefail", "-c"]

import '` + filepath.Join(ci, "just", "common.just") + `'
`,
			}
			pinned := have
			switch tt.pins {
			case fresh:
				files[filepath.Join(workflows, "build.yml")] = calls(have)
			case stale:
				pinned = other
				files[filepath.Join(workflows, "build.yml")] = calls(other)
			case mixed:
				files[filepath.Join(workflows, "build.yml")] = calls(have)
				files[filepath.Join(workflows, "stall.yml")] = calls(other)
			case none:
				files[filepath.Join(workflows, "build.yml")] = "jobs:\n  lint:\n    uses: ./.github/workflows/lint.yml\n"
			}
			for name, body := range files {
				if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.built {
				if err := os.MkdirAll(filepath.Join(dir, ".ci", "bin"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tool, filepath.Join(dir, ".ci", "bin", "divbast-pin")); err != nil {
					t.Fatal(err)
				}
			}
			// A go that notes it ran and builds divbast-pin by copying the
			// real one into the directory -o names
			stub := t.TempDir()
			goScript := "#!/bin/sh\necho \"go $*\" >>'" + filepath.Join(stub, "ran") + "'\n" +
				"while [ $# -gt 0 ]; do\n  if [ \"$1\" = -o ]; then out=$2; fi\n  shift\ndone\n" +
				"mkdir -p \"${out}\" && cp '" + tool + "' \"${out}divbast-pin\"\n"
			if err := os.WriteFile(filepath.Join(stub, "go"), []byte(goScript), 0o700); err != nil { //nolint:gosec // G306: the stub must be executable, and only by its owner
				t.Fatal(err)
			}

			cmd := exec.CommandContext(t.Context(), "just", "--justfile", filepath.Join(dir, "justfile"), "ci-fresh") //nolint:gosec // G204: the arguments are this test's own
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			_, failed := errors.AsType[*exec.ExitError](err)
			if err != nil && !failed {
				t.Fatalf("just ci-fresh: %v\n%s", err, out)
			}
			hint := strings.Contains(string(out), "just setup")
			switch {
			case tt.pins == fresh && failed:
				t.Errorf("just ci-fresh failed, though the workflows pin %s, which .ci holds:\n%s", have, out)
			case tt.pins == fresh:
			case !failed:
				t.Errorf("just ci-fresh passed, though the workflows pin %s and .ci holds %s:\n%s", tt.pins, have, out)
			case tt.pins == stale && (!strings.Contains(string(out), pinned) || !strings.Contains(string(out), have)):
				t.Errorf("just ci-fresh failed without naming both %s, the pin, and %s, .ci's:\n%s", pinned, have, out)
			case tt.pins == stale && !hint:
				t.Errorf("just ci-fresh failed without saying `just setup` moves .ci:\n%s", out)
			case tt.pins != stale && hint:
				t.Errorf("just ci-fresh says `just setup` would help, which refuses workflows that pin %s:\n%s", tt.pins, out)
			case !strings.Contains(string(out), tt.want):
				t.Errorf("just ci-fresh failed without saying %q:\n%s", tt.want, out)
			}
			root, err := os.OpenRoot(stub)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			ran, err := root.ReadFile("ran")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if got := len(ran) > 0; got != !tt.built {
				t.Errorf("built divbast-pin: %t, want %t\ngo ran: %s\n%s", got, !tt.built, ran, out)
			}
		})
	}

	t.Run("in ci", func(t *testing.T) {
		t.Parallel()
		out, code := just(t, "ci-fresh", nil)
		if code != 0 || !strings.Contains(out, "ci-fresh: ci is its own checkout") {
			t.Errorf("just ci-fresh in ci: exit %d, printed\n%s\nwant 0, and a line saying there is nothing to check", code, out)
		}
	})
}

// git runs a git command in dir that must succeed, as no one's in
// particular and unsigned, and returns its stdout.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{
		"-C", dir, "-c", "user.name=divbast test", "-c", "user.email=test@divbast.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
	}, args...)
	out, err := exec.CommandContext(t.Context(), "git", argv...).Output() //nolint:gosec // G204: the arguments are this test's own
	if err != nil {
		t.Fatalf("git %q: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// appJustfile writes a justfile set up as an app's, with shell as its
// shell, into a directory of its own, and returns its path.
func appJustfile(t *testing.T, ci, shell string) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "justfile")
	body := `set shell := ` + shell + `

ENGINE := "docker"
IMAGE := "localhost/app:dev"
ARCHIVE := "/tmp/app-image.tar"
PUBLISHED := "ghcr.io/divbast/app:latest"

import '` + filepath.Join(ci, "just", "common.just") + `'
import '` + filepath.Join(ci, "just", "app.just") + `'
`
	if err := os.WriteFile(app, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return app
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
