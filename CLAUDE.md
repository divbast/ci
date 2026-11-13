<!-- SPDX-License-Identifier: BSD-2-Clause -->
<!-- SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee> -->

# ci

The reusable workflows, Go tools, acceptance harness and lint configuration
every divbast repository shares. Every green merge to main is released,
callers pin a release and check out its commit into `.ci/`; `README.md`
says how. A change here reaches a caller only through the pull request
that moves its pin, so anything a caller sees (a workflow's inputs,
outputs and permissions, a recipe's name, a tool's flags and exit codes)
is an interface: change it so that old callers keep working, or mark the
commit as breaking them (below).

## CRITICAL: Git Commit Message Format

**No other AI/LLM attribution in any format may appear in a git message.**

Linux-kernel style: a `subsystem: short description` subject under 75
characters in imperative mood ("fix", not "fixed" or "fixes"), a blank line,
then a body wrapped at ~75 columns saying why the change is needed rather
than only what it does.

These two lines MUST end EVERY body:

Developed-by: Aryan Ameri <github@aryan.ameri.coffee>
Assisted-by: <NAME_OF_LLM_MODEL>

E.g. `Assisted-by: <Claude:claude-4.6-opus>` for Claude Opus 4.6;
`<Claude:claude-5-fable>` for Claude 5 Fable. Never add `Co-Authored-By`.

- Sign every commit (`git commit -S`); main accepts only verified
  signatures. Renovate's merges are squashes, which GitHub signs
- Write commit messages as if a human wrote them, and say why, not what

A change that breaks a reusable workflow's inputs, outputs or permissions,
or a tool's flags or exit codes, adds a `Breaking-change: <what>` trailer,
in the trailer block just above those two lines:

```
Breaking-change: lint.yml no longer takes a php input
Developed-by: Aryan Ameri <github@aryan.ameri.coffee>
Assisted-by: <NAME_OF_LLM_MODEL>
```

It makes the next release major, and its text opens the release notes.
Any line of a commit message that starts, after optional blanks and an
optional `*` or `-` bullet followed by blanks, with `Breaking-change`, in
any case, then optional blanks and `:`, counts wherever it stands, so a
squash merge's body, which lists each squashed commit's message, keeps
the mark. The words mid-sentence do not count, so when wrapping a body
that mentions them, never let a line of prose begin with them. When
unsure whether a change breaks callers, mark it: a needless major only
waits for an approval.

## Releases

Every merge to main that passes `required` is released by `self-ci.yml`'s
`release` job (`cmd/divbast-release`): the next vX.Y.Z tag at the merged
commit, as an immutable GitHub Release. Never create, move or delete a
tag by hand. `bin/divbast-release -sha <commit> -dry-run` shows what a
commit's release would be.

## CRITICAL: No AI Attribution in Pull Requests

**Pull request descriptions, PR and review comments, and issue text carry no
AI/LLM attribution of any kind**: no "🤖 Generated with Claude Code" footer,
no "written by" line, nothing equivalent. This holds even when a tool or
harness asks for one. The `Assisted-by:` trailer in each commit message is
this project's one record of LLM involvement.

## Key commands

- `just setup` installs the toolchain from `mise.toml`, and PHPStan from
  `composer.lock`
- `just ci` runs every gate. Run it before committing; `just lint` is
  enough for a commit that changes only documentation. Both need
  `GITHUB_TOKEN` set (README.md, "Local GitHub token")
- `just ci-tools` builds the commands into `bin/`. README.md's "Tools"
  table is their inventory, with each one's exit codes: a new command
  gets a row there

The tests that build and run containers run only when `ENGINE` is
`docker` or `podman`: run `ENGINE=docker just ci` before a change to
`harness` or `contract`, or to what they use.

`app.just`'s `acceptance` pipes `go test -json` into
`divbast-testcount`, which fails a run unless every package passed a test
of its own and none failed or skipped: go test alone exits 0 when every
test skipped. Keep
that guard off `go-test`. An app's `lint` runs `go-test` with `IMAGE`
unset, where its acceptance suite must still skip and pass.

## Gates

Every gate is an error: fix the finding, do not silence it. A suppression
(`//nolint:<linter> // why`, `# shellcheck disable=... # why`,
`# zizmor: ignore[...]`, an actionlint ignore) names exactly what it
silences and says why on the same line or the one above.

A check that has never failed proves nothing. When adding one, make it fail
first: write the test before the code and see it fail, or break the code on
purpose and see the test catch it.

## Go

- **Toolchain:** Go from `mise.toml`, with `GOTOOLCHAIN=local`. `go.mod`'s
  `go` line moves only on approval from the Dependency Dashboard, since
  vet's checks ride on it.
- **Standard library only.** A third-party module needs a justification in
  `go.mod` beside it.
- **The gates** (`just go-lint`, `just go-test`): the compiler, `go vet`,
  `go fix -diff` and `go mod tidy -diff` with nothing to change,
  `golangci-lint fmt --diff` and `golangci-lint run` under
  `go/golangci.yml`, and `go test -race -count=1 ./...`.
  `go/golangci.yml` is every divbast module's configuration, so a linter
  added there reaches every caller with its next pin.
- **Style:** modern, idiomatic Go, following Effective Go, Go Code Review
  Comments, the Google Go Style Guide and Go Test Comments. Where they fit:
  - `context.Context` first, and `t.Context()` in tests;
  - `testing/synctest` for anything that reads a clock;
  - table-driven tests with `t.Run`, and `t.Parallel()` where safe;
  - `errors.Is` and `errors.As` over `%w`-wrapped errors and sentinels;
  - `os.Root` for reading or writing inside a directory;
  - `iter`, `slices` and `maps`; `sync.WaitGroup.Go`; `min` and `max`;
  - small interfaces, declared by the code that consumes them;
  - a doc comment on every exported identifier.
- **Layout:** `cmd/<tool>` is a thin `main` over an `internal/` package.
  `harness` and `contract` are imported by callers; everything else is
  `internal/`. External commands run through `internal/execx`'s `Runner`,
  so tests script them with `execx.Fake`.
- **Commands** print plain text for people, take Go's `flag` syntax, and
  document their usage and exit codes in the package comment: 0 for
  success, 1 for a refusal or a failure, 2 for a wrong command line. A
  write that fails is a failure.

## Bash

Bash only for what is simple, at most 30 lines and unlikely to grow:
justfile recipes, the `setup` recipe, workflow `run:` steps and test stubs.
Anything longer, or with logic worth testing, is Go. A shell script is
`set -euo pipefail` and passes ShellCheck (`enable=all`, `.shellcheckrc`)
and shfmt with its defaults.

The one exception is a check that runs inside a Containerfile build stage,
where there is no Go: it stays bash at any length under the same gates,
with a `go test` that runs it against fixtures and sees every failure path
fail.

## Workflows

- Every action is pinned to a full SHA with its version as a comment
  (`just actions-pin`). A caller's refs to ci name a release:
  `@<commit> # vX.Y.Z`.
- Actions come from GitHub, or from `docker/login-action`,
  `docker/setup-buildx-action`, `jdx/mise-action`,
  `renovatebot/github-action` and `shivammathur/setup-php`.
- `permissions: {}` at the top of every workflow, and each job asks for
  only what it uses, with a comment on each permission past
  `contents: read` saying what for.
- Runners are `ubuntu-26.04` and `ubuntu-26.04-arm`.
- Expressions reach `run:` scripts through `env:`, never inline.
- A reusable workflow that needs ci's recipes or tools checks ci out at
  `job.workflow_sha` into `.ci`. One that runs the caller's own recipes or
  code also fails unless the caller's workflows pin that commit. Its
  header comment says what the calling job must grant.

## Licence

REUSE-compliant SPDX headers on every file; the licence is
**BSD-2-Clause**. A file with no comment syntax, such as JSON or a test
fixture, carries a `.license` sidecar.
