# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

# Lint and test recipes every divbast repository shares. A repository
# imports this file from its checkout of divbast/ci, sets the shell itself,
# since just refuses a setting made twice, and runs these recipes from a
# recipe's body:
#
#   set shell := ["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]
#   import? '.ci/just/common.just'
#
#   lint:
#       {{ just_executable() }} actions-check workflow-audit go-lint
#
# Never as dependencies, as in `lint: actions-check`. just resolves those
# when it reads the justfile, so until setup has fetched .ci no recipe
# would run at all, setup included.
#
# The recipes need that shell: bash, and the tools from the repository's
# own mise.toml rather than whatever is on PATH.

# Where divbast/ci is checked out. ci's own justfile sets it to "." and
# wins, because just lets the importing file's definition override this one
# under `set allow-duplicate-variables`.
ci_dir := ".ci"

# Build ci's tools into bin/ inside ci's checkout. Run them from the
# repository's root as .ci/bin/<tool>, so the paths they are given are the
# repository's own. The output path is absolute because -C moves go, and
# everything it is given, into the checkout
ci-tools:
    go -C '{{ ci_dir }}' build -o '{{ clean(justfile_directory() / ci_dir / "bin") }}/' ./cmd/...

# Fail if any action is not pinned to a full SHA
actions-check:
    GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token)}" pinact run --verify --check

# Rewrite tag references to the SHA
actions-pin:
    GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token)}" pinact run

# Move every action to its latest release
actions-update:
    GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token)}" pinact run --update

# Audit the workflows for security problems
workflow-audit:
    GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token)}" zizmor --persona=auditor .github/workflows

# Check the workflows' syntax, expressions and run: scripts, under ci's
# configuration
actionlint:
    actionlint -config-file {{ ci_dir }}/.github/actionlint.yaml

# ShellCheck and shfmt over every tracked shell script
shell-lint:
    git ls-files -z '*.sh' | xargs -0 -r shellcheck
    git ls-files -z '*.sh' | xargs -0 -r shfmt -d

# Every Go gate but the tests: the compiler, vet, go fix and go mod tidy
# with nothing to change, then golangci-lint's formatters and linters under
# ci's configuration
go-lint:
    go build ./...
    go vet ./...
    go fix -diff ./...
    go mod tidy -diff
    golangci-lint fmt -c {{ ci_dir }}/go/golangci.yml --diff ./...
    golangci-lint run -c {{ ci_dir }}/go/golangci.yml ./...

go-test:
    go test -race -count=1 ./...

reuse-lint:
    reuse lint
