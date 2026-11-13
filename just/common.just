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
#       {{ just_executable() }} ci-fresh actions-check workflow-audit go-lint
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

# Run the tools from the repository's root as .ci/bin/<tool>, so the
# paths they are given are the repository's own. The output path is
# absolute because -C moves go, and everything it is given, into the
# checkout.

# Build ci's tools into bin/ inside ci's checkout
ci-tools:
    go -C '{{ ci_dir }}' build -o '{{ clean(justfile_directory() / ci_dir / "bin") }}/' ./cmd/...

# A git pull that moves the workflows' pin leaves .ci where it was until
# `just setup` moves it, and every shared recipe would go on running the
# old commit's recipes, tools and configuration. A repository's lint runs
# this first. It builds divbast-pin from its own body when .ci/bin lacks
# it, since a shared recipe is never named as a dependency. ci, its own
# checkout, has no pin to check.

# Fail unless .ci holds the commit the workflows pin
ci-fresh:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ '{{ ci_dir }}' == . ]]; then
        echo "ci-fresh: ci is its own checkout, with no pin to check"
        exit 0
    fi
    [[ -x '{{ ci_dir }}/bin/divbast-pin' ]] || {{ just_executable() }} ci-tools
    have=$(git -C '{{ ci_dir }}' rev-parse HEAD)
    if ! '{{ ci_dir }}/bin/divbast-pin' -expect "${have}"; then
        echo "ci-fresh: {{ ci_dir }} holds ${have}, not the commit the workflows pin; just setup moves it there" >&2
        exit 1
    fi

# The four recipes below call GitHub. Each takes its token from
# GITHUB_TOKEN and nowhere else, and first runs this, which refuses one that
# is neither a fine-grained personal access token nor the job token CI
# passes, naming the token's kind and never the token. README.md's "Local
# GitHub token" says which token to give them. They name it as a
# dependency, which is safe within this file: it resolves whenever the file
# is imported, unlike a caller's dependency on a shared recipe.
_github-token:
    #!/usr/bin/env bash
    set -euo pipefail
    case "${GITHUB_TOKEN:-}" in
        github_pat_* | ghs_*) exit 0 ;;
        "") kind="unset or empty" ;;
        gho_*) kind="a gh/OAuth token (gho_)" ;;
        ghp_*) kind="a classic personal access token (ghp_)" ;;
        ghu_*) kind="a GitHub App user token (ghu_)" ;;
        ghr_*) kind="a GitHub App refresh token (ghr_)" ;;
        *) kind="not a GitHub token of any known kind" ;;
    esac
    echo "GITHUB_TOKEN is ${kind}; these recipes take a fine-grained personal access token (github_pat_) or CI's job token (ghs_): see https://github.com/divbast/ci#local-github-token" >&2
    exit 1

# Fail if any action is not pinned to a full SHA
actions-check: _github-token
    pinact run --verify --check

# Rewrite tag references to the SHA
actions-pin: _github-token
    pinact run

# Move every action to its latest release
actions-update: _github-token
    pinact run --update

# Audit the workflows for security problems
workflow-audit: _github-token
    zizmor --persona=auditor .github/workflows

# Check the workflows' syntax, expressions and run: scripts
actionlint:
    actionlint -config-file {{ ci_dir }}/.github/actionlint.yaml

# ShellCheck and shfmt over every tracked shell script
shell-lint:
    git ls-files -z '*.sh' | xargs -0 -r shellcheck
    git ls-files -z '*.sh' | xargs -0 -r shfmt -d

# The compiler, vet, go fix and go mod tidy with nothing to change, then
# golangci-lint's formatters and linters under ci's configuration.

# Every Go gate but the tests
go-lint:
    go build ./...
    go vet ./...
    go fix -diff ./...
    go mod tidy -diff
    golangci-lint fmt -c {{ ci_dir }}/go/golangci.yml --diff ./...
    golangci-lint run -c {{ ci_dir }}/go/golangci.yml ./...

# The tests, under the race detector
go-test:
    go test -race -count=1 ./...

# Licence and copyright headers on every file
reuse-lint:
    reuse lint
