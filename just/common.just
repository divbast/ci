# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

# Lint and test recipes every divbast repository shares. A repository
# imports this file from its checkout of divbast/ci, and sets the shell
# itself, since just refuses a setting made twice:
#
#   set shell := ["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]
#   import? '.ci/just/common.just'
#
# The recipes need that shell: bash, and the tools from the repository's
# own mise.toml rather than whatever is on PATH.

# Where divbast/ci is checked out. ci's own justfile sets it to "." and
# wins, because just lets the importing file's definition override this one
# under `set allow-duplicate-variables`.
ci_dir := ".ci"

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
