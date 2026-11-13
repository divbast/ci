# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

set shell := ["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]
set allow-duplicate-variables

# ci is its own checkout. This definition overrides common.just's ".ci"
ci_dir := "."

import 'just/common.just'

# Tool versions live in mise.toml

default:
    @just --list

# Install the pinned toolchain, and PHPStan from composer.lock
setup:
    #!/usr/bin/env bash
    # Not through the mise exec shell: this is what installs what it runs
    set -euo pipefail
    mise install
    composer install

# Dependencies only because common.just is always here. A repository
# importing it from .ci calls these from a recipe's body instead.

# Every lint gate
lint: actions-check workflow-audit actionlint shell-lint go-lint reuse-lint containerfile-lint
    # PHP and Composer come from the host, or setup-php in CI: mise's PHP
    # backend compiles PHP from source
    vendor/bin/phpstan analyse --no-progress

# hadolint over every Containerfile here: the contract suite's fixture and
# mutants, which its tests build
containerfile-lint:
    git ls-files -z '*Containerfile' | xargs -0 -r hadolint

test: go-test

# Every gate. Run before committing
ci: lint test
