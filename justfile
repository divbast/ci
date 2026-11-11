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

# Install the pinned toolchain
setup:
    #!/usr/bin/env bash
    # Not through the mise exec shell: this is what installs what it runs
    set -euo pipefail
    mise install

lint: go-lint reuse-lint

test: go-test

# Every gate. Run before committing
ci: lint test
