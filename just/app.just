# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

# Build, test and scan recipes every divbast app repository shares, beside
# common.just, which it needs: an app imports both from its checkout of
# divbast/ci, and defines what these recipes act on.
#
#   set shell := ["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]
#
#   ENGINE := env_var_or_default("ENGINE", "docker")
#   IMAGE := "localhost/librespeed:dev"
#   ARCHIVE := env_var_or_default("ARCHIVE", "/tmp/librespeed-image.tar")
#   PUBLISHED := env_var_or_default("PUBLISHED", "ghcr.io/divbast/librespeed:latest")
#
#   import? '.ci/just/common.just'
#   import? '.ci/just/app.just'
#
# ENGINE is docker or podman. IMAGE is the local tag the build writes and
# the acceptance suite runs. ARCHIVE is where archive writes the image and
# scan reads it, and PUBLISHED is the image scan compares it with. As with
# common.just, the app runs these from a recipe's body, never as a
# dependency.

# What scan unpacks the archive into, and writes beside it
LAYOUT := ARCHIVE + ".layout"
REPORT := ARCHIVE + ".report.json"
SARIF := ARCHIVE + ".sarif"
BASELINE := ARCHIVE + ".published.json"

# Build the image. CI first verifies the FrankenPHP binary's attestation; this does not
build:
    {{ ENGINE }} build -t {{ IMAGE }} -f Containerfile .

# Run the acceptance suite against the image
acceptance:
    ENGINE={{ ENGINE }} IMAGE={{ IMAGE }} go test -count=1 -timeout 90m ./test/acceptance/...

# Build the image, then run the acceptance suite against it
test: build acceptance

# Write the image to ARCHIVE as an OCI archive
archive:
    {{ ENGINE }} image save {{ if ENGINE == "podman" { "--format oci-archive " } else { "" } }}-o {{ ARCHIVE }} {{ IMAGE }}

# Fail on a HIGH or CRITICAL vulnerability the published image does not have
scan: ci-tools
    rm -rf {{ LAYOUT }} && mkdir {{ LAYOUT }} && tar xf {{ ARCHIVE }} -C {{ LAYOUT }}
    {{ ci_dir }}/bin/divbast-scan -layout {{ LAYOUT }} -report {{ REPORT }} -published {{ PUBLISHED }} \
        -baseline {{ BASELINE }} -sarif {{ SARIF }}

# hadolint and BuildKit's own checks over the Containerfile
app-lint:
    hadolint Containerfile
    docker build --check -f Containerfile .
