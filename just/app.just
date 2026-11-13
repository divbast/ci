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
# the acceptance suite runs; written as a plain value, as above, it takes
# nothing from the environment, so `just IMAGE=<image> acceptance` tests
# another image. ARCHIVE is where archive writes the image and scan reads
# it, and PUBLISHED is the image scan compares it with. As with
# common.just, the app runs these from a recipe's body, never as a
# dependency.

# What scan unpacks the archive into, and writes beside it
LAYOUT := ARCHIVE + ".layout"
REPORT := ARCHIVE + ".report.json"
SARIF := ARCHIVE + ".sarif"
BASELINE := ARCHIVE + ".published.json"

# Podman builds in Docker's format, as the harness's Build does: Podman's
# default, OCI, has no place for a HEALTHCHECK, and drops the image's.

# Build the image. CI first verifies the FrankenPHP binary's attestation; this does not
build:
    {{ ENGINE }} build {{ if ENGINE == "podman" { "--format docker " } else { "" } }}-t {{ IMAGE }} -f Containerfile .

# Run the acceptance suite against the image. go test exits 0 when every
# test skipped, so its events go through divbast-testcount, which prints
# every test's output and a count, and fails unless every package passed a
# test and none failed or skipped. It sees only what go test printed, so a
# go test killed between packages leaves a stream that passes: pipefail,
# set here whatever the caller's shell sets, keeps go test's exit status.
acceptance:
    [ -x {{ ci_dir }}/bin/divbast-testcount ] || {{ just_executable() }} ci-tools
    set -o pipefail; ENGINE={{ ENGINE }} IMAGE={{ IMAGE }} go test -json -count=1 -timeout 90m ./test/acceptance/... | {{ ci_dir }}/bin/divbast-testcount

# Build the image, then run the acceptance suite against it
test: build acceptance

# Write the image to ARCHIVE as an OCI archive
archive:
    {{ ENGINE }} image save {{ if ENGINE == "podman" { "--format oci-archive " } else { "" } }}-o {{ ARCHIVE }} {{ IMAGE }}

# An app that argues a finding unreachable does so in an OpenVEX document
# at its root, openvex.json, which scan passes to both of Trivy's scans
# when it is there. trivy refuses a --vex file that is missing, so with no
# such file there is no -vex at all.

# Fail on a HIGH or CRITICAL vulnerability the published image does not have
scan: ci-tools
    rm -rf {{ LAYOUT }} && mkdir {{ LAYOUT }} && tar xf {{ ARCHIVE }} -C {{ LAYOUT }}
    {{ ci_dir }}/bin/divbast-scan -layout {{ LAYOUT }} -report {{ REPORT }} -published {{ PUBLISHED }} \
        -baseline {{ BASELINE }} -sarif {{ SARIF }}{{ if path_exists(justfile_directory() / "openvex.json") == "true" { " -vex openvex.json" } else { "" } }}

# hadolint and BuildKit's own checks over the Containerfile
app-lint:
    hadolint Containerfile
    docker build --check -f Containerfile .
