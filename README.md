<!-- SPDX-License-Identifier: BSD-2-Clause -->
<!-- SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee> -->

# ci

The reusable workflows, Go tools, acceptance harness and lint
configuration that every divbast repository shares. A repository calls
ci's workflows at one release, and checks ci out at that release's commit
into a git-ignored `.ci/`. Its local `just` recipes and its CI then run
the same code, and a ci change reaches it only through a pull request that
moves the pin, which the repository's own CI tests.

- [Using ci from a repository](#using-ci-from-a-repository)
- [Releases](#releases)
- [Workflows](#workflows)
- [Attestations](#attestations)
- [Tools](#tools)
- [Shared configuration](#shared-configuration)
- [Working on ci](#working-on-ci)

## Using ci from a repository

### One pin

Every `uses:` line that names ci names the same [release](#releases) of
it: the release's full commit SHA, with its tag as the comment.

```yaml
jobs:
  lint:
    uses: divbast/ci/.github/workflows/lint.yml@<commit> # vX.Y.Z
```

Renovate moves every such line together, commit and comment, in one pull
request. `lint.yml`, `app-check.yml` and `app-publish.yml`, which run the
repository's own recipes and code, check ci out at their own commit into
`.ci` and run `divbast-pin -expect <that commit>`, so a repository whose
workflows name more than one commit, or one other than the commit running,
fails its CI.

### `just setup`

The repository's `setup` recipe checks ci out at the pinned commit, by
object rather than by tarball, and then installs the toolchain. This is
the recipe, as each repository carries it:

```just
# Fetch divbast/ci at the commit the workflows pin, then install the toolchain
setup:
    #!/usr/bin/env bash
    # Not through the mise exec shell: this is what installs what it runs
    set -euo pipefail
    # The one release commit every workflow calls divbast/ci at
    uses="^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[\"']?divbast/ci/[^@[:space:]\"']+@[^[:space:]\"'#]+"
    sha=$(grep -hoE "${uses}" .github/workflows/*.y*ml | sed 's/.*@//' | sort -u | paste -sd ' ' - || true)
    if [[ ! "${sha}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "setup: the workflows must call divbast/ci at one full commit SHA, not at: ${sha:-none}" >&2
        exit 1
    fi
    have=$(git -C .ci rev-parse HEAD 2>/dev/null || true)
    if [[ "${have}" == "${sha}" ]]; then
        echo "setup: .ci is already at ${sha}"
    else
        git init -q .ci
        git -C .ci fetch -q --depth 1 https://github.com/divbast/ci "${sha}"
        git -C .ci checkout -q FETCH_HEAD
    fi
    mise install
```

It refuses workflows that call ci at more than one ref, or at anything but
a full commit, and names every ref it found. It does nothing to `.ci` when
`.ci` is already at the pinned commit, which is how it finds a checkout
that one of ci's workflows made, so that CI runs the workflow's own commit
of the recipes. A repository that needs more, such as `composer install`,
adds it after `mise install`.

`.ci/` goes in both `.gitignore` and `.dockerignore`.

### The justfile

A repository imports ci's recipes from `.ci` and sets the shell they need:
bash, with the tools from the repository's own `mise.toml`.

```just
set shell := ["mise", "exec", "--", "bash", "-euo", "pipefail", "-c"]

import? '.ci/just/common.just'
# App repositories only, after defining ENGINE, IMAGE, ARCHIVE and PUBLISHED
import? '.ci/just/app.just'

# Every lint gate
lint:
    {{ just_executable() }} actions-check workflow-audit actionlint shell-lint go-lint reuse-lint
```

The imports are optional and the shared recipes are run from a recipe's
body, never named as dependencies (`lint: actions-check`). just resolves
dependencies when it reads the justfile, so until `setup` has fetched
`.ci`, a dependency on a shared recipe would stop every recipe running,
`setup` included.

`common.just` holds what every repository runs:

| Recipe | What it does |
|---|---|
| `ci-tools` | Builds ci's tools into `.ci/bin/` |
| `actions-check` | pinact: every action pinned to a full SHA whose version comment is right |
| `actions-pin`, `actions-update` | pinact: pin tag references, or move every action to its latest release |
| `workflow-audit` | zizmor, auditor persona, over `.github/workflows` |
| `actionlint` | actionlint, with its ShellCheck pass over `run:` scripts |
| `shell-lint` | ShellCheck and shfmt over every tracked `*.sh` |
| `go-lint` | The compiler, `go vet`, `go fix -diff`, `go mod tidy -diff`, `golangci-lint fmt --diff` and `golangci-lint run` |
| `go-test` | `go test -race -count=1 ./...` |
| `reuse-lint` | `reuse lint` |

App repositories, the ones that build an image, also import `app.just`,
and define what it acts on:

```just
ENGINE := env_var_or_default("ENGINE", "docker")
IMAGE := "localhost/librespeed:dev"
ARCHIVE := env_var_or_default("ARCHIVE", "/tmp/librespeed-image.tar")
PUBLISHED := env_var_or_default("PUBLISHED", "ghcr.io/divbast/librespeed:latest")
```

| Recipe | What it does |
|---|---|
| `build` | `ENGINE build -t IMAGE -f Containerfile .` |
| `acceptance` | `go test ./test/acceptance/...` against `IMAGE` under `ENGINE` |
| `test` | `build`, then `acceptance` |
| `archive` | Writes `IMAGE` to `ARCHIVE` as an OCI archive |
| `scan` | `divbast-scan` over `ARCHIVE`, against `PUBLISHED` |
| `app-lint` | hadolint, and BuildKit's own `docker build --check`, over the Containerfile |

The tools these recipes call come from the repository's `mise.toml`:
pinact, zizmor, actionlint, ShellCheck, shfmt, Go, golangci-lint, reuse and
just, and for an app hadolint and trivy as well. `ci/mise.toml` holds the
versions ci itself is tested with.

### Go

A repository with Go code reaches ci's packages, the `harness` and the
`contract` suite, through the checkout in `.ci`, so the workflows' pin is
still the only one:

```
require github.com/divbast/ci v0.0.0-00010101000000-000000000000

replace github.com/divbast/ci => ./.ci
```

The shared Renovate preset tells Renovate's gomod manager to leave
`github.com/divbast/ci` alone.

### ci's tools in `.ci/bin`

`just ci-tools` builds every command under `cmd/` into `.ci/bin/`. A
repository runs them from its own root, as `.ci/bin/<tool>`, so the paths
they are given are its own. Go builds them as ci's own module: it maps no
`./.ci/...` path into the calling repository's module, so `go run
./.ci/cmd/<tool>` does not work. In CI, each workflow builds them in its
pin check, before any step that needs one.

## Releases

Every green merge to ci's main is a release. Once `required` has passed
on a push to main, `self-ci.yml`'s `release` job runs `divbast-release`,
which tags the merged commit with the next version and publishes it as a
GitHub Release, immutable once published. Its notes list the subject of
every commit since the last release, leaving out merge commits. When two
merges land close together, the run for the earlier one finds main has
moved on and leaves the release to the run for the later one, which
releases both.

- The version is the last release's with its minor number raised:
  v1.4.0 follows v1.3.0. The first release is v1.0.0.
- A commit that marks a breaking change makes the next release major
  instead: v2.0.0 follows v1.3.0, and the notes open with what each mark
  says, each text once. A commit marks one with a
  `Breaking-change: <what broke>` trailer, even an empty one, or with any
  line of its message that starts with `Breaking-change:`, bulleted with
  `* ` or `- ` or not. So a `Breaking-change:` line anywhere in a squash
  merge's body counts, and so does one on a merge commit. The words
  mid-sentence do not.
- A change breaks callers when it changes a reusable workflow's inputs,
  outputs or the permissions its calling job must grant, or a tool's
  flags or exit codes.

A repository pins ci at a release, the release's commit with its tag as
the comment, and zizmor and pinact check that pair as they do any other
action's:

```yaml
uses: divbast/ci/.github/workflows/lint.yml@<commit> # vX.Y.Z
```

Renovate moves every ci ref in a repository together, commit and comment,
in one pull request. A minor release merges itself once that repository's
checks pass; a major one waits for approval on the Dependency Dashboard.

The job acts as the divbast org's `divbast-renovate` GitHub App, whose key
is in ci's `renovate` environment, which only main can deploy to: only a
merged commit is ever released.

## Workflows

The caller grants each called job its permissions. A called job gets no
more than its caller grants, so each workflow below lists what the calling
job must grant, and each sets `permissions: {}` at its top.

### `lint.yml`

The lint job for repositories that build no image. It checks ci out at its
own commit, checks the pin, then runs the caller's `just setup` and
`just lint`.

| Input | Type | Default | What |
|---|---|---|---|
| `php` | boolean | `false` | Install PHP 8.5 and Composer, for a lint that runs PHPStan |

The calling job grants `contents: read`.

### `app-check.yml`

Lint, build, test and scan for an app repository, on every event its build
workflow runs on:

- `lint` is `lint.yml`'s job, step for step.
- `build` verifies the FrankenPHP binary's attestation
  ([below](#the-frankenphp-binary)), then builds the image for amd64 and
  arm64 with BuildKit's provenance and SBOM, as an OCI archive. A pull
  request or push reuses the build cache; the daily slot and a manual run
  never restore it, and build each stage in `no-cache-filters` from
  scratch. Each image is uploaded as the artifact `image-<arch>`.
- `test` loads each image into Docker and into rootless Podman and runs
  `just acceptance` against it, on both architectures.
- `scan` runs `just scan` over each image, and on main uploads its
  findings to code scanning.

| Input | Type | Default | What |
|---|---|---|---|
| `php` | boolean | `true` | Install PHP 8.5 and Composer for the lint job, which runs PHPStan |
| `no-cache-filters` | string | `''` | Build stages, separated by spaces, that the daily slot and a manual run build without the cache: the ones that fetch from outside the repository |

The calling job grants `contents: read`, `attestations: read` and
`security-events: write`.

### `app-publish.yml`

Publishes what `app-check.yml` built. The caller calls it from the daily
slot and the manual run on main, once its `required` job has passed, and
it fails on any other event or ref, so a merge never publishes. It decides
with `divbast-published-revision` and `divbast-publish-decision`: it
publishes when main has moved since the commit `:latest` was built from,
or when run by hand, and never replaces `:latest` with an image of an
older commit. When it publishes, it:

1. pushes each architecture as `<image>:<version>-<arch>`;
2. merges them into one index, tagged `<image>:<version>` and
   `<image>:latest`, annotated with the version, the commit, the commit's
   time and the description;
3. attests the index, and pushes the attestation to the registry;
4. checks that `<image>:latest`, as an anonymous client pulls it, is that
   index, and fails if it is not: a private package fails here.

Publishes queue one at a time in the calling repository's `publish`
concurrency group, so the calling job needs no group of its own.

| Input | Type | What |
|---|---|---|
| `image` | string, required | The image, without a tag, such as `ghcr.io/divbast/librespeed` |
| `version-arg` | string, required | The Containerfile `ARG` whose value is the app's version, which tags the image |
| `description` | string, required | The index's description annotation, which GHCR shows on the package page |

The calling job grants `contents: read`, `packages: write`,
`id-token: write` and `attestations: write`.

An app's build workflow puts the two together, and keeps its own triggers
and its `required` job, the one check its ruleset requires:

```yaml
jobs:
  check:
    name: check
    uses: divbast/ci/.github/workflows/app-check.yml@<commit> # vX.Y.Z
    with:
      no-cache-filters: fetch
    permissions:
      contents: read
      attestations: read # verify the FrankenPHP binary
      security-events: write # code scanning, from main

  required:
    name: required
    needs: [check]
    if: always()
    # ... fails unless every needed job succeeded

  publish:
    name: publish
    needs: [required]
    if: >-
      github.ref == 'refs/heads/main'
      && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')
    uses: divbast/ci/.github/workflows/app-publish.yml@<commit> # vX.Y.Z
    with:
      image: ghcr.io/divbast/librespeed
      version-arg: LIBRESPEED_VERSION
      description: LibreSpeed speed test. Zero capabilities, read-only root, non-root, no shell
    permissions:
      contents: read
      packages: write # push the image and its attestation
      id-token: write # Sigstore signs against the runner's OIDC identity
      attestations: write # write the attestation
```

The checks are then named `check / lint`, `check / build (amd64, ...)`
and so on.

### `renovate.yml`

Self-hosted Renovate for the calling repository alone, as the divbast org's
`divbast-renovate` GitHub App. Renovate merges its own pull requests, with
a squash, once every check on one has passed, and only while `automerge`
is true.

| Input | Type | What |
|---|---|---|
| `automerge` | boolean, required | The kill switch: true only while the caller's automerge variable is `enabled` |

The calling job grants nothing (`permissions: {}`): Renovate works through
the App's token. The App's client ID and private key are the caller's
`renovate` environment's `RENOVATE_APP_CLIENT_ID` variable and
`RENOVATE_APP_PRIVATE_KEY` secret, which divbast/infra manages.

### `stall.yml`

The daily stall check: fails, so GitHub emails someone, when updates have
stopped flowing without anything failing loudly. One job per check, run
by `divbast-stall`.

| Input | Type | Default | What |
|---|---|---|---|
| `checks` | string | `'["open","stuck","renovate","slots"]'` | The checks to run, as a JSON array |
| `published` | string | `''` | The image the daily slot publishes, such as `ghcr.io/divbast/librespeed:latest`; `slots` needs it |
| `slot-workflow` | string | `build.yml` | The workflow whose scheduled runs on main are the daily slots |
| `renovate-workflow` | string | `renovate.yml` | The workflow that runs Renovate |
| `open-days` | number | `14` | Days a Renovate pull request may stay open |
| `stuck-hours` | number | `24` | Hours one may stay red since it opened, or pending since its last push |
| `run-hours` | number | `24` | Hours Renovate may go without a successful run |
| `lost-slots` | number | `2` | Lost daily slots that make a stall |

The calling job grants `contents: read`, `pull-requests: read`,
`actions: read`, `checks: read`, `statuses: read` and `packages: read`.

## Attestations

### The FrankenPHP binary

An app takes its FrankenPHP binary from `ghcr.io/divbast/frankenphp` with
one `COPY`, naming the image by tag and digest:

```dockerfile
COPY --from=ghcr.io/divbast/frankenphp:librespeed@sha256:<digest> --chmod=0755 /frankenphp /usr/local/bin/frankenphp
```

Before `app-check.yml` builds anything, `divbast-verify-frankenphp` finds
that line and has gh verify the digest:

```sh
gh attestation verify oci://ghcr.io/divbast/frankenphp@sha256:<digest> \
    --repo divbast/frankenphp \
    --signer-workflow divbast/frankenphp/.github/workflows/build.yml@refs/heads/main \
    --source-ref refs/heads/main
```

So only a binary that divbast/frankenphp's build workflow made from its
main branch is built into an app: not a pull request's build, and not
another repository's image. The Containerfile must name the image exactly
once, as `<tag>@sha256:<digest>`, so that Renovate can move it; a tag with
no digest, or a `--from=` built from a variable, fails the build.

A local `just build` does not verify the attestation. It builds from
whatever digest the Containerfile names. To check a Containerfile by hand,
with gh 2.102.0 or newer logged in:

```sh
just ci-tools && .ci/bin/divbast-verify-frankenphp
```

### Published images

`app-publish.yml` signs each image's attestation itself, for the app's
repository and its main branch. To verify an image:

```sh
gh attestation verify oci://ghcr.io/divbast/librespeed:latest \
    --repo divbast/librespeed-oci-image \
    --signer-workflow divbast/ci/.github/workflows/app-publish.yml \
    --source-ref refs/heads/main
```

`--repo` and `--source-ref` say the image was built from the app's main
branch, and `--signer-workflow` that ci's publish workflow signed it. It
names no `@ref`, because each app calls that workflow at whichever ci
commit it pins, and gh then accepts it at any ref.

Use gh 2.102.0 or newer. Older versions compare `--signer-workflow` with
only the start of the signer's identity, and `--source-ref` without regard
to case. When gh reports that the token was denied for a public image, it
is sending a stale registry login from Docker's configuration: run it with
`DOCKER_CONFIG` pointing at an empty directory.

## Tools

Each command is a thin `main` over an `internal/` package, prints plain
text, and documents its usage and exit codes in its package comment
(`go doc ./cmd/<tool>`). Exit code 2 always means the command line, or for
`divbast-stall` the environment, is wrong.

| Command | What | 0 | 1 |
|---|---|---|---|
| `divbast-pin [-dir DIR] [-expect SHA]` | Prints the one commit the workflows pin ci at | One commit, and it is `SHA` when given | None, more than one, not `SHA`, or unreadable |
| `divbast-published-revision IMAGE` | Prints the commit a published image was built from | Printed, or nothing published yet | Private, or unreadable |
| `divbast-publish-decision -event E -built SHA -published SHA` | Decides whether a run publishes | Decided, publish or skip | Refused: an event that does not publish, a published commit not on main, a built commit that diverged, or git failed |
| `divbast-scan -layout DIR -report F -published IMAGE -baseline F -sarif F [-vex F]` | Fails on a HIGH or CRITICAL finding the published image lacks | Nothing new, or advisory because nothing is pullable | A new finding, or the scan failed |
| `divbast-token-leak ARCHIVE` | Fails when an image archive holds `GITHUB_TOKEN` | Clean | Found (2: unreadable or empty archive, or no token) |
| `divbast-stall open\|stuck\|renovate\|slots` | Fails when updates have stopped flowing | Nothing stalled | Stalled (2: GitHub or the registry could not say) |
| `divbast-verify-frankenphp [-containerfile FILE]` | Refuses a FrankenPHP binary frankenphp's main build did not attest | Verified | Not verified, or the Containerfile names the image other than once in full |
| `divbast-release -sha SHA [-dry-run]` | Releases a commit on main as the next vX.Y.Z | Released, already released, left to a later merge's run, or the dry run printed | Refused: not a commit, not on origin's main, a release tag the clone lacks, or the version's tag taken; or git or gh failed |

## Shared configuration

Each lives here once and reaches a repository through `.ci`, so it moves
with the pin:

- `go/golangci.yml`: the one golangci-lint configuration, which `go-lint`
  passes with `-c`.
- `.github/actionlint.yaml`: the ubuntu-26.04 runner labels, and an
  ignore for each name GitHub documents that actionlint 1.7.12 does not
  know yet, scoped to that name.

## Working on ci

`just setup` installs the toolchain from `mise.toml`, and PHPStan from
`composer.lock` for the probe's PHP. `just ci` runs every gate: the lint
recipes above, PHPStan, and the tests. The tests that build and run
containers run only when `ENGINE` is `docker` or `podman`, so
`ENGINE=docker just ci` runs them all. `self-ci.yml` runs them on amd64 and
arm64 under Docker and Podman, and calls `lint.yml` from the commit under
test. A merge to main that passes them is released.

To see what the next release would be, from a clone with origin's tags:

```sh
just ci-tools && bin/divbast-release -sha "$(git rev-parse HEAD)" -dry-run
```

## Licence

BSD-2-Clause.
