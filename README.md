<!-- SPDX-License-Identifier: BSD-2-Clause -->
<!-- SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee> -->

# ci

The reusable workflows, Go tools, acceptance harness and lint
configuration that every divbast repository shares. A repository calls
ci's workflows at one release, and checks ci out at that release's commit
into a git-ignored `.ci/`. Its local `just` recipes and its CI then run
the same code, and a ci change reaches it only through a pull request that
moves the pin.

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
fails its CI. `divbast-pin` reads ci's name in any case, as GitHub does,
so `DivBast/CI/...@<other>` counts as a second pin, and it reads a `uses:`
in YAML's flow style, `{uses: ...}`, as well.

### `just setup`

The repository's `setup` recipe checks ci out at the pinned commit, by
object rather than by tarball, and then installs the toolchain. These are
the recipes, as each repository carries them:

```just
# Fetch divbast/ci at the commit the workflows pin, then install the toolchain
setup: ci-checkout
    #!/usr/bin/env bash
    # Not through the mise exec shell: this is what installs what it runs
    set -euo pipefail
    mise install

# Fetch divbast/ci at the commit the workflows pin, into .ci, and nothing else
ci-checkout:
    #!/usr/bin/env bash
    # Not through the mise exec shell, which would first install what is missing
    set -euo pipefail
    # The one commit the workflows call divbast/ci at, spelt in any case
    uses="^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[\"']?divbast/ci/[^@[:space:]\"']+@[^[:space:]\"'#]+"
    sha=$(grep -hoiE "${uses}" .github/workflows/*.y*ml | sed 's/.*@//' | sort -u | paste -sd ' ' - || true)
    if [[ ! "${sha}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "ci-checkout: the workflows must call divbast/ci at one full commit SHA, not at: ${sha:-none}" >&2
        exit 1
    elif [[ "$(git -C .ci rev-parse HEAD 2>/dev/null || true)" == "${sha}" ]]; then
        echo "ci-checkout: .ci is already at ${sha}"
        exit 0
    fi
    changed=$([[ ! -e .ci/.git ]] || git -C .ci status --porcelain)
    if [[ -n "${changed}" ]]; then
        printf 'ci-checkout: moving .ci to %s would carry its own changes across, or stop on them; save or discard them first:\n%s\n' "${sha}" "${changed}" >&2
        exit 1
    fi
    git init -q .ci
    git -C .ci fetch -q --depth 1 https://github.com/divbast/ci "${sha}"
    git -C .ci checkout -q FETCH_HEAD && rm -rf .ci/bin
```

`ci-checkout` refuses workflows that call ci at more than one ref, or at
anything but a full commit, and names every ref it found. It reads ci's
name in any case, as GitHub does, so `DivBast/CI/...@<other>` beside
`divbast/ci/...@<commit>` is two refs. It reads block-style `uses:` lines
only, the form Renovate writes; `ci-fresh` and CI's pin check read flow
style as well. It does nothing to `.ci` when `.ci` is already at the
pinned commit, which is how it finds a checkout that one of ci's
workflows made, so that CI runs the workflow's own commit of the recipes.
It refuses to move a `.ci` that holds changes of its own, edited or
untracked files, and names each: a checkout would carry them across to
the new commit, or stop halfway on one. The tools `ci-tools` builds into
`.ci/bin` are not changes, since ci's own `.gitignore` leaves them out,
and for that reason a checkout leaves them in place too. So once `.ci`
has moved, `ci-checkout` deletes `.ci/bin`, and each shared recipe that
runs a tool builds it again, from the new commit.

`setup` runs `ci-checkout`, then `mise install`. A repository that needs
more, such as `composer install`, adds it after `mise install`.
`ci-checkout` on its own fetches `.ci` and installs nothing.

`.ci/` goes in `.gitignore`, and in `.dockerignore` in a repository that
builds an image.

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
    {{ just_executable() }} ci-fresh actions-check workflow-audit actionlint shell-lint go-lint go-test reuse-lint app-lint
```

That is an app's `lint`. A repository runs `go-lint` and `go-test` only
when it has Go code, and `app-lint` only when it builds an image; one with
neither runs the rest, as in
[A repository that builds no image](#a-repository-that-builds-no-image).
Every repository's `lint` runs `ci-fresh` first.

The imports are optional and the shared recipes are run from a recipe's
body, never named as dependencies (`lint: actions-check`). just resolves
dependencies when it reads the justfile, so until `setup` has fetched
`.ci`, a dependency on a shared recipe would stop every recipe running,
`setup` included.

`ci-fresh` fails when `.ci` does not hold the commit the workflows pin. A
`git pull` that moves the pin leaves `.ci` where it was until `just setup`
moves it, and every shared recipe would go on running the old commit's
recipes, tools and configuration. It runs `divbast-pin -expect` with the
commit `.ci` holds, so a failure names both commits, and builds
`.ci/bin/divbast-pin` first when it is missing. It says that `just setup`
moves `.ci` only when the workflows pin one commit, since `ci-checkout`
refuses workflows that pin several or none. In CI it passes, since each
workflow checks `.ci` out at the commit it checks the pin against. Inside
ci, its own checkout, it checks nothing.

`common.just` holds what every repository runs:

| Recipe | What it does |
|---|---|
| `ci-tools` | Builds ci's tools into `.ci/bin/` |
| `ci-fresh` | Fails unless `.ci` holds the commit the workflows pin |
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

`ENGINE`, `ARCHIVE` and `PUBLISHED` take a value from the environment, so
`ENGINE=podman just test` works. `IMAGE` here is a plain value, which the
environment cannot change. To run the acceptance suite against another
image, set it on just's command line:

```sh
just IMAGE=ghcr.io/divbast/librespeed:latest acceptance
```

`IMAGE=... just acceptance` would quietly test the local image.

| Recipe | What it does |
|---|---|
| `build` | `ENGINE build -t IMAGE -f Containerfile .`, with `--format docker` under Podman, whose default, OCI, drops the HEALTHCHECK |
| `acceptance` | `go test -json ./test/acceptance/...` against `IMAGE` under `ENGINE`, through `divbast-testcount` |
| `test` | `build`, then `acceptance` |
| `archive` | Writes `IMAGE` to `ARCHIVE` as an OCI archive |
| `scan` | `divbast-scan` over `ARCHIVE`, against `PUBLISHED` |
| `app-lint` | hadolint, and BuildKit's own `docker build --check`, over the Containerfile |

`go test` exits 0 when every test skipped, and prints only `ok`, so an
acceptance suite that never ran reads in a log as one that passed.
`acceptance` therefore pipes go test's events into
[`divbast-testcount`](#tools), which prints each test's output, as
`go test -v` would, then a count:

```
divbast-testcount: 109 passed, 0 skipped, 0 failed in 1 package(s)
```

It fails the recipe unless every package built and passed with at least
one test of its own passing, and no test failed or skipped, and names on
stderr each test and package that broke the rule. A package that passes
having run no test, such as one whose `TestMain` returns before `m.Run`
when `IMAGE` is unset, fails it too.

The tool sees only what go test printed, so a go test killed between
packages leaves a stream that passes. The recipe therefore sets `pipefail`
itself, whatever the caller's shell sets, and go test's own exit status
still fails it. It builds `.ci/bin/divbast-testcount` with `ci-tools`
first when it is missing. `go-test` stays a plain `go test`, so an
acceptance suite that skips when `IMAGE` is unset still passes in a `lint`
that runs it.

The tools these recipes call come from the repository's `mise.toml`:
pinact, zizmor, actionlint, ShellCheck, shfmt, Go, golangci-lint, reuse and
just, and for an app hadolint and trivy as well. `ci/mise.toml` holds the
versions ci itself is tested with.

### A repository that builds no image

A repository that builds no image calls `lint.yml` for its lint, and
`stall.yml` and `renovate.yml`. This is the least it carries.

Its `mise.toml` lists, at the versions in `ci/mise.toml`:

- Go, as `"core:go"`, with `GOTOOLCHAIN = "local"` under `[env]`. It needs
  Go even with no Go code of its own: `lint.yml`'s pin check builds ci's
  tools with the repository's Go, and so does `ci-fresh` locally.
  `GOTOOLCHAIN=local` keeps that the pinned Go, rather than one that ci's
  `go.mod` would have Go download.
- just, pinact, zizmor, actionlint and reuse, which `lint` runs.
- ShellCheck and shfmt. `shell-lint` does nothing while the repository
  tracks no `*.sh`, and checks any added later; ShellCheck also gives
  actionlint its pass over `run:` scripts.

Its `.gitignore` holds `.ci/`. Its justfile is the shell, the import of
`common.just`, `setup` and `ci-checkout` as above, and:

```just
# Every lint gate
lint:
    {{ just_executable() }} ci-fresh actions-check workflow-audit actionlint shell-lint reuse-lint

# Every gate. Run before committing
ci: lint
```

Never `go-lint` or `go-test` without Go code: both fail in a repository
that has no Go package. A gate of the repository's own, such as a config
validator, is a recipe and a job of its own beside these, and `required`
needs that job too.

Its CI workflow calls `lint.yml`, and its `required` job needs the call:

```yaml
jobs:
  lint:
    name: lint
    uses: divbast/ci/.github/workflows/lint.yml@<commit> # vX.Y.Z
    permissions:
      contents: read

  required:
    name: required
    needs: [lint]
    if: always()
    # ... fails unless every needed job succeeded
```

Its stall workflow, on a daily schedule, leaves out `slots`, since the
repository publishes nothing. Its calling job still grants everything
`stall.yml`'s job asks for: a called job that asks for more than its
caller grants fails, even for a check the caller leaves out.

```yaml
jobs:
  stall:
    name: stall
    uses: divbast/ci/.github/workflows/stall.yml@<commit> # vX.Y.Z
    with:
      checks: '["open","stuck","renovate"]'
    permissions:
      contents: read
      pull-requests: read
      actions: read
      checks: read
      statuses: read
      packages: read
```

`renovate.yml` is called as [below](#renovateyml).

### Local GitHub token

The shared recipes in `common.just` that call GitHub, pinact's
`actions-check`, `actions-pin` and `actions-update` and zizmor's
`workflow-audit`, read `GITHUB_TOKEN`, and take only a fine-grained
personal access token (`github_pat_`) or the job token CI passes
(`ghs_`). Without a token, or with any other kind, gh's own (`gho_`) or a
classic one (`ghp_`) among them, they refuse with one line that names the
kind, never the token. An app built through `app.just` needs no token at
all.

The recipes can tell a token's kind, not what it may reach, so that is
yours to choose: a fine-grained personal access token with Repository
access set to Public repositories, and no permissions beyond the default
metadata read. It reads only what anyone can read anonymously, so a leak
costs at most your API rate limit, and an expiry of up to a year is
reasonable. GitHub allows up to 366 days or none, emails before the token
expires, and its "Regenerate token" keeps the token's settings.

Keep it in a password manager or the OS keychain, and pass it per command:

```sh
GITHUB_TOKEN="$(<your password manager's get command>)" just lint
```

Do not export it from a shell profile or a `mise.toml`'s `[env]`: gh
prefers `GITHUB_TOKEN` over its own stored login (`gh help environment`),
so your own gh commands would start using the read-only token.

CI passes the job's own token.

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

The harness labels every container, image, network and volume it makes
`divbast.harness=<module>`, the path of the main module of the test
binary running it. A repository's acceptance suite is a test of its own
module, so `Engine.Sweep` in one repository's suite removes what a dead
run of that suite left behind, and nothing another repository's suite
on the same host made.

Before that, every suite labelled what it made `divbast.harness=1`.
Suites on this version no longer remove anything carrying that label.
An interrupted run under an older pin can leave containers and networks
behind on a developer's machine, holding the host ports and subnets a
suite fixes, and then the first run after the pin moves fails on a
conflict. Remove them once, with the engine that made them, after
stopping any suite still on an older pin, since this removes what a
running one made too:

```sh
docker ps -aq --filter label=divbast.harness=1 | xargs -r docker rm -f -v
docker image ls -q --filter label=divbast.harness=1 | sort -u | xargs -r docker image rm -f
docker network ls -q --filter label=divbast.harness=1 | xargs -r docker network rm
docker volume ls -q --filter label=divbast.harness=1 | xargs -r docker volume rm
```

```sh
podman ps -aq --filter label=divbast.harness=1 | xargs -r podman rm -f -v
podman image ls -q --filter label=divbast.harness=1 | sort -u | xargs -r podman image rm -f
podman network ls -q --filter label=divbast.harness=1 | xargs -r podman network rm
podman volume ls -q --filter label=divbast.harness=1 | xargs -r podman volume rm
```

Containers go first, since an image, network or volume one still uses
cannot. CI runners start empty, and need none of this.

### ci's tools in `.ci/bin`

`just ci-tools` builds every command under `cmd/` into `.ci/bin/`. A
repository runs them from its own root, as `.ci/bin/<tool>`, so the paths
they are given are its own. Go builds them as ci's own module: it maps no
`./.ci/...` path into the calling repository's module, so `go run
./.ci/cmd/<tool>` does not work. In CI, `lint.yml`, `app-check.yml` and
`app-publish.yml` build them in their pin check, before any step that
needs one. `stall.yml` builds them with ci's own Go and checks no pin,
since it reads nothing of the calling repository's but GitHub's API and
the registry. `renovate.yml` builds none.

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
  line of its message that starts, after optional blanks and an optional
  `*` or `-` bullet followed by blanks, with `Breaking-change`, in any
  case, then optional blanks and `:`. So such a line anywhere in a squash
  merge's body counts, and so does one on a merge commit. The words
  mid-sentence do not.
- [What breaks a caller](#what-breaks-a-caller) says which changes those
  are.

Every pull request previews the release its merge would make:
`self-ci.yml`'s `release-preview` job, which `required` needs, dry-runs
`divbast-release` on GitHub's test merge of the pull request into main
and writes the version, minor or major, and its notes to the run's
summary.

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

### What breaks a caller

A ci change reaches a caller through the pull request that moves its pin,
where a minor release merges by itself once the caller's checks pass. A
change breaks callers when one that has changed nothing would stop working
with it, or fail those checks. Each of these does, and its commit carries
the mark, above, that makes the next release major:

- **Reusable workflows:** an input, output or secret changed or taken
  away, or a new one required; a permission added to what the calling job
  must grant; or more asked of the calling repository: a recipe the
  workflow runs (`setup`, `lint`, `acceptance`, `scan`), a variable it
  evaluates (`IMAGE`), a tool it installs by name from the caller's
  `mise.toml`, a file it reads, or the `required` check that `stall.yml`
  waits for.
- **Tools:** a flag or exit code a caller relies on: a flag taken away or
  changed, or another exit code for a command line a caller runs.
  Refusing a command line that no caller runs, such as an empty
  `divbast-pin -expect`, breaks no one.
- **Recipes:** a recipe in `common.just` or `app.just` renamed or taken
  away, or one that needs more of the caller than before: a tool its
  `mise.toml` lacks, or a variable an app must define beyond the `ENGINE`,
  `IMAGE`, `ARCHIVE` and `PUBLISHED` that `app.just` needs today.
- **Names:** a recipe or variable added to `common.just` or `app.just`
  under a name a caller's justfile already uses. just refuses a recipe or
  a variable defined twice unless the justfile sets
  `allow-duplicate-recipes` or `allow-duplicate-variables`. So a caller
  defines none of the recipes in the tables above, nor `common.just`'s
  private `_github-token`, and none of the variables `ci_dir`, `LAYOUT`,
  `REPORT`, `SARIF` and `BASELINE`. In turn, neither file ever defines
  what callers define themselves: the recipes `default`, `setup`,
  `ci-checkout`, `lint` and `ci`, and an app's `ENGINE`, `IMAGE`,
  `ARCHIVE` and `PUBLISHED`. Any other new name is checked against every
  caller's justfile first: frankenphp's, for one, defines `test` and
  `build-app`.
- **Go:** the exported API of `harness` and `contract`, the two packages
  callers import through `.ci`, or what they do wherever an unchanged
  caller would see it: a new contract check that an image which passed
  before now fails, say, or a harness default a caller's suite relies on.
- **The probe:** more asked of an image than the probe asks today. It
  runs as the image's own PHP, `/usr/local/bin/frankenphp php-cli`, and
  needs the `posix` extension, with which `no-shell` tells a path that is
  absent from one it may not look up. An image without it fails
  `no-shell`.
- **Shared configuration:** `go/golangci.yml` or `.github/actionlint.yaml`
  changed so that a caller's unchanged code or workflows fail.

When unsure whether a change breaks callers, mark it: a major release only
waits for approval on each caller's Dependency Dashboard.

## Workflows

The caller grants each called job its permissions. A called job gets no
more than its caller grants, so each workflow below lists what the calling
job must grant, and each sets `permissions: {}` at its top.

### `lint.yml`

The lint job for repositories that build no image. It checks ci out at its
own commit, checks the pin, then runs the caller's `just setup` and
`just lint`. What the calling repository carries for it is in
[A repository that builds no image](#a-repository-that-builds-no-image).

| Input | Type | Default | What |
|---|---|---|---|
| `php` | boolean | `false` | Install PHP 8.5 and Composer, for a lint that runs PHPStan |

The calling job grants `contents: read`.

### `app-check.yml`

Lint, build, test and scan for an app repository, on every event its build
workflow runs on:

- `lint` repeats `lint.yml`'s steps. Only its pin check's skip differs:
  it names divbast/ci, which never calls `app-check.yml`, so an app's pin
  is always checked.
- `build` verifies the FrankenPHP binary's attestation
  ([below](#the-frankenphp-binary)), then builds the image for amd64 and
  arm64 with BuildKit's provenance and SBOM, as an OCI archive. A pull
  request or push reuses the build cache. The daily slot and a manual run,
  the two that publish, never restore it, and build on the builder that
  `docker/setup-buildx-action` has just made for the job, so every stage
  builds from scratch. Each image is uploaded as the artifact
  `image-<arch>`.
- `test` loads each image into Docker and into rootless Podman and runs
  `just acceptance` against it, on both architectures.
- `scan` runs `just scan` over each image, and on main uploads its
  findings to code scanning.

| Input | Type | Default | What |
|---|---|---|---|
| `php` | boolean | `true` | Install PHP 8.5 and Composer for the lint job, which runs PHPStan |
| `no-cache-filters` | string | `''` | No effect. The daily slot and a manual run already build every stage from scratch, so the stages named here change nothing. A caller that passes it keeps working |

The calling job grants `contents: read`, `attestations: read` and
`security-events: write`.

`scan`, which can change code scanning alerts, installs only Go, just and
Trivy from the caller's `mise.toml`, and turns mise's auto-install off. The
caller declares each at one version: Go as `"core:go"` (mise reads the
short `go` the same way), and just and Trivy as exactly
`"aqua:casey/just"` and `"aqua:aquasecurity/trivy"`. mise would install a
name that `mise.toml` does not declare at its latest version, so `scan`
fails unless all three are there.

### `app-publish.yml`

Publishes what `app-check.yml` built. The caller calls it from the daily
slot and the manual run on main, once its `required` job has passed, and
it fails on any other event or ref, so a merge never publishes. It decides
with `divbast-published-revision` and `divbast-publish-decision`: it
publishes when main has moved since the commit `:latest` was built from,
or when run by hand, and never replaces `:latest` with an image of an
older commit. When it publishes, it:

1. pushes each architecture as `<image>:<version>-<arch>`;
2. merges them into one index, annotated with the version, the commit, the
   commit's time and the description, and tags it
   `<image>:<version>-staging` alone;
3. attests the index, and pushes the attestation to the registry;
4. verifies that attestation as a user would, with `gh attestation verify`
   for the calling repository, this workflow and `refs/heads/main`, against
   the index's bytes, fetched by digest and checked against it, trying three
   times, ten seconds apart;
5. only then tags the index `<image>:<version>` and `<image>:latest`, once
   a dry run of that `imagetools create` shows it would push the index
   attested, byte for byte;
6. checks that both tags, as an anonymous client pulls them, are that
   index, and fails if they are not: a private package fails here. A
   rehearsal, below, checks with the job's login instead.

The staging tag is where the index waits while it is attested and
verified. Like each architecture's tag, it sits in the package as any tag
does, but it is not for pulling, and the next publish overwrites it.
Neither `<image>:<version>` nor `<image>:latest` ever names an index whose
attestation has not verified. When a step after the decision fails before
those two move, the job says so in an error: the public tags
`:<version>` and `:latest` did not move. Re-running the failed job then
publishes, since the decision still reads the last index published, but
only within a day of the build: it downloads the images `app-check.yml`
built, whose artifacts are kept for a day. A newer image published in the
meantime keeps `:latest`, and once the artifacts are gone the next daily
slot or a manual run publishes.

Publishes queue one at a time in the calling repository's `publish`
concurrency group, so the calling job needs no group of its own.

| Input | Type | What |
|---|---|---|
| `image` | string, required | The image, without a tag, such as `ghcr.io/divbast/librespeed` |
| `version-arg` | string, required | The Containerfile `ARG` whose value is the app's version, which tags the image |
| `description` | string, required | The index's description annotation, which GHCR shows on the package page |
| `rehearse` | boolean, default `false` | Decide against `image` as ever, then publish into a registry started inside the job instead: [Rehearsal](#rehearsal) |

The calling job grants `contents: read`, `packages: write`,
`id-token: write` and `attestations: write`.

Of the caller's `mise.toml` it installs Go alone, declared there as
`"core:go"` (mise reads the short `go` the same way), and turns mise's
auto-install off: the job can push the image and sign its attestation, so
it runs no other tool's install code.

An app's build workflow puts the two together, and keeps its own triggers
and its `required` job, the one check its ruleset requires:

```yaml
jobs:
  check:
    name: check
    uses: divbast/ci/.github/workflows/app-check.yml@<commit> # vX.Y.Z
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

#### Rehearsal

With `rehearse: true`, the job still runs only from the daily slot or the
manual run on main, and still decides against `image` on ghcr.io. When it
publishes, it starts the `registry` image inside the job, on
`127.0.0.1:5000`, pinned by version and digest, which the org's Renovate
preset moves. The registry asks for a throwaway login, which the job
writes and gives Docker: actions/attest pushes only to a registry whose
first answer is a challenge for one. The job runs every step after the
decision there, under `localhost:5000/<path of image>`: it pushes,
stages, attests, verifies, promotes and checks both tags. The attestation
is real: signed for the calling repository like any other, and pushed to
that registry. The registry takes no anonymous pulls, so the last check
reads the tags with the job's login. Nothing reaches ghcr.io, and no
package is made. Each rehearsal says so in a warning and on the run's summary:
`rehearsal: nothing was published to ghcr.io`.

`divbast/oci-image-template` rehearses, since it has no package. A
repository made from it inherits `rehearse: true`, and anywhere but the
template the line goes on to say how to publish: `to publish, set image
to this app's own and remove rehearse from the job that calls
app-publish.yml`. That is the switch, in the calling job's `with:`: set
`image` to the app's own `ghcr.io/divbast/<app>`, and remove
`rehearse: true`.

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

| Secret | Required | What |
|---|---|---|
| `RENOVATE_APP_PRIVATE_KEY` | yes | The App's private key |

The called job reads the caller's `renovate` environment, but an
environment secret is not handed to a called workflow on its own: the
caller must pass it explicitly, or it arrives as an empty string. A caller
passes it by name:

```yaml
jobs:
  renovate:
    uses: divbast/ci/.github/workflows/renovate.yml@<commit> # vX.Y.Z
    with:
      automerge: ${{ vars.AUTOMERGE == 'enabled' }}
    secrets:
      RENOVATE_APP_PRIVATE_KEY: ${{ secrets.RENOVATE_APP_PRIVATE_KEY }}
    permissions: {}
```

Do not use `secrets: inherit`: it hands the called workflow every secret
the caller can see, where one is all it needs.

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
| `content-gated` | boolean | `false` | The slot workflow publishes only when the image's content moved, so once the image is published a slot run that succeeded is never lost |

`content-gated` is for a repository whose daily slot runs
`divbast-publish-decision -content-gated`, and so can succeed while it
leaves an older commit published, because nothing in the image moved. Set,
it runs `divbast-stall slots -content-gated`, under which a successful slot
is never lost once the image is published. One that failed, was cancelled
or ended any other way still is, as is a day with none, and with nothing
published yet every slot run publishes, so one that succeeded and left
nothing published is lost too. Unset, every check runs as it always has.

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
repository and its main branch, and moves the image's version tag and
`:latest` only once that attestation verifies. To verify an image:

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
(`go doc ./cmd/<tool>`). Exit code 0 is success, 1 a refusal or a
failure, and 2 a wrong command line. Three tools also exit 2 when they
could not get far enough to answer at all: `divbast-stall` when its
environment is wrong or GitHub or the registry could not say,
`divbast-token-leak` when the archive cannot be read, holds no files, or
`GITHUB_TOKEN` is wrong, and `divbast-testcount` when stdin cannot be
read, is not go test -json's, or is empty.

| Command | What | 0 | 1 |
|---|---|---|---|
| `divbast-pin [-dir DIR] [-expect SHA]` | Prints the one commit the workflows pin ci at | One commit, and it is `SHA` when given | None, more than one, not `SHA`, or unreadable |
| `divbast-published-revision IMAGE` | Prints the commit a published image was built from | Printed, or nothing published yet | Private, or unreadable |
| `divbast-publish-decision -event E -built SHA -published SHA [-content-change TEXT] [-content-gated]` | Decides whether a run publishes | Decided, publish or skip | Refused: an event that does not publish, a `-built` or `-published` that is not a full commit SHA, a published commit not on main, a built commit that diverged, or git failed |
| `divbast-scan -layout DIR -report F -published IMAGE -baseline F -sarif F [-vex F]` | Fails on a HIGH or CRITICAL finding the published image lacks | Nothing new, or advisory because nothing is pullable | A new finding, or the scan failed |
| `divbast-token-leak ARCHIVE` | Fails when an image archive holds `GITHUB_TOKEN` | Clean | Found (2: unreadable or empty archive, or no token) |
| `go test -json ... \| divbast-testcount` | Fails a go test run in which no test ran, or one skipped; prints each test's output and a count | Every package built and passed with a test of its own passing, and no test failed or skipped | A test failed or skipped; a package failed, did not build, never finished, or ran no test that passed; or a write failed (2: stdin unreadable, not go test -json's, or empty) |
| `divbast-stall open\|stuck\|renovate\|slots`, `divbast-stall slots [-content-gated]` | Fails when updates have stopped flowing | Nothing stalled | Stalled (2: GitHub or the registry could not say) |
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

## Pinned build tools

Four tools the workflows run are not actions, so nothing pins them by
default. Each is fixed, and Renovate moves it through the org preset's
managers (`divbast/renovate-config`), which read these exact shapes:

- BuildKit: `driver-opts: image=moby/buildkit:vX.Y.Z@sha256:<digest>` on
  every `docker/setup-buildx-action` step, not the `buildx-stable-1` tag.
- The SBOM scanner: `--attest 'type=sbom,generator=docker/buildkit-syft-scanner:X.Y.Z@sha256:<digest>'`
  in `app-check.yml`, not the scanner buildx picks.
- mise: `MISE_VERSION` in each workflow's `env:`, under a
  `# renovate: datasource=github-releases depName=jdx/mise` line, and
  `version: ${{ env.MISE_VERSION }}` on every `jdx/mise-action` step.
- Renovate: `renovate-image: ghcr.io/renovatebot/renovate:X.Y.Z@sha256:<digest>`
  in `renovate.yml`. The input is `renovate-image` and not
  `renovate-version`, because the github-actions manager reads a digest
  from the first and takes the whole of the second, digest included, as the
  version. The action ignores `renovate-version` once the image has a tag.

`go test ./internal/workflows` fails when any of them floats.

## Working on ci

`just setup` installs the toolchain from `mise.toml`, and PHPStan from
`composer.lock` for the probe's PHP. `just ci` runs every gate: the lint
recipes above, PHPStan, and the tests. It needs `GITHUB_TOKEN` set (see
[Local GitHub token](#local-github-token)). The tests that build and run
containers run only when `ENGINE` is `docker` or `podman`, so
`ENGINE=docker just ci` runs them all. `self-ci.yml` runs them on amd64 and
arm64 under Docker and Podman, and calls `lint.yml` from the commit under
test. A merge to main that passes them is released.

The contract suite runs against two images. One is the published
LibreSpeed image `internal/testfixture` pins. The other is the minimal
fixture in `contract/testdata/minimal`, which the tests build from the
distroless runtime and the FrankenPHP binary the template copies: an app
with no bootstrap and no volume, and nothing in it the contract does not
need. A contract change that would fail either kind of app fails here
first. The mutants under `contract/testdata/mutants` each break one thing
in one of the two, and exactly the records for that one thing must fail.
Renovate's dockerfile manager moves the digests every one of those
Containerfiles pins, and `just lint` runs hadolint over them, and PHPStan
over the fixture's PHP. The contract package's documentation says
exactly what each check asserts.

The shell `app-publish.yml`'s publish job runs, from its gate and its
decision on, is pinned word for word in
`internal/workflows/testdata/app-publish-shell.golden.txt`, so a change to
it fails the tests with a diff until the file is rewritten on purpose:

```sh
go test ./internal/workflows -run TestPublishShellPinned -update
```

To see what the next release would be, from a clone with origin's tags:

```sh
just ci-tools && bin/divbast-release -sha "$(git rev-parse HEAD)" -dry-run
```

## Licence

BSD-2-Clause.
