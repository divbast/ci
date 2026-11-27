This issue lists Renovate updates and detected dependencies. Read the [Dependency Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/) docs to learn more.

## Pending Approval

The following branches are pending approval. To create them, click on a checkbox below.

 - [ ] <!-- approve-branch=renovate/go-1.x -->tools: update go module directive to v1.27.4

## Pending Status Checks

The following updates await pending status checks. To force their creation now, click on a checkbox below.

 - [ ] <!-- unpend-branch=renovate/axe-core-playwright-4.x -->tools: update dependency @axe-core/playwright to v4.14.1
 - [ ] <!-- unpend-branch=renovate/github.com-ncruces-go-sqlite3-0.x -->[tools: update module github.com/ncruces/go-sqlite3 to v0.38.1](../pull/14)
 - [ ] <!-- unpend-branch=renovate/github.com-pressly-goose-v3-3.x -->[tools: update module github.com/pressly/goose/v3 to v3.30.2](../pull/15)
 - [ ] <!-- unpend-branch=renovate/lucide-monorepo -->tools: update dependency lucide-static to v1.81.0
 - [ ] <!-- unpend-branch=renovate/stylelint-18.x -->tools: update dependency stylelint to v18.1.0
 - [ ] <!-- unpend-branch=renovate/vite-plus-monorepo -->tools: update dependency vite-plus to v1.8.0
 - [ ] <!-- unpend-branch=renovate/pnpm -->tools: update pnpm to v12.23.0

## Detected Dependencies

<details><summary>dockerfile (1)</summary>
<blockquote>

<details><summary>Containerfile (3)</summary>

 - `dhi.io/node 26.13.1-debian13-dev@sha256:efd29755a80e4753b972c58d0adeb3d45874c45d200d9ab8a17acf9dbb73620a`
 - `dhi.io/golang 1.27.4-debian13-dev@sha256:121afb8b390b1d6babba8cd0a93eaf2ffa3735f835d388b9d79c2be38b41ee4f`
 - `dhi.io/static 20250419-debian13@sha256:1295ce0b300e0972ee6034f75f2161a629c12d760526f2e029528416dec2f96e`

</details>

</blockquote>
</details>

<details><summary>github-actions (5)</summary>
<blockquote>

<details><summary>.github/workflows/browser.yml (5)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `jdx/mise-action v5.3.0@924e7c586e33d7d4bae9c14e26c5d22e2beb6e78`
 - `actions/upload-artifact v7.0.2@cf430e030ddbb5b0abf93d22962f4752f3646cd9`
 - `actions/upload-artifact v7.0.2@cf430e030ddbb5b0abf93d22962f4752f3646cd9`
 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/build.yml (2)</summary>

 - `divbast/ci v4.36.0@3f7c3d27a07a997d9bb90b912902b2869ea7989a`
 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/fuzz.yml (4)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `jdx/mise-action v5.3.0@924e7c586e33d7d4bae9c14e26c5d22e2beb6e78`
 - `actions/upload-artifact v7.0.2@cf430e030ddbb5b0abf93d22962f4752f3646cd9`
 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/renovate.yml (1)</summary>

 - `divbast/ci v4.36.0@3f7c3d27a07a997d9bb90b912902b2869ea7989a`

</details>

<details><summary>.github/workflows/stall.yml (1)</summary>

 - `divbast/ci v4.36.0@3f7c3d27a07a997d9bb90b912902b2869ea7989a`

</details>

</blockquote>
</details>

<details><summary>gomod (2)</summary>
<blockquote>

<details><summary>go.mod (20)</summary>

 - `go 1.27.0` → [Updates: `1.27.4`]
 - `go 1.27.4`
 - `github.com/a-h/templ v0.3.1118`
 - `github.com/alecthomas/kong v1.17.0`
 - `github.com/ncruces/go-sqlite3 v0.38.0` → [Updates: `v0.38.1`]
 - `github.com/pelletier/go-toml/v2 v2.4.3`
 - `github.com/pressly/goose/v3 v3.30.1` → [Updates: `v3.30.2`]
 - `github.com/prometheus/client_golang v1.25.0`
 - `go.opentelemetry.io/otel v1.47.0`
 - `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.47.0`
 - `go.opentelemetry.io/otel/exporters/prometheus v0.69.0`
 - `go.opentelemetry.io/otel/sdk v1.47.0`
 - `go.opentelemetry.io/otel/sdk/metric v1.47.0`
 - `go.opentelemetry.io/otel/trace v1.47.0`
 - `go.opentelemetry.io/proto/otlp v1.11.1`
 - `go.uber.org/goleak v1.3.0`
 - `golang.org/x/crypto v0.59.0`
 - `golang.org/x/net v0.63.0`
 - `golang.org/x/sync v0.25.0`
 - `google.golang.org/protobuf v1.36.12`

</details>

<details><summary>tools/go.mod (5)</summary>

 - `go 1.27.0` → [Updates: `1.27.4`]
 - `go 1.27.4`
 - `github.com/a-h/templ v0.3.1118`
 - `github.com/sqlc-dev/sqlc v1.31.1`
 - `golang.org/x/vuln v1.10.0`

</details>

</blockquote>
</details>

<details><summary>mise (1)</summary>
<blockquote>

<details><summary>mise.toml (16)</summary>

 - `core:go 1.27.4`
 - `aqua:golangci/golangci-lint 2.15.0`
 - `core:node 26.13.1`
 - `pnpm 12.22.0` → [Updates: `12.23.0`]
 - `aqua:betterleaks/betterleaks 1.10.1`
 - `aqua:hadolint/hadolint 2.15.1`
 - `aqua:koalaman/shellcheck 0.11.0`
 - `aqua:mvdan/sh 3.14.1`
 - `aqua:rhysd/actionlint 1.7.12`
 - `pipx:reuse 6.3.0`
 - `aqua:casey/just 1.59.0`
 - `aqua:suzuki-shunsuke/pinact 5.0.2`
 - `aqua:aquasecurity/trivy 0.76.2`
 - `aqua:anchore/grype 0.122.1`
 - `aqua:zizmorcore/zizmor 1.33.1`
 - `aqua:sigstore/cosign 3.1.6`

</details>

</blockquote>
</details>

<details><summary>npm (2)</summary>
<blockquote>

<details><summary>build/pnpm/package.json (1)</summary>

 - `pnpm 12.22.0` → [Updates: `12.23.0`]

</details>

<details><summary>package.json (10)</summary>

 - `@axe-core/playwright 4.14.0` → [Updates: `4.14.1`]
 - `@playwright/test 1.65.1`
 - `browserslist 4.29.6`
 - `happy-dom 21.0.4`
 - `lightningcss 1.33.0`
 - `lucide-static 1.76.0` → [Updates: `1.81.0`]
 - `stylelint 18.0.0` → [Updates: `18.1.0`]
 - `typescript 7.0.2`
 - `vite-plus 1.7.0` → [Updates: `1.8.0`]
 - `pnpm 12.22.0` → [Updates: `12.23.0`]

</details>

</blockquote>
</details>

<details><summary>regex (2)</summary>
<blockquote>

<details><summary>.github/workflows/browser.yml (1)</summary>

 - `jdx/mise 2026.11.14`

</details>

<details><summary>.github/workflows/fuzz.yml (1)</summary>

 - `jdx/mise 2026.11.14`

</details>

</blockquote>
</details>

<details><summary>renovate-config (1)</summary>
<blockquote>

<details><summary>renovate.json (4)</summary>

 - `golang 1.27.4`
 - `golang 1.27.4`
 - `golang 1.27.4`
 - `node 26.13.1`

</details>

</blockquote>
</details>


