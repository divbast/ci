<!-- SPDX-License-Identifier: BSD-2-Clause -->
<!-- SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee> -->

# What the reader's tests read

`pnpm-lock.yaml` was written by pnpm 12.14.0 on 2026-11-25, against the
npm registry, for this `package.json`, in an empty directory of its own:

```json
{
  "name": "divbast-scan-fixture",
  "private": true,
  "dependencies": {
    "minimist": "1.2.5",
    "my-minimist": "npm:minimist@1.2.6",
    "react": "18.3.1",
    "react-dom": "18.3.1"
  },
  "optionalDependencies": {
    "is-number": "7.0.0"
  },
  "devDependencies": {
    "debug": "2.6.9",
    "lodash": "4.17.20",
    "loose-envify": "1.4.0",
    "mkdirp": "0.5.5"
  },
  "packageManager": "pnpm@12.14.0"
}
```

```sh
pnpm install --lockfile-only --ignore-scripts --ignore-pnpmfile
```

It is unedited. pnpm 12 writes it as two documents, because
`packageManager` pins pnpm 12:

- the boot document: pnpm itself, under `packageManagerDependencies`, with
  its 14 platform binaries, 15 packages;
- the project's: 12 packages, among them an alias (`my-minimist`), a peer
  suffix (`react-dom@18.3.1(react@18.3.1)`), an optional dependency, a
  package only a devDependency reaches (`ms`, through `debug`), and two
  that a devDependency and a runtime dependency both reach (`loose-envify`,
  directly and through `react`, and `minimist@1.2.5`, through `mkdirp`).

`lodash@4.17.20`, a devDependency, and `minimist@1.2.5`, a runtime one,
each have known HIGH or CRITICAL advisories, so the same file serves
divbast-scan's tests, which `internal/scan/testdata/README.md` describes.
