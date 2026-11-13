<!-- SPDX-License-Identifier: BSD-2-Clause -->
<!-- SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee> -->

# What the scan tests read

Recorded with Trivy 0.76.2 and skopeo 1.24.1 on 2026-11-11, with
`DOCKER_CONFIG` pointing at an empty directory so that every registry saw an
anonymous client, against the vulnerability database of 2026-11-10.

## Reports

The image is LibreSpeed's published index
`ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909`,
at amd64.

`trivy-librespeed.json` is the image as the scan's first step sees it, an OCI
layout:

```sh
skopeo copy --override-os linux --override-arch amd64 \
    docker://ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909 \
    oci:layout-amd64
trivy image --input layout-amd64 --severity HIGH,CRITICAL --format json \
    --output trivy-librespeed.json
```

`trivy-librespeed-published.json` is the same image as the baseline scan reads
it, from the registry:

```sh
trivy image --image-src remote --platform linux/amd64 --skip-db-update \
    --severity HIGH,CRITICAL --format json --output trivy-librespeed-published.json \
    ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909
```

Trivy wrote each at 234 KB, most of it every package's dependency list. Both
are trimmed to the fields the parser reads, by this jq program, which keeps
Trivy's key order and leaves a key Trivy left out absent rather than null:

```jq
def keep($ks): with_entries(select(.key | IN($ks[])));
keep(["ArtifactName", "Metadata", "Results"])
| .Metadata |= (keep(["ImageConfig", "RepoDigests"]) | .ImageConfig |= keep(["architecture"]))
| .Results |= map(
    keep(["Target", "Class", "Type", "Packages", "Vulnerabilities"])
    | if has("Packages") then .Packages |= map(keep(["ID"])) else . end
    | if has("Vulnerabilities") then .Vulnerabilities |= map(keep(["VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "PrimaryURL"])) else . end)
```

Packages keep only their `ID`, since only their number is read. `scan.sh`'s
own jq gives the same package count, architecture, baseline name, listing and
summary for the trimmed reports as for the untrimmed ones.

The image has one HIGH finding and no fixed version, so
`trivy-synthetic-candidate.json` and `trivy-synthetic-published.json` are
written by hand, in the same shape, to carry what it lacks: an OS package,
a fixed version, a missing and an empty `PrimaryURL`, `|` and a newline in a
cell, one advisory in two packages, and one in the same package at another
version.

## Golden output

`listing*.golden.txt` is what `scan.sh` prints on stdout, and
`summary*.golden.md` what it appends to `$GITHUB_STEP_SUMMARY`. Neither was
written by the Go code they test. Both were rendered by `scan.sh`'s own jq
programs, copied verbatim from `librespeed-oci-image@24e63e2`, from these
reports:

| Golden | Report | Baseline | Arch | Mode |
|---|---|---|---|---|
| `listing.golden.txt`, `summary.golden.md` | `trivy-librespeed.json` | `trivy-librespeed-published.json` | amd64 | blocking |
| `listing-advisory.golden.txt`, `summary-advisory.golden.md` | `trivy-librespeed.json` | `{}` | amd64 | advisory, `ghcr.io/divbast/librespeed:latest` unpullable |
| `listing-synthetic.golden.txt`, `summary-synthetic.golden.md` | `trivy-synthetic-candidate.json` | `trivy-synthetic-published.json` | arm64 | blocking, against `ghcr.io/divbast/x@sha256:00` |

## Trivy's stderr

Each `trivy-*.txt` is Trivy's stderr, verbatim, from the baseline scan
`scan.sh` runs, with `REF` as below. Trivy exited 1 every time, and wrote no
report.

```sh
trivy image --image-src remote --platform linux/amd64 --skip-db-update \
    --severity HIGH,CRITICAL --format json --output out.json REF
```

| File | `REF` | Says |
|---|---|---|
| `trivy-no-such-tag.txt` | `ghcr.io/divbast/librespeed:no-such-tag` | `MANIFEST_UNKNOWN` |
| `trivy-no-such-package.txt` | `ghcr.io/divbast/no-such-package-t5:latest` | `DENIED` |
| `trivy-manifest-429.txt` | a local stub registry answering every manifest 429 | `TOOMANYREQUESTS` |

The scan once read the first two as an image nobody publishes. It no
longer reads Trivy's stderr at all: the registry, and GitHub, say whether
the published image is there before Trivy scans it, so the tests replay
these as what a scan that failed prints, which fails the scan whatever it
says. ghcr.io cannot be made to answer 429 on demand, hence the stub, a
Python `http.server` on 127.0.0.1 that answers `/v2/` with 200.
