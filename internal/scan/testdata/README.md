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

## Grype

Recorded with Grype 0.122.1 on 2026-11-20, offline, against its
vulnerability database built 2026-11-19 (the `from` in each report), with
a configuration as `Grype.WriteConfig` writes one: no update check, the
database's auto-update off.

The inputs are synthetic, so that each has packages with known findings:
an image of one zstd layer, written in the shape buildx's `type=oci`
export gives (an index naming an index, which names the image beside an
attestation manifest), for linux/arm64, holding:

- `/etc/os-release` saying `ID=dhi`, `ID_LIKE=debian`, `VERSION_ID=13`,
  and `/etc/debian_version`;
- `/var/lib/dpkg/status` listing `curl 8.14.1-2+deb13u2dhi2`,
  `qemu 1:10.0.11+ds-0+deb13u1+dhi0`, `brotli 1.1.0-1`,
  `coreutils 9.7-3+dhi3` and `libc6 2.41-12+dhi1`;
- `/app/node_modules/lodash/package.json` for lodash 4.17.15.

The Debian image is the same with `ID=debian`, `VERSION_ID="13"`.

```sh
grype -c grype.yaml oci-dir:dhi-layout --platform linux/arm64 \
    -o json=dhi.json -o cyclonedx-json=dhi.cdx.json -o sarif=dhi.sarif
grype -c grype.yaml oci-dir:deb-layout --platform linux/arm64 \
    -o json=deb.json -o cyclonedx-json=deb.cdx.json
grype -c grype.yaml 'pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-13' -o json
grype -c grype.yaml 'pkg:deb/dhi/brotli@1.1.0-1?arch=arm64&distro=dhi-14' -o json
grype -c grype.yaml 'pkg:deb/debian/brotli@1.1.0-1?arch=arm64&distro=debian-13' -o json
```

The last three are the database probe's three answers, as
`grype-probe-dhi-13.json`, `grype-probe-dhi-14.json` and
`grype-probe-debian-13.json`: a match from DHI's own namespace, none, and
one from Debian's.

Each JSON report is trimmed to what the parser reads, with the layout's
path replaced by `layout`, by this jq program. `grype-dhi.json` keeps 7 of
its 92 matches (`$ids`), one of each severity, a language finding keyed by
GHSA and one with no severity; `grype-debian.json` keeps its first 5 HIGH
or CRITICAL ones; the probes keep everything (`$ids` null):

```jq
def keep($ks): with_entries(select(.key | IN($ks[])));
keep(["matches", "source", "distro", "descriptor"])
| .matches |= map(
    select($ids == null or (.vulnerability.id | IN($ids[])))
    | keep(["vulnerability", "relatedVulnerabilities", "artifact"])
    | .vulnerability |= (keep(["id", "dataSource", "namespace", "severity", "fix"]) | if has("fix") then .fix |= keep(["versions", "state"]) else . end)
    | .relatedVulnerabilities |= ((. // []) | map(keep(["id"])))
    | .artifact |= (keep(["name", "version", "type", "locations", "purl"]) | .locations |= ((. // []) | map(keep(["path"])))))
| .source |= (keep(["type", "target"]) | .target |= (if type == "object" then keep(["userInput", "repoDigests", "architecture"]) | .userInput = "layout" else . end))
| .descriptor |= (keep(["name", "version", "db"]) | .db |= (.status |= keep(["schemaVersion", "from", "built"]) | .providers |= with_entries(.value |= keep(["captured"]))))
```

Each CycloneDX file keeps every component's type, name, version and PURL:

```jq
def keep($ks): with_entries(select(.key | IN($ks[])));
keep(["bomFormat", "specVersion", "metadata", "components"])
| .metadata |= (keep(["component"]) | .component |= (keep(["type", "name"]) | .name = "layout"))
| .components |= map(keep(["type", "name", "version", "purl"]))
```

`grype-dhi.sarif` keeps the results and rules of those 7 matches, without
each rule's long descriptions, and with the layout's path replaced by
`layout`.

## Grype on a lockfile

Recorded with Grype 0.122.1 on 2026-11-25, offline, against its
database of 2026-11-24 (the `from` in the report), with a
configuration as `Grype.WriteConfig` writes one.

The input is `internal/pnpmlock/testdata/pnpm-lock.yaml`, which pnpm 12
wrote, as its README says, placed where an image would ship it, under a
directory of its own, `root`, as divbast-scan writes a lockfile an image
declares:

```sh
mkdir -p root/usr/share/doc/app
cp pnpm-lock.yaml root/usr/share/doc/app/
grype -c grype.yaml dir:root \
    -o json=lock.json -o cyclonedx-json=lock.cdx.json -o sarif=lock.sarif
```

grype found 27 npm packages, both of pnpm 12's documents, and five
findings: lodash 4.17.20, a devDependency, two HIGH and two MEDIUM, and
minimist 1.2.5, a runtime dependency, one CRITICAL.

`grype-lockfile.json` is the report, trimmed by the jq program above with
`$ids` null, and with the directory's path, the source's target, replaced
by `root`. `grype-lockfile.cdx.json` keeps each component's type, name,
version and PURL, as above, and of its properties only
`syft:location:0:path`, the file grype found it in, which the scan counts
packages by:

```jq
def keep($ks): with_entries(select(.key | IN($ks[])));
keep(["bomFormat", "specVersion", "metadata", "components"])
| .metadata |= (keep(["component"]) | .component |= (keep(["type", "name"]) | .name = "root"))
| .components |= map(keep(["type", "name", "version", "purl", "properties"])
    | if has("properties") then .properties |= map(select(.name == "syft:location:0:path")) else . end)
```

`grype-lockfile.sarif` keeps every result and rule, without each rule's
long descriptions. grype names no host path in a directory scan's SARIF:
each result is at the lockfile's path in the image.

## Grype on an SBOM

Recorded with Grype 0.122.1 on 2026-11-26, offline, against its database of
2026-11-24, with a configuration as `Grype.WriteConfig` writes one.

The input is `sbom.cdx.json`, written by hand: a CycloneDX 1.6 document
naming two components an image might build or copy in, each by the
identifier an image declares it by. unrar 6.11 is named by its CPE alone,
and brotli 1.1.0-1 by the package URL Docker's own builds of it carry. Each
version is an old one with a known record. It was placed where an image
would ship it, as divbast-scan writes an SBOM an image declares:

```sh
mkdir -p root/usr/local/share/divbast
cp sbom.cdx.json root/usr/local/share/divbast/
grype -c grype.yaml sbom:root/usr/local/share/divbast/sbom.cdx.json \
    -o json=sbom.json -o cyclonedx-json=sbom.out.cdx.json -o sarif=sbom.sarif
```

grype matched unrar by its CPE, one HIGH, and brotli by its package URL,
one CRITICAL and one HIGH, from Docker's own namespace: it reads the
distribution from the package URL's `distro`. No finding has a location,
and grype names none in the SARIF.

`grype-sbom.json` is the report, trimmed by the first jq program above with
`$ids` null, and with the source's target, the file's path, replaced by
`sbom.cdx.json`. `grype-sbom.cdx.json` keeps grype's `metadata` as it wrote
it, and each component's type, name, version, PURL and CPE: a component an
SBOM names by its CPE alone keeps no PURL there.

```jq
def keep($ks): with_entries(select(.key | IN($ks[])));
keep(["bomFormat", "specVersion", "metadata", "components"])
| .metadata |= keep(["component"])
| .components |= map(keep(["type", "name", "version", "purl", "cpe"]))
```

`grype-sbom.sarif` keeps every result and rule, without each rule's long
descriptions.
