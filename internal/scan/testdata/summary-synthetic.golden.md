### Vulnerability scan, arm64

Compared with `ghcr.io/divbast/x@sha256:00`.

**New, so blocking: 3**

| Vulnerability | Severity | Package | Installed | Fixed in | Where |
|---|---|---|---|---|---|
| CVE-2026-0002 | HIGH | `zlib1g` | 1.3 | no fix | debian package |
| [CVE-2026-0003](https://example.test/a\|b) | HIGH | `std\|lib` | v1.27.3 rc1 | 1.27.4, 1.28.1 | usr/local/bin/a\|b |
| CVE-2026-0001 | HIGH | `stdlib` | v1.27.3 | no fix | usr/local/bin/a\|b |

**Already published, so advisory: 1**

| Vulnerability | Severity | Package | Installed | Fixed in | Where |
|---|---|---|---|---|---|
| [CVE-2026-0001](https://avd.aquasec.com/nvd/cve-2026-0001) | CRITICAL | `libssl3t64` | 3.5.1-1 | 3.5.1-2 | debian package |

