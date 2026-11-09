# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only; the NVD response carries the timestamp
2026-11-09T10:27:27 (UTC). Each SHA-256 below was checked against
`sources/cve2026/SHA256SUMS` before use.

| Source | URL | Commit | Used for | SHA-256 of copy |
|---|---|---|---|---|
| Fix diff `CVE-2026-65600_traefik_3f10dd442479.diff` (2 files, +77/-42) | https://github.com/traefik/traefik/commit/3f10dd442479530560f010167cac2947676d9b29 | 3f10dd442479530560f010167cac2947676d9b29 ("Sanitize replaced path in ReplacePathRegex middleware", 2026-07-06T09:44:05Z) | `ServeHTTP` diff:8-34 (cited: 11-13, 17, 21-24, 26-31); test table diff:41-203 (cited: 60-73, 143-155, 157-169, 195-203) | 93c9afd68d535c50dd54ac5ee7a00876769077fa020f891ae317bb590e069e65 |
| GHSA record `ghsa_rec/CVE-2026-65600.json` | https://github.com/advisories/GHSA-cxjq-mrr5-89rv (repo advisory: https://github.com/traefik/traefik/security/advisories/GHSA-cxjq-mrr5-89rv) | references 3f10dd4 | affected/fixed versions, CWE-22, attack flow and PoC router layout (`^/api(.*)` → `/$1`, `/api../admin`, `/api%2e%2e/admin`) | 8e7f969a43f1aa0437e0d399a6cecd4419ffcfe4d87c1260b89db41ff83d0f68 |
| NVD record `nvd/CVE-2026-65600.json` (status Analyzed, published 2026-07-22) | https://nvd.nist.gov/vuln/detail/CVE-2026-65600 | references 3f10dd4 | description, affected ranges (<= 2.11.51, 3.6.0-3.6.22, 3.7.0-3.7.6; fixed 2.11.52, 3.6.23, 3.7.7) | 166cf5b80ec53020a2811b39c3cbb9f3796b1308f4d74a6b6768731e19bfc858 |

Go standard library behaviour (`net/url` `ParseRequestURI`, `EscapedPath`,
`RequestURI`, `JoinPath`; `path.Clean`) is used as shipped with the Go
toolchain named in `go.mod`; it is not a downloaded source.

No source contained instructions addressed to a tool or agent.
