# cortex9-traefik-replacepathregex-normalization-model

Offline model of **CVE-2026-65600** (GHSA-cxjq-mrr5-89rv): authentication
bypass by path traversal in Traefik's `ReplacePathRegex` middleware, before
(`pre`) and after (`post`) the fix commit
[3f10dd4](https://github.com/traefik/traefik/commit/3f10dd442479530560f010167cac2947676d9b29)
("Sanitize replaced path in ReplacePathRegex middleware"). Educational,
deterministic, Go standard library only (`net/url`, `path`, `regexp`). No
Traefik code is imported or run, no socket is opened.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled

`diff:N` is line N of the saved fix diff (see [SOURCES.md](SOURCES.md)).

1. The request-target is parsed with `url.ParseRequestURI` (what `net/http`
   gives the entrypoint). Traefik's own entrypoint sanitizing is **not**
   modelled.
2. Router of the GHSA PoC: `PathPrefix(/admin)` (priority 2, auth → 401)
   before `PathPrefix(/api)` (priority 1, rewrite), matched on the decoded
   path (model assumption).
3. `ServeHTTP`: `currentPath` is `RawPath`, else `EscapedPath()`
   (diff:11-13); the regex replacement becomes `RawPath` and its unescaped
   form `Path` (reconstructed: that code is between the hunks, consistent
   with the test expectations at diff:143-155 and diff:157-169);
   `RequestURI` is recomputed (diff:17).
4. `post` only: `req.URL = req.URL.JoinPath()` when the path is not empty
   (diff:21-24) and **400** if the normalized `Path` differs (diff:26-31).
5. Two backend kinds see the forwarded `RequestURI`: *raw* normalizes the
   path as received (like `path.posix.normalize` in the GHSA PoC backend);
   *decoded* unescapes first, then normalizes.

Labels: `BYPASS_RAW` / `BYPASS_DECODED` / `BYPASS_BOTH` when the forwarded
path is not under `/admin` but the backend's normalized form is;
`CONFIG_ADMIN` when the rewrite itself already yields `/admin` (no
traversal, not the CVE); `REJECT_400`, `AUTH_401`, `NO_ROUTER_404`,
`UNESCAPE_500`, `OK`, `BAD_INPUT`.

## What it shows (differential evidence)

| Case | pre | post |
|---|---|---|
| `p01` `GET /api../admin`, `^/api(.*)` → `/$1` | `BYPASS_BOTH`: public router, backend gets `/../admin` → `/admin` | `REJECT_400` (diff:27-30) |
| `d01` `/foo../bar`, `^/foo(.*)` (diff:195-203) | 200, forwards `/../bar` | 400, as the diff's new test expects |
| `d02` `/whoami/and/whoami` (diff:60-73) | `RawPath` `/who-am-i/and/whoami` (old expectation, diff:67) | `RawPath` empty after `JoinPath` (new table, diff:69-72) |
| `n01` `^/api/(.*)` (separator in the regex) | `OK` | `OK`, unchanged |
| `p02` `GET /api%2e%2e/admin` | `BYPASS_DECODED` | `BYPASS_DECODED` (**unverified observation**, below) |

Fixed sweep (`results/sweep.csv`, 748 targets `/api` + 3 tokens, PoC
configuration): every literal (no `%`) pre-fix bypass (5) is `REJECT_400`
post-fix; post-fix has no bypass for a raw-normalizing backend; 21
percent-encoded targets are `BYPASS_DECODED` pre-fix and 18 of them still are
post-fix; 119 targets that were `OK` or `CONFIG_ADMIN` become `REJECT_400`
(for example `/api/users` → `//users`).

**Unverified observation, not a finding:** in the model, `JoinPath()`
cleans the *escaped* form, so `%2e%2e` is not a dot segment there and the
decoded `Path` (`/../admin`) is unchanged; the check at diff:27 passes. Only a
backend that decodes before normalizing would then resolve `/admin`. This was
not reproduced against Traefik: its entrypoint may reject or rewrite encoded
dots before the middleware runs, and the GHSA PoC reports the `%2e` variant
for the vulnerable version only. See [LIMITATIONS.md](LIMITATIONS.md).

## Run

```sh
sh scripts/build.sh test                                # gofmt, vet, tests
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/rprmodel case pre '/api../admin' '^/api(.*)' '/$1'
```

`fixtures/expected.tsv` and the sweep are derived independently in Python
(`scripts/derive_expected.py`), which re-implements the URL and dot-segment
rules without reading the Go model; the Go tests compare against it.

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
