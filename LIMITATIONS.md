# Limitations

- **A model is not a finding.** Nothing here was run against Traefik. The
  labels describe the model, built from the saved diff, the GHSA and NVD
  text and the Go standard library.
- **Reconstructed code.** The diff shows `ServeHTTP` only partly
  (diff:8-34). The regex replacement into `RawPath` and its unescaping into
  `Path` sit between the hunks and are reconstructed, checked only against
  the test expectations at diff:60-73, 143-155, 157-169 and 195-203. The
  `UNESCAPE_500` label (bad escape after replacement) is part of that
  reconstruction and is **not verified**.
- **Not verified: Traefik's real router and entrypoint with `%2e`.** The
  model parses the target with `url.ParseRequestURI` only. Traefik's
  entrypoint sanitizing (named `sanitizePath` in the GHSA attack flow), any
  encoded-character policy and its rule matcher are not modelled. The
  post-fix `BYPASS_DECODED` rows (`p02`, `p05`, 18 sweep targets) are an
  **unverified observation** about the model: `JoinPath()` cleans the
  escaped form, so encoded dots are not dot segments there. In real Traefik
  they may be rejected or decoded earlier. The GHSA PoC also reports
  `/api%2e%2e/admin` reaching `/admin` on v3.7.6 with a backend that does not
  decode, which this model does not reproduce (here the raw backend gets
  `/%2e%2e/admin`): another sign that the entrypoint behaves differently from
  the model.
- **Router.** Two `PathPrefix` rules on the decoded path, higher priority
  first, as in the GHSA PoC. Host rules, other matchers, priorities computed
  from rule length, and `StripPrefix` (CVE-2026-48020) are not modelled.
- **Backends.** Two idealized normalizations (raw and decoded). Real
  frameworks differ (Express, Flask, Spring, etc.). The decoded backend
  decodes `%2F` too, which is not common.
- **Side effect.** In the model, `^/api(.*)` → `/$1` turns `/api/users` into
  `//users`, which the fix rejects with 400 (`a01`, 119 sweep targets). This
  is model behaviour, not verified against a Traefik release.
- **Input domain:** origin-form targets of at most 512 characters made of
  `A-Za-z0-9-._~/%`; replacements may add `$1`..`$9` (not followed by a name
  character); regexes must compile in both Go RE2 and Python `re` for the
  fixtures. Anything else is `BAD_INPUT`. Queries are not modelled.
- **Sweep:** `results/sweep.csv` is a fixed grid, not a proof.
- Nothing is attributed beyond the commit, GHSA and CVE listed in
  SOURCES.md.
