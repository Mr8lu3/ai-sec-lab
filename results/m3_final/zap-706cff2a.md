# Cross-Origin-Opener-Policy Header Missing or Invalid

- **Finding ID:** `zap-706cff2a`
- **Source:** zap
- **Severity:** low
- **Affected:** http://localhost:3000
- **Evidence:** param=Cross-Origin-Opener-Policy
- **Reproduced:** confirmed - header 'cross-origin-opener-policy' is absent from the response

## Description

No `Cross-Origin-Opener-Policy` header is returned. Confirmed by reproduction: the header is absent from the response to a request for the site root.


## Impact

Without COOP, a page that opens this application - or is opened by it - retains a reference to its window via `window.opener`. That reference enables cross-window interference such as tabnabbing, where an opened page redirects its opener to a phishing origin. It also prevents the document from reaching a cross-origin isolated state. No exploitation was demonstrated in this test.


## Remediation

Set `Cross-Origin-Opener-Policy: same-origin`. If the application legitimately depends on communicating with popups it opens, use `same-origin-allow-popups` instead. Pair with `Cross-Origin-Embedder-Policy` (see `zap-6b914d64`) if cross-origin isolation is the goal.

