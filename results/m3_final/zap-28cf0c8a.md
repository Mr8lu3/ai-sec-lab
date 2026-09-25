# CORS Misconfiguration

- **Finding ID:** `zap-28cf0c8a`
- **Source:** zap
- **Severity:** medium
- **Affected:** http://localhost:3000
- **Evidence:** attack=origin: http://QhAoQOKF.com
- **Reproduced:** confirmed - Access-Control-Allow-Origin: * returned

## Description

The application returns `Access-Control-Allow-Origin: *` on its responses, so any origin may issue cross-origin reads of unauthenticated endpoints. Confirmed by reproduction: a request carrying an arbitrary `Origin` header received the wildcard in response.


## Impact

Any third-party site can read responses from unauthenticated endpoints on this host using the visitor's browser. Because the wildcard cannot be combined with credentialed requests, browsers will not expose authenticated session data this way, so the exposure is limited to data already reachable without authentication. It does still defeat controls that rely on origin or network position, such as IP allow-listing.


## Remediation

Replace the wildcard with an explicit allow-list of trusted origins, validated server-side against the request's `Origin` header. Do not set `Access-Control-Allow-Origin: null` - the null origin is forgeable from a sandboxed iframe. Do not enable `Access-Control-Allow-Credentials` unless credentialed cross-origin access is genuinely required, and never alongside a wildcard.

