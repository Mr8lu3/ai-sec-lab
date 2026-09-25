# CORS Misconfiguration

- **Finding ID:** `zap-28cf0c8a`
- **Source:** zap
- **Severity:** medium
- **Affected:** http://localhost:3000
- **Evidence:** attack=origin: http://QhAoQOKF.com
- **Reproduced:** confirmed - Access-Control-Allow-Origin: * returned

## Description

CORS misconfiguration allows any domain to access content, even without credentials.

## Impact

An attacker could read unauthenticated sensitive content from the server.

## Remediation

Set Access-Control-Allow-Origin to null or the specific domain, and set Access-Control-Allow-Credentials to true for authenticated requests.
