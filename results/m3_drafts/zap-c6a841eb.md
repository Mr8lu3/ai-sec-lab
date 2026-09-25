# Content Security Policy (CSP) Header Not Set

- **Finding ID:** `zap-c6a841eb`
- **Source:** zap
- **Severity:** medium
- **Affected:** http://localhost:3000
- **Evidence:** (none recorded)
- **Reproduced:** confirmed - header 'content-security-policy' is absent from the response

## Description

Content Security Policy (CSP) header not set, allowing potentially malicious scripts to run.

## Impact

An attacker could inject malicious scripts, compromising user sessions or stealing session tokens.

## Remediation

Set the CSP header in your server configuration to restrict allowed sources of content.
