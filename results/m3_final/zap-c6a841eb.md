# Content Security Policy (CSP) Header Not Set

- **Finding ID:** `zap-c6a841eb`
- **Source:** zap
- **Severity:** medium
- **Affected:** http://localhost:3000
- **Evidence:** (none recorded)
- **Reproduced:** confirmed - header 'content-security-policy' is absent from the response

## Description

No `Content-Security-Policy` header is returned by the application. Confirmed by reproduction: the header is absent from the response to a request for the site root.


## Impact

A missing CSP does not by itself permit script injection. Its absence removes a layer of defence in depth: if a cross-site scripting flaw exists elsewhere in the application, there is no policy to restrict which script sources may execute or where data may be sent, so an injected script runs unimpeded. The practical severity therefore depends on whether an injection vector exists; none was demonstrated in this test.


## Remediation

Introduce a `Content-Security-Policy` header, deploying first in `Content-Security-Policy-Report-Only` mode to identify breakage before enforcing. Note that this application is Angular-based: a policy forbidding inline styles will break the framework's runtime style injection unless nonces or hashes are configured, so the policy needs tailoring rather than a blanket `default-src 'self'`.

