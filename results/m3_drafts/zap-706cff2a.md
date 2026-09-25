# Cross-Origin-Opener-Policy Header Missing or Invalid

- **Finding ID:** `zap-706cff2a`
- **Source:** zap
- **Severity:** low
- **Affected:** http://localhost:3000
- **Evidence:** param=Cross-Origin-Opener-Policy
- **Reproduced:** confirmed - header 'cross-origin-opener-policy' is absent from the response

## Description

Cross-Origin-Opener-Policy header missing from responses, allowing other sites to potentially share browsing contexts.

## Impact

An attacker could exploit this to potentially access data from shared browsing contexts, though no specific data leakage was observed.

## Remediation

Add 'Cross-Origin-Opener-Policy: same-origin' to all server responses to restrict sharing.
