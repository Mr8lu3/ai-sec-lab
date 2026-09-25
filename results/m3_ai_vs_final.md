# AI draft vs human-edited final

Left side (`-`) is the unedited local-model draft. Right side (`+`) is what a human sent to the client. This file exists so a reader can judge how much correction AI-assisted report writing actually needed.

**5 of 5 drafts required human edits.**

## `zap-28cf0c8a` CORS Misconfiguration

Sections edited: description, impact, remediation

```diff
--- ai_draft
+++ human_final
@@ -11,3 +11,4 @@
 
-CORS misconfiguration allows any domain to access content, even without credentials.
+The application returns `Access-Control-Allow-Origin: *` on its responses, so any origin may issue cross-origin reads of unauthenticated endpoints. Confirmed by reproduction: a request carrying an arbitrary `Origin` header received the wildcard in response.
+
 
@@ -15,3 +16,4 @@
 
-An attacker could read unauthenticated sensitive content from the server.
+Any third-party site can read responses from unauthenticated endpoints on this host using the visitor's browser. Because the wildcard cannot be combined with credentialed requests, browsers will not expose authenticated session data this way, so the exposure is limited to data already reachable without authentication. It does still defeat controls that rely on origin or network position, such as IP allow-listing.
+
 
@@ -19,2 +21,3 @@
 
-Set Access-Control-Allow-Origin to null or the specific domain, and set Access-Control-Allow-Credentials to true for authenticated requests.
+Replace the wildcard with an explicit allow-list of trusted origins, validated server-side against the request's `Origin` header. Do not set `Access-Control-Allow-Origin: null` - the null origin is forgeable from a sandboxed iframe. Do not enable `Access-Control-Allow-Credentials` unless credentialed cross-origin access is genuinely required, and never alongside a wildcard.
+
```

## `zap-c6a841eb` Content Security Policy (CSP) Header Not Set

Sections edited: description, impact, remediation

```diff
--- ai_draft
+++ human_final
@@ -11,3 +11,4 @@
 
-Content Security Policy (CSP) header not set, allowing potentially malicious scripts to run.
+No `Content-Security-Policy` header is returned by the application. Confirmed by reproduction: the header is absent from the response to a request for the site root.
+
 
@@ -15,3 +16,4 @@
 
-An attacker could inject malicious scripts, compromising user sessions or stealing session tokens.
+A missing CSP does not by itself permit script injection. Its absence removes a layer of defence in depth: if a cross-site scripting flaw exists elsewhere in the application, there is no policy to restrict which script sources may execute or where data may be sent, so an injected script runs unimpeded. The practical severity therefore depends on whether an injection vector exists; none was demonstrated in this test.
+
 
@@ -19,2 +21,3 @@
 
-Set the CSP header in your server configuration to restrict allowed sources of content.
+Introduce a `Content-Security-Policy` header, deploying first in `Content-Security-Policy-Report-Only` mode to identify breakage before enforcing. Note that this application is Angular-based: a policy forbidding inline styles will break the framework's runtime style injection unless nonces or hashes are configured, so the policy needs tailoring rather than a blanket `default-src 'self'`.
+
```

## `zap-e50391e9` Cross-Domain Misconfiguration

Sections edited: description, impact, remediation

```diff
--- ai_draft
+++ human_final
@@ -11,3 +11,4 @@
 
-Cross-Domain Misconfiguration allows any domain to access unauthenticated API responses, reducing security controls.
+The same wildcard CORS policy observed as `zap-28cf0c8a`, detected here passively by inspecting response headers rather than by an active origin probe. Both findings describe one underlying misconfiguration.
+
 
@@ -15,3 +16,4 @@
 
-An attacker could access data intended for authenticated users, compromising security.
+As above: arbitrary origins can read unauthenticated responses. Authenticated responses are not exposed, because browsers refuse to combine a wildcard policy with credentialed requests.
+
 
@@ -19,2 +21,3 @@
 
-Restrict Access-Control-Allow-Origin to specific domains or use more secure headers like Access-Control-Allow-Origin: null.
+Addressed by the same fix as `zap-28cf0c8a`: an explicit server-side origin allow-list.
+
```

## `zap-6b914d64` Cross-Origin-Embedder-Policy Header Missing or Invalid

Sections edited: description, impact, remediation

```diff
--- ai_draft
+++ human_final
@@ -11,3 +11,4 @@
 
-Cross-Origin-Embedder-Policy header missing or invalid on http://localhost:3000. Header prevents loading cross-origin resources without explicit permission.
+No `Cross-Origin-Embedder-Policy` header is returned. Confirmed by reproduction: the header is absent from the response to a request for the site root.
+
 
@@ -15,3 +16,4 @@
 
-An attacker could exploit this by loading a malicious resource, though the header prevents direct loading, it could be used to bypass other security measures.
+This is a hardening gap rather than a directly exploitable flaw. Without COEP the document cannot enter a cross-origin isolated state, which means browser features gated behind isolation (such as `SharedArrayBuffer` and high-resolution timers) remain unavailable, and the page does not benefit from isolation's mitigation of speculative-execution side-channel attacks. No data exposure follows from the header's absence on its own.
+
 
@@ -19,2 +21,3 @@
 
-Add 'Cross-Origin-Embedder-Policy: require-same-origin' to response headers in server configuration.
+Set `Cross-Origin-Embedder-Policy: require-corp`, or `credentialless` where third-party resources cannot supply CORP headers. Cross-origin isolation additionally requires `Cross-Origin-Opener-Policy: same-origin` (see `zap-706cff2a`); neither header achieves isolation alone. Expect to audit embedded third-party resources first, as `require-corp` will block any that do not opt in.
+
```

## `zap-706cff2a` Cross-Origin-Opener-Policy Header Missing or Invalid

Sections edited: description, impact, remediation

```diff
--- ai_draft
+++ human_final
@@ -11,3 +11,4 @@
 
-Cross-Origin-Opener-Policy header missing from responses, allowing other sites to potentially share browsing contexts.
+No `Cross-Origin-Opener-Policy` header is returned. Confirmed by reproduction: the header is absent from the response to a request for the site root.
+
 
@@ -15,3 +16,4 @@
 
-An attacker could exploit this to potentially access data from shared browsing contexts, though no specific data leakage was observed.
+Without COOP, a page that opens this application - or is opened by it - retains a reference to its window via `window.opener`. That reference enables cross-window interference such as tabnabbing, where an opened page redirects its opener to a phishing origin. It also prevents the document from reaching a cross-origin isolated state. No exploitation was demonstrated in this test.
+
 
@@ -19,2 +21,3 @@
 
-Add 'Cross-Origin-Opener-Policy: same-origin' to all server responses to restrict sharing.
+Set `Cross-Origin-Opener-Policy: same-origin`. If the application legitimately depends on communicating with popups it opens, use `same-origin-allow-popups` instead. Pair with `Cross-Origin-Embedder-Policy` (see `zap-6b914d64`) if cross-origin isolation is the goal.
+
```
