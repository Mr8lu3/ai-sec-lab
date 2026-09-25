"""Reproduce findings against the live target to establish ground truth.

Why this exists: a human reviewer asked to judge "is this AI claim correct?" needs something
to judge against. For most web findings that something is cheap - one HTTP request settles it.
Without it, the accuracy table measures whether one person's guess agreed with a model's
guess, which is not a security result.

It found a real one immediately. ZAP reported "Bypassing 403" on
`/%2e/ftp/coupons_2013.md.bak`, returning HTTP 200. Reproduction showed the body was
byte-identical to the response for a URL that does not exist - Angular's catch-all route
serving index.html. Nothing was disclosed and no 403 was bypassed. The scanner was wrong, and
the model then rated that false positive "likely exploitable".

Three conclusions, and the third is used honestly rather than as a dumping ground:
  confirmed      - reproduction supports the finding
  false_positive - reproduction contradicts it
  inconclusive   - not mechanically checkable; needs a human. Said plainly, not guessed at.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit, urlunsplit

from aisec import config
from aisec.m2.models import Finding

VERIFICATION_PATH = config.RESULTS_DIR / "m2_verification.jsonl"

CONCLUSIONS = ("confirmed", "false_positive", "inconclusive")

# Findings whose truth is a response header. title fragment -> header that should be present.
HEADER_CHECKS = {
    "content security policy": "content-security-policy",
    "cross-origin-embedder-policy": "cross-origin-embedder-policy",
    "cross-origin-opener-policy": "cross-origin-opener-policy",
    "anti-clickjacking": "x-frame-options",
}
# Findings that claim content was disclosed at a URL.
DISCLOSURE_HINTS = ("disclosure", "bypassing 403", "backup file", "directory browsing")


@dataclass
class Verification:
    finding_id: str
    method: str                  # how it was checked
    conclusion: str
    detail: str
    observed: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _fetch(url: str, headers: dict | None = None, timeout: int = 8) -> dict:
    """GET a URL, returning status/body-hash/size/headers. Never raises on HTTP errors."""
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return {"status": response.status, "size": len(body),
                    "sha": hashlib.sha256(body).hexdigest()[:16],
                    "headers": {k.lower(): v for k, v in response.headers.items()},
                    "error": ""}
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return {"status": exc.code, "size": len(body),
                "sha": hashlib.sha256(body).hexdigest()[:16],
                "headers": {k.lower(): v for k, v in (exc.headers or {}).items()},
                "error": ""}
    except Exception as exc:
        return {"status": 0, "size": 0, "sha": "", "headers": {},
                "error": f"{type(exc).__name__}: {exc}"}


def spa_baseline(origin: str) -> dict:
    """Fetch a URL that cannot exist, to learn what 'not found' looks like on this app.

    A single-page app commonly answers every unmatched path with 200 and its index.html.
    Without this baseline, 'HTTP 200' reads as proof that a file was disclosed when it is
    proof of nothing.
    """
    probe = f"{origin}/aisec-probe-{hashlib.sha256(origin.encode()).hexdigest()[:10]}-nonexistent"
    return _fetch(probe)


def origin_of(url: str) -> str:
    """Scheme + host, or "" when the input is not an absolute http(s) URL.

    The scheme must be checked explicitly: urlsplit("localhost:3000") reads "localhost" as the
    scheme and "3000" as the path, which would otherwise yield the truthy nonsense "localhost:"
    and get used as a URL.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def verify_disclosure(finding: Finding, baseline: dict) -> Verification:
    """Did the URL actually return distinct content, or the app's catch-all page?"""
    url = finding.target
    observed = _fetch(url)
    if observed["error"]:
        return Verification(finding.id, "http-get", "inconclusive",
                            f"could not reach target: {observed['error']}", observed)

    if observed["status"] in (401, 403):
        return Verification(finding.id, "http-get", "false_positive",
                            f"target returns HTTP {observed['status']}; content is not "
                            f"accessible", observed)
    if baseline.get("sha") and observed["sha"] == baseline["sha"]:
        return Verification(
            finding.id, "http-get + spa-baseline", "false_positive",
            f"HTTP {observed['status']} but body is byte-identical to the response for a "
            f"URL that does not exist ({observed['size']}b, sha {observed['sha']}): this is "
            f"the app's catch-all page, not disclosed content", observed)
    if observed["status"] == 200:
        return Verification(
            finding.id, "http-get + spa-baseline", "confirmed",
            f"HTTP 200 returning {observed['size']}b of content distinct from the "
            f"catch-all page (sha {observed['sha']})", observed)
    return Verification(finding.id, "http-get", "inconclusive",
                        f"HTTP {observed['status']}; neither clearly accessible nor blocked",
                        observed)


def verify_header(finding: Finding, header: str) -> Verification:
    """Is the header the finding says is missing actually missing?"""
    url = origin_of(finding.target) or finding.target
    observed = _fetch(url)
    if observed["error"]:
        return Verification(finding.id, "http-head", "inconclusive",
                            f"could not reach target: {observed['error']}", observed)
    value = observed["headers"].get(header)
    if value:
        return Verification(finding.id, "http-head", "false_positive",
                            f"header {header!r} IS present: {value[:80]!r}", observed)
    return Verification(finding.id, "http-head", "confirmed",
                        f"header {header!r} is absent from the response", observed)


def verify_cors(finding: Finding) -> Verification:
    """Does the server reflect or wildcard an arbitrary Origin?"""
    url = origin_of(finding.target) or finding.target
    observed = _fetch(url, headers={"Origin": "http://aisec-probe.test"})
    if observed["error"]:
        return Verification(finding.id, "http-get + Origin", "inconclusive",
                            f"could not reach target: {observed['error']}", observed)
    allow = observed["headers"].get("access-control-allow-origin", "")
    if allow == "*":
        return Verification(finding.id, "http-get + Origin", "confirmed",
                            "Access-Control-Allow-Origin: * returned", observed)
    if "aisec-probe.test" in allow:
        return Verification(finding.id, "http-get + Origin", "confirmed",
                            f"arbitrary Origin reflected: {allow!r}", observed)
    if not allow:
        return Verification(finding.id, "http-get + Origin", "false_positive",
                            "no Access-Control-Allow-Origin header returned", observed)
    return Verification(finding.id, "http-get + Origin", "inconclusive",
                        f"Access-Control-Allow-Origin: {allow!r} - neither wildcard nor "
                        f"reflected", observed)


def verify_finding(finding: Finding, baseline: dict) -> Verification:
    """Route a finding to whichever mechanical check fits, or say it needs a human."""
    if finding.source != "zap" or not finding.target.startswith("http"):
        return Verification(finding.id, "none", "inconclusive",
                            "not an HTTP finding; not mechanically checkable here", {})

    title = finding.title.lower()
    for fragment, header in HEADER_CHECKS.items():
        if fragment in title:
            return verify_header(finding, header)
    if "cors" in title or "cross-domain misconfiguration" in title:
        return verify_cors(finding)
    if any(hint in title for hint in DISCLOSURE_HINTS):
        return verify_disclosure(finding, baseline)

    return Verification(finding.id, "none", "inconclusive",
                        "no mechanical check applies; requires manual testing or source review",
                        {})


# ---------------------------------------------------------------- storage

def save_verification(verification: Verification) -> None:
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with VERIFICATION_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(verification.to_dict(), ensure_ascii=False) + "\n")


def load_verifications() -> dict[str, Verification]:
    if not VERIFICATION_PATH.exists():
        return {}
    latest: dict[str, Verification] = {}
    for line in VERIFICATION_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            latest[record["finding_id"]] = Verification(**record)
    return latest
