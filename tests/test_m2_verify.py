"""Reproduction logic. This is what turns a reviewer's opinion into a checkable fact, so a
bug here silently corrupts the ground truth everything else leans on."""
import pytest

from aisec.m2 import verify as verify_mod
from aisec.m2.models import Finding


def _finding(title, target="http://x.test/a", source="zap"):
    return Finding(id="f1", source=source, title=title, severity="medium", target=target)


SPA = {"status": 200, "size": 9393, "sha": "aa97229042ec", "headers": {}, "error": ""}


def test_spa_fallback_is_called_a_false_positive(monkeypatch):
    """The finding that started this: HTTP 200 whose body is the app's catch-all page is
    proof of nothing, but reads as proof of disclosure if you only look at the status code."""
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: dict(SPA))
    result = verify_mod.verify_disclosure(_finding("Bypassing 403"), SPA)
    assert result.conclusion == "false_positive"
    assert "byte-identical" in result.detail


def test_distinct_content_is_confirmed(monkeypatch):
    real = {"status": 200, "size": 3047, "sha": "deadbeefcafe", "headers": {}, "error": ""}
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: real)
    result = verify_mod.verify_disclosure(_finding("Backup File Disclosure"), SPA)
    assert result.conclusion == "confirmed" and "3047b" in result.detail


@pytest.mark.parametrize("status", [401, 403])
def test_blocked_content_is_a_false_positive(monkeypatch, status):
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": status, "size": 100, "sha": "x", "headers": {}, "error": ""})
    assert verify_mod.verify_disclosure(_finding("Backup File Disclosure"), SPA).conclusion \
        == "false_positive"


def test_unreachable_target_is_inconclusive_not_confirmed(monkeypatch):
    """A target that is down must never be scored as evidence either way."""
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": 0, "size": 0, "sha": "", "headers": {}, "error": "URLError: refused"})
    assert verify_mod.verify_disclosure(_finding("Backup File Disclosure"), SPA).conclusion \
        == "inconclusive"


def test_missing_header_is_confirmed(monkeypatch):
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": 200, "size": 1, "sha": "x", "headers": {"server": "x"}, "error": ""})
    result = verify_mod.verify_header(_finding("CSP Header Not Set"), "content-security-policy")
    assert result.conclusion == "confirmed"


def test_present_header_contradicts_the_finding(monkeypatch):
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": 200, "size": 1, "sha": "x",
        "headers": {"content-security-policy": "default-src 'self'"}, "error": ""})
    result = verify_mod.verify_header(_finding("CSP Header Not Set"), "content-security-policy")
    assert result.conclusion == "false_positive" and "IS present" in result.detail


def test_wildcard_cors_is_confirmed(monkeypatch):
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": 200, "size": 1, "sha": "x",
        "headers": {"access-control-allow-origin": "*"}, "error": ""})
    assert verify_mod.verify_cors(_finding("CORS Misconfiguration")).conclusion == "confirmed"


def test_reflected_origin_is_confirmed(monkeypatch):
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": 200, "size": 1, "sha": "x",
        "headers": {"access-control-allow-origin": "http://aisec-probe.test"}, "error": ""})
    assert verify_mod.verify_cors(_finding("CORS Misconfiguration")).conclusion == "confirmed"


def test_absent_cors_header_contradicts_the_finding(monkeypatch):
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: {
        "status": 200, "size": 1, "sha": "x", "headers": {}, "error": ""})
    assert verify_mod.verify_cors(_finding("CORS Misconfiguration")).conclusion \
        == "false_positive"


def test_non_http_findings_are_honestly_inconclusive():
    """Said plainly rather than guessed at - 'inconclusive' is a real answer, not a dumping
    ground for things the tool could not be bothered to check."""
    result = verify_mod.verify_finding(
        _finding("Open tcp/3000", target="localhost:3000", source="nmap"), SPA)
    assert result.conclusion == "inconclusive" and "not an HTTP finding" in result.detail


def test_unknown_finding_types_are_inconclusive():
    result = verify_mod.verify_finding(_finding("Some Novel Alert"), SPA)
    assert result.conclusion == "inconclusive"
    assert "requires manual testing" in result.detail


def test_routing_picks_the_right_check():
    assert verify_mod.verify_finding.__name__ == "verify_finding"
    for title, expect_method in [
        ("Content Security Policy (CSP) Header Not Set", "http-head"),
        ("CORS Misconfiguration", "http-get + Origin"),
    ]:
        # patchless: only asserts routing shape via the method string on a down target
        result = verify_mod.verify_finding(_finding(title, target="http://127.0.0.1:1/"), SPA)
        assert result.method == expect_method


def test_origin_of_strips_path():
    assert verify_mod.origin_of("http://x.test/a/b?c=1") == "http://x.test"
    assert verify_mod.origin_of("localhost:3000") == ""


def test_all_conclusions_are_from_the_declared_set():
    assert set(verify_mod.CONCLUSIONS) == {"confirmed", "false_positive", "inconclusive"}
