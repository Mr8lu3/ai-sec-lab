"""Scanner parsing. If this is wrong, every downstream triage and accuracy number is wrong."""
import json
from pathlib import Path

import pytest

from aisec import config
from aisec.m2 import parsers
from aisec.m2.models import SEVERITIES

FIXTURES = config.REPO_ROOT / "aisec" / "m2" / "fixtures"


@pytest.fixture
def zap_findings():
    return parsers.parse_file(FIXTURES / "zap_sample.json")


@pytest.fixture
def nmap_findings():
    return parsers.parse_file(FIXTURES / "nmap_sample.xml")


# ---------------------------------------------------------------- ZAP

def test_zap_parses_every_alert(zap_findings):
    assert len(zap_findings) == 6


def test_zap_maps_riskcodes_to_our_severity_vocabulary(zap_findings):
    by_title = {f.title: f.severity for f in zap_findings}
    assert by_title["SQL Injection"] == "high"
    assert by_title["Content Security Policy (CSP) Header Not Set"] == "medium"
    assert by_title["Re-examine Cache-control Directives"] == "informational"
    assert all(f.severity in SEVERITIES for f in zap_findings)


def test_zap_strips_html_from_descriptions(zap_findings):
    for finding in zap_findings:
        assert "<p>" not in finding.description and "</p>" not in finding.description


def test_zap_keeps_genuine_duplicates_separate(zap_findings):
    """Two CSP alerts under different alertRefs must arrive as two Findings.

    Collapsing them here would do the model's grouping job for it and make the
    duplicate-detection accuracy measurement meaningless.
    """
    csp = [f for f in zap_findings if "Content Security Policy" in f.title]
    assert len(csp) == 2
    assert csp[0].id != csp[1].id


def test_zap_captures_evidence_and_parameter(zap_findings):
    sqli = next(f for f in zap_findings if f.title == "SQL Injection")
    assert "q" in sqli.evidence and "SQLITE_ERROR" in sqli.evidence
    assert sqli.cwe == "89"


def test_zap_records_instance_counts(zap_findings):
    csp = next(f for f in zap_findings if f.raw["alertRef"] == "10038-1")
    assert csp.instances == 3


# ---------------------------------------------------------------- Nmap

def test_nmap_returns_only_open_ports(nmap_findings):
    """Closed ports are scan facts, not findings. Feeding them to a model invites invented risk."""
    assert len(nmap_findings) == 2
    assert not any("8080" in f.title for f in nmap_findings)


def test_nmap_captures_service_banner(nmap_findings):
    ssh = next(f for f in nmap_findings if "22" in f.title)
    assert "OpenSSH" in ssh.evidence and "8.9p1" in ssh.evidence


def test_nmap_never_assigns_a_severity_itself(nmap_findings):
    """An open port is not a vulnerability. Rating it is the model's claim to make and the
    human's to check - this parser must not pre-empt either."""
    assert all(f.severity == "informational" for f in nmap_findings)


# ---------------------------------------------------------------- shared

def test_ids_are_stable_across_reparsing():
    """A review recorded yesterday must still match its finding today."""
    first = parsers.parse_file(FIXTURES / "zap_sample.json")
    second = parsers.parse_file(FIXTURES / "zap_sample.json")
    assert [f.id for f in first] == [f.id for f in second]


def test_ids_are_unique_within_a_scan(zap_findings, nmap_findings):
    ids = [f.id for f in zap_findings + nmap_findings]
    assert len(ids) == len(set(ids))


def test_ids_are_namespaced_by_source(zap_findings, nmap_findings):
    assert all(f.id.startswith("zap-") for f in zap_findings)
    assert all(f.id.startswith("nmap-") for f in nmap_findings)


def test_parser_tolerates_missing_optional_fields():
    """A partial export should degrade to a partial Finding, not crash a triage run."""
    minimal = '{"site":[{"@name":"http://x.test","alerts":[{"alert":"Bare","riskcode":"1"}]}]}'
    findings = parsers.parse_zap(minimal)
    assert len(findings) == 1
    assert findings[0].title == "Bare" and findings[0].severity == "low"


def test_empty_scans_return_no_findings():
    assert parsers.parse_zap('{"site":[]}') == []
    assert parsers.parse_nmap('<?xml version="1.0"?><nmaprun></nmaprun>') == []


def test_unsupported_file_type_is_rejected_clearly(tmp_path):
    bad = tmp_path / "scan.txt"
    bad.write_text("not a scan", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported scan file"):
        parsers.parse_file(bad)


def test_strip_html_collapses_whitespace():
    assert parsers.strip_html("<p>one</p>\n\n<p>two</p>") == "one two"


# ---------------------------------------------------------------- real exports

REAL_SCANS = config.REPO_ROOT / "scans"


@pytest.mark.skipif(not (REAL_SCANS / "zap_juiceshop.json").exists(),
                    reason="real scan export not present")
def test_parses_a_real_zap_export():
    """The fixtures are my reconstruction of ZAP's format; this checks the parser against an
    actual export from a real scan of Juice Shop. Real reports carry extra keys the fixtures
    do not (systemic, otherinfo, sourceid, and top-level insights/sequences), and the parser
    must ignore them rather than choke."""
    findings = parsers.parse_file(REAL_SCANS / "zap_juiceshop.json")
    assert len(findings) >= 10
    assert all(f.id.startswith("zap-") for f in findings)
    assert all(f.severity in SEVERITIES for f in findings)
    assert all(f.title and f.target for f in findings)
    assert any("Content Security Policy" in f.title for f in findings)


@pytest.mark.skipif(not (REAL_SCANS / "zap_full.json").exists(),
                    reason="full scan export not present")
def test_parses_a_multi_site_zap_report():
    """A real ZAP full scan emitted two sites - an empty https:// entry alongside the http://
    one that held all 16 alerts. A parser reading only site[0] would report zero findings."""
    findings = parsers.parse_file(REAL_SCANS / "zap_full.json")
    assert len(findings) >= 15, "alerts must be collected across every site entry"
    assert any("Backup File Disclosure" in f.title for f in findings)


def test_active_scan_evidence_is_captured_from_attack_and_otherinfo():
    """Regression: ZAP's ACTIVE rules usually leave `evidence` empty and put the payload in
    `attack` and the demonstrated result in `otherinfo`. Reading only `evidence` discarded the
    proof for exactly the findings that had any, so the model was asked whether a 403 bypass
    was exploitable while being shown "evidence: (none)"."""
    report = json.dumps({"site": [{"@name": "http://x.test", "alerts": [{
        "alert": "Bypassing 403", "riskcode": "2", "count": "1",
        "instances": [{"uri": "http://x.test/%2e/ftp/secret.bak", "method": "GET",
                       "attack": "/%2e/ftp/secret.bak", "evidence": "",
                       "otherinfo": "http://x.test/ftp/secret.bak"}]}]}]})
    finding = parsers.parse_zap(report)[0]
    assert "attack=/%2e/ftp/secret.bak" in finding.evidence
    assert "result=http://x.test/ftp/secret.bak" in finding.evidence


def test_passive_scan_evidence_field_is_still_used():
    report = json.dumps({"site": [{"@name": "http://x.test", "alerts": [{
        "alert": "Cross-Domain Misconfiguration", "riskcode": "2", "count": "1",
        "instances": [{"uri": "http://x.test/", "evidence": "Access-Control-Allow-Origin: *"}]}]}]})
    assert "evidence=Access-Control-Allow-Origin: *" in parsers.parse_zap(report)[0].evidence


def test_alert_level_otherinfo_is_used_when_instances_lack_it():
    report = json.dumps({"site": [{"@name": "http://x.test", "alerts": [{
        "alert": "Backup File Disclosure", "riskcode": "2", "count": "1",
        "otherinfo": "<p>A backup of [http://x.test/a] is at [http://x.test/a.bak]</p>",
        "instances": [{"uri": "http://x.test/a.bak"}]}]}]})
    evidence = parsers.parse_zap(report)[0].evidence
    assert "a.bak" in evidence and "<p>" not in evidence


@pytest.mark.skipif(not (REAL_SCANS / "zap_full.json").exists(),
                    reason="full scan export not present")
def test_real_active_findings_carry_usable_evidence():
    """The model cannot judge exploitability from an empty evidence field. Every medium+
    finding from the active scan must arrive with something to reason about."""
    findings = parsers.parse_file(REAL_SCANS / "zap_full.json")
    actionable = [f for f in findings if f.severity in ("medium", "high", "critical")]
    assert actionable
    with_evidence = [f for f in actionable if f.evidence.strip()]
    assert len(with_evidence) >= len(actionable) - 1, \
        "active-scan findings should carry attack/result evidence"


@pytest.mark.skipif(not (REAL_SCANS / "nmap_juiceshop.xml").exists(),
                    reason="real scan export not present")
def test_parses_a_real_nmap_export():
    findings = parsers.parse_file(REAL_SCANS / "nmap_juiceshop.xml")
    assert len(findings) >= 1
    assert any("3000" in f.title for f in findings)
    assert all(f.severity == "informational" for f in findings)
