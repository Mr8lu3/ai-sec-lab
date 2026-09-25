"""Turn scanner exports into normalised Findings.

Two parsers, both pure functions over file content, both unit tested. They are deliberately
tolerant: a scan export that is missing optional fields should degrade to a partial Finding
rather than crash a triage run halfway through.

NOTE ON FIXTURES: the sample files in fixtures/ are synthetic, written to match the documented
shapes of ZAP's JSON report and Nmap's XML output. They exist so the parsing logic is testable
without running a scan. They are NOT a substitute for validating against a real export - run
`cli.py m2 parse` against your own scan output and check the counts before trusting a triage.
"""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from aisec.m2.models import Finding

# ZAP encodes severity as riskcode 0-3. Mapped to our shared vocabulary.
_ZAP_RISK = {"0": "informational", "1": "low", "2": "medium", "3": "high"}

_TAG = re.compile(r"<[^>]+>")


def strip_html(text: str) -> str:
    """ZAP wraps descriptions in HTML. Strip it - the model gets plain text, not markup."""
    return re.sub(r"\s+", " ", _TAG.sub(" ", text or "")).strip()


def make_id(source: str, *parts: str) -> str:
    """Stable id from identifying fields, so re-parsing the same scan yields the same ids
    and a review recorded yesterday still matches its finding today."""
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:8]
    return f"{source}-{digest}"


def parse_zap(content: str) -> list[Finding]:
    """Parse a ZAP JSON report.

    Note the duplicate shape this preserves: ZAP reports the same pluginid more than once when
    an alert fires under different alertRefs. Those arrive as separate Findings on purpose -
    collapsing them here would do the model's grouping job for it and make the duplicate-
    detection accuracy measurement meaningless.
    """
    data = json.loads(content)
    findings: list[Finding] = []
    for site in data.get("site", []):
        target_base = site.get("@name", "")
        for alert in site.get("alerts", []):
            instances = alert.get("instances", []) or []
            first_uri = instances[0].get("uri", target_base) if instances else target_base
            param = next((i.get("param", "") for i in instances if i.get("param")), "")

            # ZAP spreads its proof across three fields and which one is populated depends on
            # the rule. PASSIVE rules fill `evidence` (the matched string). ACTIVE rules
            # usually leave it empty and put the payload in `attack` and the demonstrated
            # result in `otherinfo` - e.g. attack='/%2e/ftp/coupons_2013.md.bak' with
            # otherinfo naming the protected URL it reached.
            #
            # Reading only `evidence` therefore discarded the proof for exactly the findings
            # that had any: the active-scan results. The model was being asked whether a 403
            # bypass was exploitable while being shown "evidence: (none)".
            evidence = next((i.get("evidence", "") for i in instances if i.get("evidence")), "")
            attack = next((i.get("attack", "") for i in instances if i.get("attack")), "")
            otherinfo = next((i.get("otherinfo", "") for i in instances if i.get("otherinfo")), "")
            if not otherinfo:
                otherinfo = strip_html(alert.get("otherinfo", ""))
            evidence_parts = [
                f"evidence={evidence}" if evidence else "",
                f"attack={attack}" if attack else "",
                f"result={strip_html(otherinfo)}" if otherinfo else "",
            ]
            findings.append(Finding(
                id=make_id("zap", alert.get("pluginid", ""), alert.get("alertRef", ""), first_uri),
                source="zap",
                title=alert.get("alert") or alert.get("name", "Untitled alert"),
                severity=_ZAP_RISK.get(str(alert.get("riskcode", "")), "informational"),
                target=first_uri,
                description=strip_html(alert.get("desc", "")),
                evidence=" | ".join(p for p in
                                    ([f"param={param}"] if param else []) + evidence_parts if p),
                cwe=str(alert.get("cweid", "")),
                plugin_id=str(alert.get("pluginid", "")),
                instances=int(alert.get("count", len(instances) or 1)),
                raw={"alertRef": alert.get("alertRef", ""),
                     "confidence": alert.get("confidence", ""),
                     "riskdesc": alert.get("riskdesc", "")},
            ))
    return findings


def parse_nmap(content: str) -> list[Finding]:
    """Parse an Nmap XML report into one Finding per OPEN port.

    Closed and filtered ports are skipped: they are scan facts, not findings, and feeding them
    to a model invites it to invent risk where there is none.

    Severity is left at 'informational' for every port. An open port is not a vulnerability,
    and assigning it a severity here would be this tool asserting a risk rating the scan does
    not support. Rating it is the model's job in the next step - and that claim is exactly
    what the human review is there to check.
    """
    root = ET.fromstring(content)
    findings: list[Finding] = []
    for host in root.findall("host"):
        address = host.find("address")
        addr = address.get("addr", "unknown") if address is not None else "unknown"
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            service_el = port.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            banner = " ".join(p for p in (product, version) if p)

            findings.append(Finding(
                id=make_id("nmap", addr, proto, portid),
                source="nmap",
                title=f"Open {proto}/{portid} ({service})" + (f" - {banner}" if banner else ""),
                severity="informational",
                target=f"{hostname or addr}:{portid}",
                description=(f"Nmap reported {proto} port {portid} open on {addr}, "
                             f"service '{service}'." + (f" Banner: {banner}." if banner else "")),
                evidence=banner,
                plugin_id=f"nmap-{proto}-{portid}",
                raw={"service": service, "product": product, "version": version},
            ))
    return findings


def parse_file(path: Path) -> list[Finding]:
    """Dispatch on file extension. Explicit and boring on purpose."""
    content = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_zap(content)
    if suffix == ".xml":
        return parse_nmap(content)
    raise ValueError(f"unsupported scan file {path.name!r}: expected .json (ZAP) or .xml (Nmap)")
