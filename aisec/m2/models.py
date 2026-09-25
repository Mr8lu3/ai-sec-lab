"""Normalised shapes for Module 2.

A Finding is what a scanner reported. An Assessment is what the model CLAIMED about it.
A Review is what the human concluded after verifying that claim by hand.

Keeping these three separate is the entire point of the module: scanner output is evidence,
model output is a claim, and only human verification turns a claim into a finding you would
put in a report.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

# Severities we accept. Deliberately the scanner/industry vocabulary, not a numeric score:
# this project does not compute CVSS and must never present a model's guess as one.
SEVERITIES = ["informational", "low", "medium", "high", "critical"]

# What a human can conclude about a model claim after checking it.
VERDICTS = {
    "correct": "The claim matched what manual verification showed.",
    "wrong": "The claim was factually incorrect.",
    "overconfident": "Directionally reasonable but stated with more certainty than the "
                     "evidence supports, or severity inflated.",
    "unverified": "Not yet checked by a human.",
}


@dataclass
class Finding:
    """One raw scanner result, normalised across tools."""
    id: str                      # stable, derived from source + identifying fields
    source: str                  # "zap" | "nmap"
    title: str
    severity: str                # as reported by the SCANNER, not the model
    target: str                  # url or host:port
    description: str = ""
    evidence: str = ""
    cwe: str = ""
    plugin_id: str = ""
    instances: int = 1
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Assessment:
    """What the model claimed. Every field here is unverified until a human says otherwise."""
    finding_id: str
    model: str
    duplicate_of: str = ""       # another finding id, or "" if not a duplicate
    severity: str = ""           # the model's suggested severity
    exploitable: str = ""        # "likely" | "unlikely" | "unclear"
    reasoning: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# How the reviewer arrived at the verdict. Recorded because "I reproduced this" and
# "it looked plausible" are not the same evidence, and a table that stores them identically
# overstates how much of the review was actually grounded.
BASES = {
    "reproduced": "Checked against the live target; ground truth available.",
    "evidence": "Judged from the scanner evidence without independent reproduction.",
    "knowledge": "Judged from domain knowledge; not reproducible from this data.",
    "unsure": "Recorded a verdict but with low confidence.",
}


@dataclass
class Review:
    """The human verdict on one model claim."""
    finding_id: str
    model: str
    verdict: str                 # one of VERDICTS
    note: str = ""
    reviewer: str = ""
    basis: str = "evidence"      # one of BASES

    def to_dict(self) -> dict:
        return asdict(self)
