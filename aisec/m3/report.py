"""Assemble the pentest report, and the side-by-side that shows what the human changed.

Layout on disk:

  results/m3_drafts/<finding>.md   raw AI output. Written once, never edited. This is evidence.
  results/m3_final/<finding>.md    seeded from the draft, then edited by a human in their editor.
  results/pentest_report.md        the deliverable, assembled from the FINAL files.
  results/m3_ai_vs_final.md        unified diff per finding, so a reader can see every edit.

Editing happens in a real editor rather than a terminal prompt, because report prose is not
something anyone wants to type into an input() box - and because leaving the raw file
untouched on disk is what makes the comparison honest.
"""
from __future__ import annotations

import difflib
import json
from datetime import datetime, timezone

from aisec import config
from aisec.m2.models import Finding
from aisec.m2.review import latest_reviews, load_findings
from aisec.m2.verify import load_verifications
from aisec.m3.draft import SECTIONS, parse_markdown, to_markdown

DRAFTS_DIR = config.RESULTS_DIR / "m3_drafts"
FINAL_DIR = config.RESULTS_DIR / "m3_final"
REPORT_PATH = config.RESULTS_DIR / "pentest_report.md"
DIFF_PATH = config.RESULTS_DIR / "m3_ai_vs_final.md"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

REPORTABLE_VERDICTS = {"correct", "overconfident"}


def verified_findings(include_unverified: bool = False) -> tuple[list[Finding], list[str]]:
    """Return (findings to report, notes about what was excluded and why).

    Inclusion is decided by **reproduction against the live target**, not by whether the AI's
    triage claim was any good. Those are different questions and an earlier version of this
    function conflated them: it gated the report on the human's verdict about the MODEL, so a
    finding the model described badly was dropped even though reproduction had confirmed it
    was real. "The AI was wrong about this" is not evidence that a finding does not exist.

    So:
      confirmed by reproduction        -> reported
      contradicted by reproduction     -> excluded, and said so
      not mechanically checkable       -> excluded unless include_unverified

    A report that contains only findings the tester reproduced is a defensible artefact. One
    that contains whatever a scanner said, filtered by what a language model thought of it,
    is not.
    """
    findings = load_findings()
    verifications = load_verifications()
    reviews = latest_reviews()
    reviewed = {finding_id for (finding_id, _model) in reviews}

    keep, notes = [], []
    for finding in findings:
        verification = verifications.get(finding.id)
        conclusion = verification.conclusion if verification else "unchecked"

        if conclusion == "confirmed":
            keep.append(finding)
        elif conclusion == "false_positive":
            notes.append(f"{finding.id} ({finding.title}) excluded: reproduction contradicts "
                         f"the scanner - {verification.detail}")
        elif include_unverified:
            keep.append(finding)
            notes.append(f"{finding.id} ({finding.title}) INCLUDED WITHOUT REPRODUCTION: "
                         f"{verification.detail if verification else 'not checked'}")
        else:
            reason = verification.detail if verification else "not checked against the target"
            suffix = "" if finding.id in reviewed else " and not reviewed"
            notes.append(f"{finding.id} ({finding.title}) excluded: not reproduced{suffix} "
                         f"- {reason}")
    return keep, notes


def write_draft(finding: Finding, sections: dict) -> None:
    """Raw AI output. Written once and then left alone - it is the 'before' half of the
    comparison, so overwriting it on a re-run would destroy the evidence."""
    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    (DRAFTS_DIR / f"{finding.id}.md").write_text(
        to_markdown(finding, sections), encoding="utf-8")


def seed_final(finding: Finding, sections: dict) -> bool:
    """Create the editable copy if it does not exist. Returns True if seeded.

    Never overwrites: a re-run of `m3 draft` must not silently discard someone's edits.
    """
    FINAL_DIR.mkdir(parents=True, exist_ok=True)
    path = FINAL_DIR / f"{finding.id}.md"
    if path.exists():
        return False
    path.write_text(to_markdown(finding, sections), encoding="utf-8")
    return True


def _read(directory, finding_id: str) -> str:
    path = directory / f"{finding_id}.md"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def edit_stats(finding_id: str) -> dict:
    """How much a human changed, per section. Counted, not guessed."""
    raw = parse_markdown(_read(DRAFTS_DIR, finding_id))
    final = parse_markdown(_read(FINAL_DIR, finding_id))
    stats = {}
    for section in SECTIONS:
        before, after = raw.get(section, ""), final.get(section, "")
        stats[section] = {
            "changed": before.strip() != after.strip(),
            "words_before": len(before.split()),
            "words_after": len(after.split()),
        }
    stats["any_changed"] = any(s["changed"] for s in stats.values() if isinstance(s, dict))
    return stats


def build_report(include_unverified: bool = False) -> str:
    findings, notes = verified_findings(include_unverified)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines = [
        "# Penetration Test Report — OWASP Juice Shop",
        "",
        f"**Date:** {generated}  ",
        "**Target:** OWASP Juice Shop, local Docker container (`http://localhost:3000`)  ",
        "**Tools:** OWASP ZAP, Nmap  ",
        "**Report drafting:** local LLM draft, human reviewed and edited  ",
        "",
        "> Every finding below was produced by an automated scanner, triaged by a local "
        "language model, and then **verified by hand** before inclusion. AI-drafted prose was "
        "reviewed and corrected; the unedited AI drafts are kept alongside this report in "
        "`results/m3_drafts/` and the changes are shown in `results/m3_ai_vs_final.md`.",
        "",
        "## Scope and limitations",
        "",
        "Testing was limited to a locally hosted instance of OWASP Juice Shop, a deliberately "
        "vulnerable application, running in Docker on the tester's own machine. No external "
        "or third-party systems were touched. Findings come from an automated scan and are "
        "not a substitute for a full manual penetration test.",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in SEVERITY_ORDER:
        if counts.get(severity):
            lines.append(f"| {severity.capitalize()} | {counts[severity]} |")
    lines += [f"| **Total** | **{len(findings)}** |", ""]

    if not findings:
        lines += ["_No verified findings to report. Run `cli.py m2 review` to verify "
                  "findings before generating a report._", ""]

    lines += ["## Findings", ""]
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity)
                                              if f.severity in SEVERITY_ORDER else 99, f.id))
    for index, finding in enumerate(ordered, start=1):
        final = parse_markdown(_read(FINAL_DIR, finding.id))
        lines += [
            f"### {index}. {finding.title}",
            "",
            f"**Severity:** {finding.severity.capitalize()}  ",
            f"**Affected:** `{finding.target}`  ",
            f"**Source:** {finding.source} ({finding.plugin_id or 'n/a'})"
            + (f"  \n**CWE:** {finding.cwe}" if finding.cwe else ""),
            "",
        ]
        for section in SECTIONS:
            body = final.get(section, "").strip()
            lines += [f"**{section.capitalize()}**", "", body or "_Not yet written._", ""]

    if notes:
        lines += ["## Appendix A — findings excluded from this report", "",
                  "Recorded for transparency: a finding left out of a report should be "
                  "accounted for, not silently dropped.", ""]
        lines += [f"- {note}" for note in notes]
        lines.append("")

    text = "\n".join(lines)
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(text, encoding="utf-8")
    return text


def build_diff() -> str:
    """Per-finding unified diff of raw AI draft against the human-edited final."""
    findings, _ = verified_findings(include_unverified=True)
    lines = [
        "# AI draft vs human-edited final",
        "",
        "Left side (`-`) is the unedited local-model draft. Right side (`+`) is what a human "
        "sent to the client. This file exists so a reader can judge how much correction "
        "AI-assisted report writing actually needed.",
        "",
    ]
    edited_count = 0
    drafted_count = 0
    for finding in findings:
        raw_text, final_text = _read(DRAFTS_DIR, finding.id), _read(FINAL_DIR, finding.id)
        if not raw_text:
            continue
        drafted_count += 1
        stats = edit_stats(finding.id)
        changed_sections = [s for s in SECTIONS if stats[s]["changed"]]
        if changed_sections:
            edited_count += 1
        lines += [f"## `{finding.id}` {finding.title}", "",
                  f"Sections edited: {', '.join(changed_sections) if changed_sections else 'none'}",
                  ""]
        if changed_sections:
            diff = difflib.unified_diff(
                raw_text.splitlines(), final_text.splitlines(),
                fromfile="ai_draft", tofile="human_final", lineterm="", n=1)
            lines += ["```diff", *diff, "```", ""]
    # Denominator is drafts that exist, not findings considered. Counting undrafted findings
    # here reported "5 of 14" for a run where all 5 drafts needed editing, which understated
    # the edit rate and made the model look better than it was.
    lines.insert(4, f"**{edited_count} of {drafted_count} drafts required human edits.**\n")
    text = "\n".join(lines)
    DIFF_PATH.write_text(text, encoding="utf-8")
    return text
