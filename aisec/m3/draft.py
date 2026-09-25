"""Module 3 — AI-assisted report writing.

The model drafts three sections per finding: description, impact, remediation. Structured
output again, for the same reason as everywhere else: a 3B model asked for "write me a report
section" returns prose of unpredictable shape, and the assembler needs fields.

Three rules this module enforces, all of them about not letting the model overstate:

1. **Only verified findings are drafted.** A finding whose AI triage a human marked `wrong`
   never reaches the report. Writing polished prose about a claim you already disproved is
   how AI-assisted reporting produces confident nonsense.

2. **Severity comes from the scanner and the human, never the draft.** The drafting schema has
   no severity field at all. The model writes prose; it does not get to re-rate anything.

3. **The raw draft is immutable.** It is written once to results/m3_drafts/ and never touched
   again. The edited version lives separately. That separation is what lets a reader see
   exactly what a human had to correct — which is the point of the module.
"""
from __future__ import annotations

from aisec.llm import LLMClient
from aisec.m2.models import Finding

DRAFT_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "impact": {"type": "string"},
        "remediation": {"type": "string"},
    },
    "required": ["description", "impact", "remediation"],
}

DRAFT_SYSTEM = (
    "You are drafting sections of a penetration test report for a technical client. "
    "Write three sections about the single finding given:\n"
    "description - what the issue is, factually, in 2-3 sentences.\n"
    "impact - what an attacker could actually achieve. Be concrete and proportionate. "
    "Do not inflate a hardening issue into a breach.\n"
    "remediation - specific, actionable steps for a developer.\n"
    "Use only the evidence provided. Do not invent affected systems, CVEs, CVSS scores or "
    "exploit details that are not in the evidence. Do not state a severity rating. "
    "Do not claim an issue 'allows' an attack when it only removes a mitigating control. "
    "Plain prose, no markdown headings, under 70 words per section."
)

# Report sections in fixed order. Used for drafting, file layout and parsing back.
SECTIONS = ["description", "impact", "remediation"]


def build_prompt(finding: Finding, verdict: str = "", reproduction: str = "") -> str:
    lines = [
        f"Finding: {finding.title}",
        f"Source: {finding.source} ({finding.plugin_id or 'n/a'})",
        f"Severity (confirmed): {finding.severity}",
        f"Affected: {finding.target}",
        f"Instances observed: {finding.instances}",
        f"Evidence: {finding.evidence or '(none recorded)'}",
        f"Scanner description: {finding.description[:500]}",
    ]
    if reproduction:
        # The strongest evidence available: what happened when the finding was reproduced
        # against the live target. Giving the model this keeps the prose tied to something
        # observed rather than to the generic description of the alert class.
        lines.append(f"Reproduction against the live target: {reproduction}")
    if verdict:
        lines.append(f"Human review of the AI triage for this finding: {verdict}")
    return "\n".join(lines)


def draft_finding(client: LLMClient, finding: Finding, verdict: str = "",
                  reproduction: str = "") -> dict:
    """Return {section: text}. A parse failure yields empty sections rather than junk prose."""
    result = client.chat_json(DRAFT_SYSTEM, build_prompt(finding, verdict, reproduction),
                              DRAFT_SCHEMA, num_predict=500)
    if result.get("_parse_error"):
        return {section: "" for section in SECTIONS} | {"_parse_error": True}
    return {section: str(result.get(section, "")).strip() for section in SECTIONS}


def to_markdown(finding: Finding, sections: dict) -> str:
    """One finding as an editable markdown file. Headings are the parse contract."""
    lines = [
        f"# {finding.title}",
        "",
        f"- **Finding ID:** `{finding.id}`",
        f"- **Source:** {finding.source}",
        f"- **Severity:** {finding.severity}",
        f"- **Affected:** {finding.target}",
        f"- **Evidence:** {finding.evidence or '(none recorded)'}",
        *([f"- **Reproduced:** {sections['_reproduction']}"]
          if sections.get("_reproduction") else []),
        "",
    ]
    for section in SECTIONS:
        lines += [f"## {section.capitalize()}", "", sections.get(section, "") or "_(empty)_", ""]
    return "\n".join(lines)


def parse_markdown(text: str) -> dict:
    """Read sections back out of an edited file.

    Tolerant by design: a human editing prose in their own editor should not be able to break
    the report by adding a blank line or changing capitalisation.
    """
    sections = {section: [] for section in SECTIONS}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            heading = stripped[3:].strip().lower()
            current = heading if heading in sections else None
            continue
        if current:
            sections[current].append(line)
    return {name: "\n".join(body).strip() for name, body in sections.items()}
