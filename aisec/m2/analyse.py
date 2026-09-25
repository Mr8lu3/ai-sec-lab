"""Ask a local model to triage scanner findings — and treat every answer as an unverified claim.

Three things the model is asked for, all via structured output:
  duplicate_of  - is this the same underlying issue as another finding?
  severity      - what severity would you assign?
  exploitable   - likely / unlikely / unclear

Two guardrails that matter more than the prompt:

1. **The model never sees a free-text severity field.** The schema pins severity to a fixed
   enum, so it cannot invent "Critical-High" or a CVSS score. This project does not compute
   CVSS, and a model's guess must never be dressed up as one.

2. **A claimed duplicate_of is validated against the real finding ids.** Small models cheerfully
   invent plausible-looking identifiers. An id that was not in the input is recorded as a
   hallucination rather than silently accepted - and that count is itself a result worth
   reporting.
"""
from __future__ import annotations

from aisec.llm import LLMClient
from aisec.m2.models import SEVERITIES, Assessment, Finding

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "duplicate_of": {
            "type": "string",
            "description": "id of an earlier finding describing the same issue, or 'none'",
        },
        "severity": {"type": "string", "enum": SEVERITIES},
        "exploitable": {"type": "string", "enum": ["likely", "unlikely", "unclear"]},
        "reasoning": {"type": "string"},
    },
    "required": ["duplicate_of", "severity", "exploitable", "reasoning"],
}

TRIAGE_SYSTEM = (
    "You are triaging automated security scanner output for a penetration test report. "
    "For the finding given, decide: whether it duplicates another finding in the provided list; "
    "what severity it warrants; and whether it is likely exploitable in practice. "
    "Judge only from the evidence given. An open port is not by itself a vulnerability. "
    "A missing security header is a hardening issue, not usually directly exploitable. "
    "If the evidence does not support a confident answer, say 'unclear'. "
    "Keep reasoning under 40 words."
)


def _catalogue(findings: list[Finding], current: Finding) -> str:
    """The other findings, compactly, so duplicate_of has something real to point at."""
    lines = [f"- {f.id}: [{f.source}/{f.severity}] {f.title} ({f.target})"
             for f in findings if f.id != current.id]
    return "\n".join(lines) or "(no other findings)"


def build_prompt(finding: Finding, findings: list[Finding]) -> str:
    return (
        f"Other findings in this scan:\n{_catalogue(findings, finding)}\n\n"
        f"Finding to assess:\n"
        f"  id: {finding.id}\n"
        f"  source: {finding.source}\n"
        f"  title: {finding.title}\n"
        f"  scanner severity: {finding.severity}\n"
        f"  target: {finding.target}\n"
        f"  instances: {finding.instances}\n"
        f"  evidence: {finding.evidence or '(none)'}\n"
        f"  description: {finding.description[:400]}"
    )


def validate_duplicate_ref(claimed: str, findings: list[Finding], current_id: str) -> tuple[str, str]:
    """Return (accepted_value, problem). `problem` is non-empty when the model hallucinated.

    Checked rather than trusted, because an invented finding id in a report is exactly the
    kind of error that destroys confidence in AI-assisted triage.
    """
    value = (claimed or "").strip()
    if not value or value.lower() in {"none", "n/a", "null", "-"}:
        return "", ""
    known = {f.id for f in findings}
    if value == current_id:
        return "", f"claimed the finding duplicates itself ({value})"
    if value not in known:
        return "", f"claimed duplicate_of={value!r}, which is not a finding id in this scan"
    return value, ""


def assess_finding(client: LLMClient, finding: Finding, findings: list[Finding]) -> Assessment:
    result = client.chat_json(TRIAGE_SYSTEM, build_prompt(finding, findings), TRIAGE_SCHEMA)

    if result.get("_parse_error"):
        return Assessment(finding_id=finding.id, model=client.model,
                          reasoning="model output unparseable",
                          raw={"parse_error": True})

    duplicate, problem = validate_duplicate_ref(
        str(result.get("duplicate_of", "")), findings, finding.id)

    severity = str(result.get("severity", "")).lower()
    if severity not in SEVERITIES:
        severity = ""

    return Assessment(
        finding_id=finding.id,
        model=client.model,
        duplicate_of=duplicate,
        severity=severity,
        exploitable=str(result.get("exploitable", "")).lower(),
        reasoning=str(result.get("reasoning", ""))[:400],
        raw={"claimed_duplicate_of": str(result.get("duplicate_of", "")),
             "hallucinated_reference": problem,
             "severity_delta": severity_delta(finding.severity, severity)},
    )


def severity_delta(scanner: str, model: str) -> int:
    """How far the model moved the scanner's severity. Positive = model escalated.

    Tracked because systematic escalation is the most common failure mode in AI triage, and
    it is invisible unless you measure it.
    """
    if scanner not in SEVERITIES or model not in SEVERITIES:
        return 0
    return SEVERITIES.index(model) - SEVERITIES.index(scanner)
