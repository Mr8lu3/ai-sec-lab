"""Storage and scoring for the human review workflow.

The module's thesis in one sentence: an AI triage result is a claim, and a claim only becomes
a finding after a human verifies it. Everything here exists to make that verification a
recorded, countable step rather than an informal glance.

The accuracy table is per model, because "the AI was right 70% of the time" is not a useful
statement unless you say which model, on what, and how you checked.
"""
from __future__ import annotations

import json
from pathlib import Path

from aisec import config
from aisec.m2.models import BASES, VERDICTS, Assessment, Finding, Review

FINDINGS_PATH = config.RESULTS_DIR / "m2_findings.jsonl"
ASSESSMENTS_PATH = config.RESULTS_DIR / "m2_assessments.jsonl"
REVIEWS_PATH = config.RESULTS_DIR / "m2_reviews.jsonl"


def _append(path: Path, record: dict) -> None:
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


# ---------------------------------------------------------------- findings

def save_findings(findings: list[Finding]) -> None:
    """Replace the finding set. Findings come from a scan, so a new scan supersedes the old."""
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with FINDINGS_PATH.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")


def load_findings() -> list[Finding]:
    return [Finding(**record) for record in _load(FINDINGS_PATH)]


# ---------------------------------------------------------------- assessments

def save_assessment(assessment: Assessment) -> None:
    _append(ASSESSMENTS_PATH, assessment.to_dict())


def load_assessments() -> list[Assessment]:
    return [Assessment(**record) for record in _load(ASSESSMENTS_PATH)]


def latest_assessments(model: str | None = None) -> dict[tuple[str, str], Assessment]:
    """Most recent assessment per (finding, model). Re-running triage supersedes, not duplicates."""
    latest: dict[tuple[str, str], Assessment] = {}
    for assessment in load_assessments():
        if model and assessment.model != model:
            continue
        latest[(assessment.finding_id, assessment.model)] = assessment
    return latest


# ---------------------------------------------------------------- reviews

def save_review(review: Review) -> None:
    if review.verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {review.verdict!r}; expected one of {sorted(VERDICTS)}")
    if review.basis not in BASES:
        raise ValueError(f"unknown basis {review.basis!r}; expected one of {sorted(BASES)}")
    _append(REVIEWS_PATH, review.to_dict())


def load_reviews() -> list[Review]:
    return [Review(**record) for record in _load(REVIEWS_PATH)]


def latest_reviews() -> dict[tuple[str, str], Review]:
    latest: dict[tuple[str, str], Review] = {}
    for review in load_reviews():
        latest[(review.finding_id, review.model)] = review
    return latest


def pending(model: str, include_reviewed: bool = False) -> list[tuple[Finding, Assessment]]:
    """Claims by this model that no human has ruled on yet.

    `include_reviewed` re-opens claims that already carry a verdict, so a second reviewer can
    record their own. Verdicts are append-only and the most recent one wins, so nothing is
    destroyed - the earlier verdict stays in the file as a record of who thought what.
    """
    findings = {f.id: f for f in load_findings()}
    reviewed = set() if include_reviewed else set(latest_reviews())
    out = []
    for (finding_id, model_name), assessment in latest_assessments(model).items():
        if (finding_id, model_name) in reviewed:
            continue
        if finding_id in findings:
            out.append((findings[finding_id], assessment))
    return sorted(out, key=lambda pair: pair[0].id)


def describe_finding(finding_id: str, findings: list[Finding]) -> str:
    """Render a finding id as something a reviewer can actually judge.

    The review prompt used to print a bare id for a duplicate claim. A reviewer cannot say
    whether "this duplicates zap-6b914d64" is true without knowing what zap-6b914d64 IS, so
    the claim was unjudgeable as displayed - the tool was asking for a verdict while
    withholding what the verdict was about.
    """
    for finding in findings:
        if finding.id == finding_id:
            return (f'{finding_id}  ->  "{finding.title}" '
                    f'[{finding.source}/{finding.severity}] {finding.target}')
    return f"{finding_id}  ->  (no such finding in this scan)"


# ---------------------------------------------------------------- claim-set validation

def duplicate_graph_problems(assessments: dict[tuple[str, str], Assessment],
                             findings: list[Finding]) -> dict[str, list[str]]:
    """Check duplicate claims against each other, not just individually.

    Each duplicate_of claim can be individually well-formed (it names a real finding id) and
    the SET of them still be incoherent. Three objective checks, no human judgement needed:

      mutual     - A says it duplicates B while B says it duplicates A. Both cannot be the
                   original, so at least one claim is wrong.
      cycle      - the same thing over a longer chain (A->B->C->A).
      cross_source - a finding from one scanner claimed as a duplicate of another scanner's.
                   An open port reported by nmap is not the same issue as a missing HTTP
                   header reported by ZAP.

    These are caught by the tool, not the reviewer, which is the point: the more of the
    validation burden that is mechanical, the less a tired human has to carry.
    """
    source_of = {f.id: f.source for f in findings}
    problems: dict[str, list[str]] = {}

    for model in {model for _, model in assessments}:
        edges = {fid: a.duplicate_of for (fid, m), a in assessments.items()
                 if m == model and a.duplicate_of}
        issues: list[str] = []

        for src, dst in sorted(edges.items()):
            if edges.get(dst) == src:
                if src < dst:  # report each mutual pair once
                    issues.append(f"mutual: {src} and {dst} each claim the other as the original")
            if (src in source_of and dst in source_of
                    and source_of[src] != source_of[dst]):
                issues.append(
                    f"cross-source: {src} ({source_of[src]}) claimed as duplicate of "
                    f"{dst} ({source_of[dst]})")

        # Longer cycles, excluding the mutual pairs already reported.
        for start in sorted(edges):
            seen, node = [], start
            while node in edges:
                if node in seen:
                    cycle = seen[seen.index(node):]
                    if len(cycle) > 2 and start == min(cycle):
                        issues.append("cycle: " + " -> ".join(cycle + [node]))
                    break
                seen.append(node)
                node = edges[node]

        if issues:
            problems[model] = issues
    return problems


def render_claim_validation() -> str:
    findings = load_findings()
    problems = duplicate_graph_problems(latest_assessments(), findings)
    if not problems:
        return ""
    lines = ["### Automatic claim-set validation", "",
             "Individually well-formed claims that contradict each other as a set. Found by the "
             "tool before any human review.", ""]
    for model in sorted(problems):
        lines.append(f"**`{model}`**")
        lines += [f"- {issue}" for issue in problems[model]]
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- accuracy

def accuracy_by_model() -> dict[str, dict]:
    """Counts per model. Deliberately counts 'unreviewed' too.

    A table that silently drops unreviewed claims would let a model look accurate because
    only its easy claims were checked. The denominator has to be honest.
    """
    assessments = latest_assessments()
    reviews = latest_reviews()
    # Only count claims about findings that are still in the current set. A new scan replaces
    # the findings, and assessments left over from a previous scan would otherwise pad the
    # denominator with claims about findings this report no longer contains.
    current = {f.id for f in load_findings()}
    stats: dict[str, dict] = {}
    for (finding_id, model), assessment in assessments.items():
        if current and finding_id not in current:
            continue
        entry = stats.setdefault(model, {v: 0 for v in VERDICTS} | {
            "total": 0, "hallucinated_refs": 0, "escalations": 0, "de_escalations": 0,
            "duplicate_claims": 0, "reproduced": 0})
        entry["total"] += 1
        if assessment.duplicate_of:
            entry["duplicate_claims"] += 1
        review = reviews.get((finding_id, model))
        entry[review.verdict if review else "unverified"] += 1
        if review and review.basis == "reproduced":
            entry["reproduced"] += 1
        if assessment.raw.get("hallucinated_reference"):
            entry["hallucinated_refs"] += 1
        delta = assessment.raw.get("severity_delta", 0)
        if delta > 0:
            entry["escalations"] += 1
        elif delta < 0:
            entry["de_escalations"] += 1
    return stats


def reviewers() -> set[str]:
    """Who owns the verdicts that currently COUNT.

    Uses the latest verdict per claim, not every verdict ever recorded: once a second reviewer
    supersedes an earlier one, the table should name the reviewer whose verdict it is
    reporting, not everyone who has ever touched the file.
    """
    return {r.reviewer for r in latest_reviews().values() if r.reviewer}


def render_accuracy() -> str:
    stats = accuracy_by_model()
    if not stats:
        return "_No assessments recorded yet. Run `cli.py m2 analyse`._"

    who = reviewers()
    provenance = []
    if any("assistant" in r.lower() or "claude" in r.lower() or "ai" in r.lower() for r in who):
        provenance = [
            "> **Who recorded these verdicts.** Some or all were recorded by an AI assistant, "
            "not by an independent human reviewer. They are listed below. This module argues "
            "that AI output must be validated by a person; a table that quietly let an AI fill "
            "that role would refute its own thesis. Treat these rows as a worked demonstration "
            "of the review process, not as independent verification.",
            "",
            "Reviewers: " + ", ".join(f"`{r}`" for r in sorted(who)),
            "",
        ]
    elif who:
        provenance = ["Reviewers: " + ", ".join(f"`{r}`" for r in sorted(who)), ""]

    lines = ["### AI triage accuracy, by model", "", *provenance,
             "Every row is a count of **claims a human checked by hand**. `unverified` is shown "
             "rather than hidden: a table that drops unchecked claims lets a model look accurate "
             "because only its easy claims were reviewed.", "",
             "| Model | Claims | Correct | Wrong | Overconfident | Unverified | Verdicts backed by reproduction | Called duplicate | Invented IDs | Escalated |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for model in sorted(stats):
        s = stats[model]
        checked = s["correct"] + s["wrong"] + s["overconfident"]
        rate = f"{100 * s['correct'] / checked:.0f}%" if checked else "–"
        lines.append(
            f"| `{model}` | {s['total']} | {s['correct']} ({rate}) | {s['wrong']} | "
            f"{s['overconfident']} | {s['unverified']} | {s['reproduced']} | "
            f"{s['duplicate_claims']}/{s['total']} | "
            f"{s['hallucinated_refs']} | {s['escalations']} |")
    lines += ["", "*Verdicts backed by reproduction* counts verdicts the reviewer reached by "
                  "checking the finding against the live target rather than judging from the "
                  "scanner evidence alone. A verdict and a reproduction are not the same "
                  "evidence.",
              "", "*Correct %* is over claims actually reviewed, not over all claims. "
                  "*Invented IDs* counts duplicate references to findings that do not exist — "
                  "caught automatically, not by the reviewer.",
              "", render_claim_validation()]
    return "\n".join(l for l in lines if l is not None)
