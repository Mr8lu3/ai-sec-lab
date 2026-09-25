"""Report assembly and the AI-vs-human comparison that is the module's whole point."""
import pytest

from aisec.m2.models import Finding, Review
from aisec.m2 import review as review_mod
from aisec.m2 import verify as verify_mod
from aisec.m2.verify import Verification
from aisec.m3 import draft as draft_mod
from aisec.m3 import report as report_mod
from aisec.m3.draft import SECTIONS, parse_markdown, to_markdown


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(review_mod.config, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(review_mod, "FINDINGS_PATH", tmp_path / "f.jsonl")
    monkeypatch.setattr(review_mod, "ASSESSMENTS_PATH", tmp_path / "a.jsonl")
    monkeypatch.setattr(review_mod, "REVIEWS_PATH", tmp_path / "r.jsonl")
    monkeypatch.setattr(report_mod.config, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(report_mod, "DRAFTS_DIR", tmp_path / "drafts")
    monkeypatch.setattr(report_mod, "FINAL_DIR", tmp_path / "final")
    monkeypatch.setattr(report_mod, "REPORT_PATH", tmp_path / "report.md")
    monkeypatch.setattr(report_mod, "DIFF_PATH", tmp_path / "diff.md")
    monkeypatch.setattr(verify_mod.config, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(verify_mod, "VERIFICATION_PATH", tmp_path / "v.jsonl")
    return tmp_path


def _confirm(fid, conclusion="confirmed"):
    verify_mod.save_verification(Verification(fid, "http-get", conclusion, "detail"))


def _finding(fid="zap-1", severity="medium"):
    return Finding(id=fid, source="zap", title=f"Issue {fid}", severity=severity,
                   target="http://x.test")


SAMPLE = {"description": "Desc.", "impact": "Impact.", "remediation": "Fix it."}


# ---------------------------------------------------------------- markdown contract

def test_markdown_round_trips_all_sections():
    parsed = parse_markdown(to_markdown(_finding(), SAMPLE))
    assert parsed == SAMPLE


def test_parsing_tolerates_heading_case_and_blank_lines():
    """A human editing prose must not be able to break the report with formatting."""
    text = "# T\n\n## DESCRIPTION\n\nOne.\n\n\n## Impact\nTwo.\n\n## remediation\nThree.\n"
    parsed = parse_markdown(text)
    assert parsed["description"] == "One." and parsed["impact"] == "Two."
    assert parsed["remediation"] == "Three."


def test_unknown_headings_are_ignored_not_merged():
    text = "## Description\nKeep.\n\n## Notes to self\nDrop.\n\n## Impact\nAlso keep.\n"
    parsed = parse_markdown(text)
    assert parsed["description"] == "Keep." and parsed["impact"] == "Also keep."
    assert "Drop." not in parsed["description"]


def test_draft_schema_has_no_severity_field():
    """The model writes prose; it does not get to re-rate a finding. Severity comes from the
    scanner and the human."""
    assert "severity" not in draft_mod.DRAFT_SCHEMA["properties"]
    assert set(draft_mod.DRAFT_SCHEMA["properties"]) == set(SECTIONS)


def test_draft_prompt_carries_confirmed_severity_but_forbids_restating_it():
    prompt = draft_mod.build_prompt(_finding(severity="low"))
    assert "Severity (confirmed): low" in prompt
    assert "Do not state a severity rating" in draft_mod.DRAFT_SYSTEM


# ---------------------------------------------------------------- verification gate

def test_only_reproduced_findings_reach_the_report(isolated):
    review_mod.save_findings([_finding("zap-1"), _finding("zap-2")])
    _confirm("zap-1")
    keep, notes = report_mod.verified_findings()
    assert [f.id for f in keep] == ["zap-1"]
    assert any("zap-2" in n and "not reproduced" in n for n in notes)


def test_findings_reproduction_contradicts_are_excluded(isolated):
    """The Bypassing 403 case: the scanner said 200, reproduction showed the app's catch-all
    page. A report must not carry a finding that testing disproved."""
    review_mod.save_findings([_finding("zap-1")])
    _confirm("zap-1", "false_positive")
    keep, notes = report_mod.verified_findings(include_unverified=True)
    assert keep == []
    assert any("reproduction contradicts" in n for n in notes)


def test_a_confirmed_finding_is_reported_even_if_the_ai_claim_was_wrong(isolated):
    """Regression: inclusion used to be gated on the human's verdict about the MODEL, so a
    reproduced finding the model described badly was dropped from the report. 'The AI was
    wrong about this' is not evidence that a finding does not exist."""
    review_mod.save_findings([_finding("zap-1")])
    _confirm("zap-1")
    review_mod.save_review(Review("zap-1", "m", "wrong"))
    keep, _ = report_mod.verified_findings()
    assert [f.id for f in keep] == ["zap-1"]


def test_include_unverified_flags_each_one_in_the_notes(isolated):
    review_mod.save_findings([_finding("zap-1")])
    keep, notes = report_mod.verified_findings(include_unverified=True)
    assert len(keep) == 1
    assert any("INCLUDED WITHOUT REPRODUCTION" in n for n in notes)


# ---------------------------------------------------------------- draft/final separation

def test_seed_final_never_overwrites_human_edits(isolated):
    finding = _finding()
    report_mod.write_draft(finding, SAMPLE)
    assert report_mod.seed_final(finding, SAMPLE) is True
    (report_mod.FINAL_DIR / f"{finding.id}.md").write_text(
        to_markdown(finding, {**SAMPLE, "impact": "EDITED"}), encoding="utf-8")
    assert report_mod.seed_final(finding, SAMPLE) is False
    final = parse_markdown((report_mod.FINAL_DIR / f"{finding.id}.md").read_text(encoding="utf-8"))
    assert final["impact"] == "EDITED"


def test_edit_stats_detects_which_sections_changed(isolated):
    finding = _finding()
    report_mod.write_draft(finding, SAMPLE)
    report_mod.seed_final(finding, SAMPLE)
    assert report_mod.edit_stats(finding.id)["any_changed"] is False
    (report_mod.FINAL_DIR / f"{finding.id}.md").write_text(
        to_markdown(finding, {**SAMPLE, "impact": "Much more precise impact."}), encoding="utf-8")
    stats = report_mod.edit_stats(finding.id)
    assert stats["impact"]["changed"] is True
    assert stats["description"]["changed"] is False
    assert stats["any_changed"] is True


# ---------------------------------------------------------------- assembly

def test_report_orders_findings_by_severity(isolated):
    findings = [_finding("zap-low", "low"), _finding("zap-high", "high"),
                _finding("zap-med", "medium")]
    review_mod.save_findings(findings)
    for finding in findings:
        _confirm(finding.id)
        report_mod.write_draft(finding, SAMPLE)
        report_mod.seed_final(finding, SAMPLE)
    text = report_mod.build_report()
    assert text.index("Issue zap-high") < text.index("Issue zap-med") < text.index("Issue zap-low")


def test_report_lists_excluded_findings_in_an_appendix(isolated):
    review_mod.save_findings([_finding("zap-1"), _finding("zap-2")])
    _confirm("zap-1")
    _confirm("zap-2", "false_positive")
    report_mod.write_draft(_finding("zap-1"), SAMPLE)
    report_mod.seed_final(_finding("zap-1"), SAMPLE)
    text = report_mod.build_report()
    assert "Appendix A" in text and "zap-2" in text


def test_report_is_valid_with_no_verified_findings(isolated):
    review_mod.save_findings([_finding("zap-1")])
    text = report_mod.build_report()
    assert "No verified findings" in text and "| **Total** | **0** |" in text


def test_diff_reports_how_many_drafts_needed_editing(isolated):
    for fid, edited in [("zap-1", True), ("zap-2", False)]:
        finding = _finding(fid)
        review_mod.save_findings(review_mod.load_findings() + [finding])
        _confirm(fid)
        report_mod.write_draft(finding, SAMPLE)
        report_mod.seed_final(finding, SAMPLE)
        if edited:
            (report_mod.FINAL_DIR / f"{fid}.md").write_text(
                to_markdown(finding, {**SAMPLE, "impact": "Corrected."}), encoding="utf-8")
    text = report_mod.build_diff()
    assert "**1 of 2 drafts required human edits.**" in text
    assert "```diff" in text and "Corrected." in text
