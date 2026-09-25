"""Triage validation and the accuracy scoring that qualifies every Module 2 claim."""
import pytest

from aisec.m2 import analyse, review as review_mod
from aisec.m2.models import Assessment, Finding, Review


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point the store at a temp dir so tests never touch real results."""
    monkeypatch.setattr(review_mod.config, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(review_mod, "FINDINGS_PATH", tmp_path / "f.jsonl")
    monkeypatch.setattr(review_mod, "ASSESSMENTS_PATH", tmp_path / "a.jsonl")
    monkeypatch.setattr(review_mod, "REVIEWS_PATH", tmp_path / "r.jsonl")
    return tmp_path


def _finding(fid, severity="medium"):
    return Finding(id=fid, source="zap", title=f"t-{fid}", severity=severity, target="http://x.test")


# ---------------------------------------------------------------- duplicate validation

def test_none_variants_are_treated_as_no_duplicate():
    findings = [_finding("zap-1"), _finding("zap-2")]
    for claimed in ["none", "None", "", "n/a", "-", "null"]:
        assert analyse.validate_duplicate_ref(claimed, findings, "zap-1") == ("", "")


def test_valid_duplicate_reference_is_accepted():
    findings = [_finding("zap-1"), _finding("zap-2")]
    value, problem = analyse.validate_duplicate_ref("zap-2", findings, "zap-1")
    assert value == "zap-2" and not problem


def test_invented_finding_id_is_rejected_and_flagged():
    """Small models invent plausible identifiers. An invented id in a report is exactly the
    error that destroys confidence in AI-assisted triage, so it is caught automatically."""
    findings = [_finding("zap-1")]
    value, problem = analyse.validate_duplicate_ref("zap-deadbeef", findings, "zap-1")
    assert value == "" and "not a finding id" in problem


def test_self_reference_is_rejected():
    findings = [_finding("zap-1")]
    value, problem = analyse.validate_duplicate_ref("zap-1", findings, "zap-1")
    assert value == "" and "duplicates itself" in problem


@pytest.mark.parametrize("scanner,model,expected", [
    ("low", "high", 2), ("high", "low", -2), ("medium", "medium", 0),
    ("informational", "critical", 4), ("medium", "", 0), ("", "high", 0),
])
def test_severity_delta_measures_escalation(scanner, model, expected):
    assert analyse.severity_delta(scanner, model) == expected


def test_prompt_lists_other_findings_but_not_the_current_one():
    """The catalogue gives duplicate_of something real to point at, and must exclude the
    finding under assessment so the model cannot trivially claim it duplicates itself."""
    findings = [Finding(id="zap-1", source="zap", title="Alpha", severity="medium", target="t"),
                Finding(id="zap-2", source="zap", title="Beta", severity="medium", target="t")]
    prompt = analyse.build_prompt(findings[0], findings)
    catalogue = prompt.split("Finding to assess:")[0]
    assert "zap-2" in catalogue and "Beta" in catalogue
    assert "zap-1" not in catalogue, "the finding under assessment must not list itself"


# ---------------------------------------------------------------- storage

def test_findings_round_trip(isolated):
    review_mod.save_findings([_finding("zap-1"), _finding("zap-2")])
    assert [f.id for f in review_mod.load_findings()] == ["zap-1", "zap-2"]


def test_saving_findings_replaces_rather_than_appends(isolated):
    """A new scan supersedes the old one; appending would silently mix two scans."""
    review_mod.save_findings([_finding("zap-1")])
    review_mod.save_findings([_finding("zap-2")])
    assert [f.id for f in review_mod.load_findings()] == ["zap-2"]


def test_latest_assessment_wins(isolated):
    review_mod.save_assessment(Assessment("zap-1", "m", severity="low"))
    review_mod.save_assessment(Assessment("zap-1", "m", severity="high"))
    latest = review_mod.latest_assessments()
    assert len(latest) == 1 and latest[("zap-1", "m")].severity == "high"


def test_assessments_are_kept_separate_per_model(isolated):
    review_mod.save_assessment(Assessment("zap-1", "model-a"))
    review_mod.save_assessment(Assessment("zap-1", "model-b"))
    assert len(review_mod.latest_assessments()) == 2
    assert len(review_mod.latest_assessments("model-a")) == 1


def test_invalid_verdict_is_rejected(isolated):
    with pytest.raises(ValueError, match="unknown verdict"):
        review_mod.save_review(Review("zap-1", "m", "probably-fine"))


def test_pending_excludes_reviewed_claims(isolated):
    review_mod.save_findings([_finding("zap-1"), _finding("zap-2")])
    review_mod.save_assessment(Assessment("zap-1", "m"))
    review_mod.save_assessment(Assessment("zap-2", "m"))
    assert len(review_mod.pending("m")) == 2
    review_mod.save_review(Review("zap-1", "m", "correct"))
    assert [f.id for f, _ in review_mod.pending("m")] == ["zap-2"]


# ---------------------------------------------------------------- accuracy

def test_accuracy_counts_unverified_in_the_denominator(isolated):
    """A table that hides unchecked claims lets a model look accurate because only its easy
    claims were reviewed."""
    review_mod.save_findings([_finding("zap-1"), _finding("zap-2")])
    review_mod.save_assessment(Assessment("zap-1", "m"))
    review_mod.save_assessment(Assessment("zap-2", "m"))
    review_mod.save_review(Review("zap-1", "m", "correct"))
    stats = review_mod.accuracy_by_model()["m"]
    assert stats["total"] == 2 and stats["correct"] == 1 and stats["unverified"] == 1


def test_correct_percentage_is_over_reviewed_claims_only(isolated):
    review_mod.save_findings([_finding(f"zap-{i}") for i in range(4)])
    for i in range(4):
        review_mod.save_assessment(Assessment(f"zap-{i}", "m"))
    review_mod.save_review(Review("zap-0", "m", "correct"))
    review_mod.save_review(Review("zap-1", "m", "wrong"))
    table = review_mod.render_accuracy()
    assert "1 (50%)" in table, "1 correct of 2 reviewed, not of 4 claimed"


def test_accuracy_counts_invented_ids_and_escalations(isolated):
    review_mod.save_findings([_finding("zap-1")])
    review_mod.save_assessment(Assessment(
        "zap-1", "m", raw={"hallucinated_reference": "claimed duplicate_of='nope'",
                           "severity_delta": 2}))
    stats = review_mod.accuracy_by_model()["m"]
    assert stats["hallucinated_refs"] == 1 and stats["escalations"] == 1


def test_stale_assessments_from_a_previous_scan_are_not_counted(isolated):
    """A new scan replaces the finding set. Claims about findings that no longer exist must
    not pad the denominator of the accuracy table."""
    review_mod.save_findings([_finding("zap-current")])
    review_mod.save_assessment(Assessment("zap-current", "m"))
    review_mod.save_assessment(Assessment("zap-from-old-scan", "m"))
    stats = review_mod.accuracy_by_model()["m"]
    assert stats["total"] == 1


def test_accuracy_table_is_empty_but_valid_with_no_data(isolated):
    assert "No assessments recorded yet" in review_mod.render_accuracy()


# ---------------------------------------------------------------- claim-set validation

def _assessments(pairs, model="m"):
    """pairs: {finding_id: duplicate_of}"""
    return {(fid, model): Assessment(fid, model, duplicate_of=dup)
            for fid, dup in pairs.items()}


def _findings_from(sources):
    return [Finding(id=fid, source=src, title=fid, severity="low", target="t")
            for fid, src in sources.items()]


def test_mutual_duplicate_claims_are_detected():
    """A says it duplicates B while B says it duplicates A. Both cannot be the original, so
    at least one claim is wrong - and neither is individually malformed."""
    from aisec.m2.review import duplicate_graph_problems
    problems = duplicate_graph_problems(
        _assessments({"zap-a": "zap-b", "zap-b": "zap-a"}),
        _findings_from({"zap-a": "zap", "zap-b": "zap"}))
    assert len(problems["m"]) == 1 and "mutual" in problems["m"][0]


def test_longer_duplicate_cycles_are_detected():
    from aisec.m2.review import duplicate_graph_problems
    problems = duplicate_graph_problems(
        _assessments({"zap-a": "zap-b", "zap-b": "zap-c", "zap-c": "zap-a"}),
        _findings_from({"zap-a": "zap", "zap-b": "zap", "zap-c": "zap"}))
    assert any("cycle" in issue for issue in problems["m"])


def test_cross_source_duplicate_claims_are_flagged():
    """An open port reported by nmap is not the same issue as a missing header from ZAP."""
    from aisec.m2.review import duplicate_graph_problems
    problems = duplicate_graph_problems(
        _assessments({"nmap-a": "zap-b"}),
        _findings_from({"nmap-a": "nmap", "zap-b": "zap"}))
    assert any("cross-source" in issue for issue in problems["m"])


def test_a_coherent_chain_raises_no_problems():
    """A -> B -> C is a legitimate claim shape and must not be flagged."""
    from aisec.m2.review import duplicate_graph_problems
    problems = duplicate_graph_problems(
        _assessments({"zap-a": "zap-b", "zap-b": "zap-c"}),
        _findings_from({"zap-a": "zap", "zap-b": "zap", "zap-c": "zap"}))
    assert problems == {}


def test_no_duplicate_claims_means_no_problems():
    from aisec.m2.review import duplicate_graph_problems
    assert duplicate_graph_problems(
        _assessments({"zap-a": "", "zap-b": ""}),
        _findings_from({"zap-a": "zap", "zap-b": "zap"})) == {}


def test_models_are_validated_independently():
    from aisec.m2.review import duplicate_graph_problems
    assessments = {}
    assessments.update(_assessments({"zap-a": "zap-b", "zap-b": "zap-a"}, model="bad"))
    assessments.update(_assessments({"zap-a": "zap-b"}, model="good"))
    problems = duplicate_graph_problems(
        assessments, _findings_from({"zap-a": "zap", "zap-b": "zap"}))
    assert "bad" in problems and "good" not in problems


def test_duplicate_reference_is_rendered_with_its_title():
    """Regression: the review prompt printed a bare finding id for a duplicate claim. A
    reviewer cannot judge 'this duplicates zap-6b914d64' without being told what that finding
    is, so the tool was asking for a verdict while withholding what it was about."""
    from aisec.m2.review import describe_finding
    findings = [Finding(id="zap-1", source="zap", title="COEP Header Missing",
                        severity="low", target="http://x.test/")]
    rendered = describe_finding("zap-1", findings)
    assert "COEP Header Missing" in rendered and "zap/low" in rendered


def test_unknown_duplicate_reference_says_so_plainly():
    from aisec.m2.review import describe_finding
    assert "no such finding" in describe_finding("zap-ghost", [])


def test_redo_reopens_already_reviewed_claims(isolated):
    """A second reviewer must be able to record their own verdict. Append-only storage means
    the earlier verdict survives in the file as a record of who thought what."""
    review_mod.save_findings([_finding("zap-1")])
    review_mod.save_assessment(Assessment("zap-1", "m"))
    review_mod.save_review(Review("zap-1", "m", "correct", reviewer="first"))
    assert review_mod.pending("m") == []
    assert len(review_mod.pending("m", include_reviewed=True)) == 1


def test_a_later_verdict_supersedes_an_earlier_one(isolated):
    review_mod.save_findings([_finding("zap-1")])
    review_mod.save_assessment(Assessment("zap-1", "m"))
    review_mod.save_review(Review("zap-1", "m", "correct", reviewer="first"))
    review_mod.save_review(Review("zap-1", "m", "wrong", reviewer="second"))
    latest = review_mod.latest_reviews()[("zap-1", "m")]
    assert latest.verdict == "wrong" and latest.reviewer == "second"
    assert len(review_mod.load_reviews()) == 2, "the earlier verdict is kept as a record"


def test_reviewers_names_only_whoever_owns_the_current_verdict(isolated):
    """Once superseded, an earlier reviewer should not still be credited in the table."""
    review_mod.save_findings([_finding("zap-1")])
    review_mod.save_assessment(Assessment("zap-1", "m"))
    review_mod.save_review(Review("zap-1", "m", "correct", reviewer="ai-assistant"))
    review_mod.save_review(Review("zap-1", "m", "wrong", reviewer="human"))
    assert review_mod.reviewers() == {"human"}


def test_basis_values_are_prefix_unambiguous():
    """The review prompt accepts an unambiguous prefix (e.g. 'rep' -> 'reproduced') and
    re-prompts otherwise. That only works if no basis is a prefix of another."""
    from aisec.m2.models import BASES
    for a in BASES:
        for b in BASES:
            if a != b:
                assert not b.startswith(a), f"{b!r} starts with {a!r}; prefix entry is ambiguous"
