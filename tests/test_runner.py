"""Results aggregation. Bugs here would misreport the security posture, so it is tested
independently of any model."""
from aisec.m1 import runner


def _record(attack_id, config_name, model, succeeded, timestamp, error="", blocked=False):
    return {"attack_id": attack_id, "config": config_name, "model": model,
            "attack_succeeded": succeeded, "timestamp": timestamp, "error": error,
            "blocked": blocked}


def test_latest_by_key_keeps_the_most_recent_run():
    """Re-running one attack should replace its old verdict, not double-count it."""
    records = [
        _record("di-01", "baseline", "m", True, "2026-09-01T00:00:00"),
        _record("di-01", "baseline", "m", False, "2026-09-02T00:00:00"),
    ]
    latest = runner.latest_by_key(records)
    assert len(latest) == 1
    assert latest[("di-01", "baseline", "m")]["attack_succeeded"] is False


def test_latest_by_key_separates_configs_and_models():
    records = [
        _record("di-01", "baseline", "m1", True, "2026-09-01T00:00:00"),
        _record("di-01", "d1", "m1", False, "2026-09-01T00:00:00"),
        _record("di-01", "baseline", "m2", True, "2026-09-01T00:00:00"),
    ]
    assert len(runner.latest_by_key(records)) == 3


def test_render_matrix_distinguishes_vulnerable_blocked_and_failed():
    """The three outcomes must stay distinct.

    Collapsing 'failed' into 'blocked' would credit a defence with an outcome it had nothing
    to do with - and at baseline, where no defence is enabled, it would be simply false.
    """
    records = [
        _record("di-01", "baseline", "m", True, "2026-09-01T00:00:00"),
        _record("di-01", "d1", "m", False, "2026-09-01T00:00:00", blocked=True),
        _record("di-01", "d2", "m", False, "2026-09-01T00:00:00", blocked=False),
    ]
    row = next(l for l in runner.render_matrix(records, "m").splitlines() if "`di-01`" in l)
    cells = [c.strip() for c in row.split("|")]
    assert "**VULNERABLE**" in cells
    assert "blocked" in cells
    assert "failed" in cells


def test_unblocked_failure_at_baseline_is_never_called_blocked():
    """Regression: an attack the model simply did not carry out was rendered as 'blocked'
    even with zero defences active, which inflated the baseline effectiveness number."""
    records = [_record("di-04", "baseline", "m", False, "2026-09-01T00:00:00", blocked=False)]
    row = next(l for l in runner.render_matrix(records, "m").splitlines() if "`di-04`" in l)
    assert "failed" in row and "blocked" not in row


def test_render_matrix_shows_a_dash_for_runs_that_never_happened():
    table = runner.render_matrix([_record("di-01", "baseline", "m", True, "2026-09-01T00:00:00")], "m")
    row = next(line for line in table.splitlines() if "`di-01`" in line)
    assert row.count("–") >= 3, "configs with no data should be blank, not counted as blocked"


def test_errored_runs_are_excluded_from_the_summary():
    """An unreachable model must not be scored as a successful defence."""
    records = [
        _record("di-01", "baseline", "m", False, "2026-09-01T00:00:00", error="timeout"),
        _record("di-02", "baseline", "m", True, "2026-09-01T00:00:00"),
    ]
    assert "| 1/1 | 0 | 0 |" in runner.render_matrix(records, "m")


def test_refused_tool_call_counts_as_a_defence_stopping_the_attack():
    """Regression: D2 refuses an individual tool call rather than aborting the run, so
    `blocked` stays False. Counting only `blocked` credited D2's refusals to the
    'failed on their own' column and understated the defence that closed tool misuse."""
    record = _record("tm-01", "d2", "m", False, "2026-09-01T00:00:00", blocked=False)
    record["tool_calls"] = [{"tool": "read_file", "args": {}, "allowed": False}]
    assert runner.was_defended(record)
    row = next(l for l in runner.render_matrix([record], "m").splitlines() if "`tm-01`" in l)
    assert "blocked" in row and "failed" not in row


def test_run_with_only_allowed_tool_calls_is_not_counted_as_defended():
    record = _record("tm-01", "baseline", "m", False, "2026-09-01T00:00:00", blocked=False)
    record["tool_calls"] = [{"tool": "read_file", "args": {}, "allowed": True}]
    assert not runner.was_defended(record)


def test_summary_separates_defended_from_self_failed():
    records = [
        _record("di-01", "d1", "m", True, "2026-09-01T00:00:00"),
        _record("di-02", "d1", "m", False, "2026-09-01T00:00:00", blocked=True),
        _record("di-03", "d1", "m", False, "2026-09-01T00:00:00", blocked=False),
    ]
    table = runner.render_matrix(records, "m")
    assert "| 1/3 | 1 | 1 |" in table, "one succeeded, one defended, one failed by itself"


def test_render_matrix_includes_framework_columns():
    table = runner.render_matrix([_record("di-01", "baseline", "m", True, "2026-09-01T00:00:00")], "m")
    assert "OWASP" in table and "ATLAS" in table and "AML.T0051.000" in table
