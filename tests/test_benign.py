"""The benign suite is the control group. If its logic is wrong, the false-positive numbers
that qualify every defence claim are wrong too."""
import pytest

from aisec.m1 import benign as benign_mod
from aisec.m1.benign import BENIGN_TASKS, BenignTask, evaluate_benign
from aisec.m1.types import TargetRun, ToolCall

TASK = BenignTask(id="t", name="t", target="chatbot", payload="q", expect_any=("25 days",))
AGENT_TASK = BenignTask(id="t", name="t", target="agent", payload="q",
                        expect_any=("done",), expect_tool="send_email")


def test_answered_when_expected_content_present():
    outcome, _ = evaluate_benign(TASK, TargetRun(output="You get 25 days plus bank holidays."))
    assert outcome == "answered"


def test_matching_is_case_insensitive():
    assert evaluate_benign(
        BenignTask("t", "t", "chatbot", "q", ("ACHEBE",)),
        TargetRun(output="Approved by Dawn Achebe."))[0] == "answered"


def test_blocked_is_reported_as_a_false_positive():
    """A defence refusing legitimate work is the number that makes it expensive to deploy."""
    outcome, evidence = evaluate_benign(
        TASK, TargetRun(blocked=True, block_reason="D3 output judge: too vague"))
    assert outcome == "blocked" and "FALSE POSITIVE" in evidence


def test_missed_when_answer_lacks_the_expected_fact():
    outcome, _ = evaluate_benign(TASK, TargetRun(output="I don't know."))
    assert outcome == "missed"


def test_missed_is_distinct_from_blocked():
    """Model weakness must not be counted as a defence false positive, for the same reason
    'failed on their own' is separated in the attack table."""
    assert evaluate_benign(TASK, TargetRun(output="no idea"))[0] == "missed"
    assert evaluate_benign(TASK, TargetRun(blocked=True, block_reason="x"))[0] == "blocked"


def test_agent_task_requires_the_expected_tool_to_have_run():
    no_call = TargetRun(output="done")
    assert evaluate_benign(AGENT_TASK, no_call)[0] == "missed"
    with_call = TargetRun(output="done", tool_calls=[ToolCall("send_email", {"to": "a@b.test"})])
    assert evaluate_benign(AGENT_TASK, with_call)[0] == "answered"


def test_refused_tool_call_does_not_count_as_the_tool_running():
    """D2 refusing the call means the legitimate task did not complete."""
    refused = TargetRun(output="done", tool_calls=[
        ToolCall("send_email", {"to": "a@b.test"}, allowed=False, refusal_reason="blocked")])
    assert evaluate_benign(AGENT_TASK, refused)[0] == "missed"


def test_errors_are_not_counted_as_false_positives():
    assert evaluate_benign(TASK, TargetRun(error="timeout"))[0] == "missed"


def test_task_ids_are_unique_and_both_targets_covered():
    ids = [t.id for t in BENIGN_TASKS]
    assert len(ids) == len(set(ids))
    assert {t.target for t in BENIGN_TASKS} == {"chatbot", "agent"}


@pytest.mark.parametrize("task", BENIGN_TASKS, ids=lambda t: t.id)
def test_every_benign_task_is_well_formed(task):
    assert task.payload.strip() and task.expect_any
    assert all(f.strip() for f in task.expect_any)
    assert len(task.rationale) > 20
    if task.target == "agent":
        assert task.expect_tool, "an agent task must name the tool it legitimately needs"


@pytest.mark.parametrize("task", BENIGN_TASKS, ids=lambda t: t.id)
def test_benign_payloads_are_not_attack_payloads(task):
    """The control group must be genuinely ordinary, not attacks in disguise."""
    from aisec.m1.attacks import ATTACKS
    assert task.payload not in {a.payload for a in ATTACKS}


def test_benign_answers_are_actually_present_in_the_corpus():
    """A task whose expected answer is not in the documents would score as a permanent
    'missed' and quietly understate how well the system works."""
    from aisec import config
    from aisec.m1 import retrieval
    blob = "\n".join(c.text for c in retrieval.load_corpus(config.CORPUS_DIR)).lower()
    for task in BENIGN_TASKS:
        if task.target != "chatbot":
            continue
        assert any(f.lower() in blob for f in task.expect_any), \
            f"{task.id}: none of {task.expect_any} appear in the corpus"


def test_by_id_round_trips_and_rejects_unknown():
    assert benign_mod.by_id("bn-01").id == "bn-01"
    with pytest.raises(KeyError):
        benign_mod.by_id("bn-99")


def test_first_step_schema_cannot_finish_the_task():
    """Regression: with one combined schema the agent selected the right tool and right args
    but set action='final_answer' and fabricated the result, so 32 attack runs executed zero
    tools and the agent target was effectively untested."""
    from aisec.m1.agent import ACTION_SCHEMA, FIRST_STEP_SCHEMA
    assert FIRST_STEP_SCHEMA["properties"]["action"]["enum"] == ["use_tool"]
    assert "final_answer" not in FIRST_STEP_SCHEMA["properties"]
    assert "none" not in FIRST_STEP_SCHEMA["properties"]["tool"]["enum"]
    # Later steps must still be able to finish, or the loop could never terminate early.
    assert "final_answer" in ACTION_SCHEMA["properties"]["action"]["enum"]


def test_agent_gets_a_larger_token_budget_than_a_chat_reply():
    """Regression: at the default 200 tokens phi4-mini truncated its tool-selection JSON
    mid-document, recording ERROR runs that are measurement artefacts rather than security
    results. The agent's JSON carries tool + args + final_answer and needs more room."""
    from aisec import config
    assert config.AGENT_NUM_PREDICT > config.NUM_PREDICT
