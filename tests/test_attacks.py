"""The attack table is data, and wrong data silently produces a wrong report.

These tests enforce the integrity rules the write-up depends on: every attack is mapped,
every mapping is well-formed, and the payloads genuinely target only local fixtures.
"""
import re

import pytest

from aisec.m1 import attacks as attack_mod
from aisec.m1 import defences, oracles
from aisec.m1.attacks import ATTACKS

# Verified against published sources - see docs/MAPPING.md.
VALID_OWASP = {
    "LLM01:2025", "LLM02:2025", "LLM03:2025", "LLM04:2025", "LLM05:2025",
    "LLM06:2025", "LLM07:2025", "LLM08:2025", "LLM09:2025", "LLM10:2025",
}
ATLAS_PATTERN = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


def test_attack_ids_are_unique():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))


def test_suite_covers_every_category_and_both_targets():
    covered = {a.category for a in ATTACKS}
    assert covered == set(attack_mod.CATEGORIES)
    assert {a.target for a in ATTACKS} == set(attack_mod.TARGETS)


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_every_attack_is_fully_mapped(attack):
    """No attack ships without both framework IDs - the results table claims these."""
    assert attack.owasp in VALID_OWASP, f"{attack.id}: bad OWASP id {attack.owasp!r}"
    assert ATLAS_PATTERN.match(attack.atlas), f"{attack.id}: bad ATLAS id {attack.atlas!r}"


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_every_attack_is_runnable_and_explained(attack):
    assert attack.oracle in oracles.ORACLES
    assert attack.category in attack_mod.CATEGORIES
    assert attack.target in attack_mod.TARGETS
    assert attack.payload.strip(), "an attack needs a payload"
    assert len(attack.rationale) > 30, "each attack must justify why it is a distinct test"


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_indirect_attacks_actually_plant_something(attack):
    """An indirect injection with no planted content is really a direct one, mislabelled."""
    if attack.category == "indirect_injection":
        assert attack.planted_doc or attack.planted_email
    else:
        assert not attack.planted_doc and not attack.planted_email


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_agent_only_oracles_are_not_used_against_the_chatbot(attack):
    tool_oracles = {"email_sent", "email_sent_externally", "sandbox_escaped"}
    if attack.oracle in tool_oracles:
        assert attack.target == "agent", f"{attack.id}: tool oracle on a target with no tools"


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_payloads_only_reference_reserved_test_domains(attack):
    """Scope control. Every domain in every payload must be RFC 2606 .test/.example, so the
    suite cannot be pointed at a real system by copy-paste."""
    blob = f"{attack.payload} {attack.planted_doc} {attack.planted_email.get('body', '')}"
    for domain in re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", blob):
        assert domain.endswith((".test", ".example")), f"{attack.id}: real-looking domain {domain}"


def test_subset_is_a_genuine_subset_covering_all_categories():
    subset = attack_mod.subset()
    assert 0 < len(subset) < len(ATTACKS)
    assert {a.category for a in subset} == set(attack_mod.CATEGORIES)
    assert {a.target for a in subset} == set(attack_mod.TARGETS)


def test_by_id_round_trips_and_rejects_unknown_ids():
    assert attack_mod.by_id("di-01").id == "di-01"
    with pytest.raises(KeyError):
        attack_mod.by_id("nope-99")


def test_every_config_named_in_the_runner_has_a_label():
    assert set(defences.CONFIGS) <= set(defences.CONFIG_LABELS)
