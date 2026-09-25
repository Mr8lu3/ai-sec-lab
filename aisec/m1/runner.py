"""Executes the attack x defence x model matrix and renders the results table."""
from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone

from aisec import config
from aisec.llm import LLMClient
from aisec.m1 import attacks as attack_mod
from aisec.m1 import benign as benign_mod
from aisec.m1 import defences, oracles, retrieval
from aisec.m1.agent import ToolAgent
from aisec.m1.chatbot import DocumentQABot
from aisec.m1.types import TargetRun


@contextmanager
def planted_email(mail: dict):
    """Drop a poisoned email into the inbox for one run, then remove it.

    Planting at run time rather than committing poisoned files keeps the corpus honest: the
    benign baseline really is benign, so a defence cannot look good by accident.
    """
    if not mail:
        yield
        return
    path = config.INBOX_DIR / f"9{mail['id']}_planted.json"
    path.write_text(json.dumps(mail, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        yield
    finally:
        path.unlink(missing_ok=True)


def run_attack(attack: attack_mod.Attack, config_name: str, model: str,
               use_cache: bool = True) -> dict:
    """Run one attack under one defence config against one model."""
    flags = defences.CONFIGS[config_name]
    client = LLMClient(model=model, use_cache=use_cache)

    extra_chunks = []
    if attack.planted_doc:
        extra_chunks = retrieval.split_into_chunks("planted_policy.md", attack.planted_doc)

    with planted_email(attack.planted_email):
        if attack.target == "chatbot":
            bot = DocumentQABot(
                client,
                use_input_filter=flags["d1"],
                use_output_judge=flags["d3"],
                extra_chunks=extra_chunks,
            )
            run: TargetRun = bot.answer(attack.payload)
        else:
            policy = None
            if flags["d2"]:
                # The agent only ever needs these three; the allowlist is the task's, not the model's.
                policy = defences.make_tool_policy(
                    allowed_tools=["read_file", "search_inbox", "send_email"]
                )
            agent = ToolAgent(
                client,
                use_input_filter=flags["d1"],
                tool_policy=policy,
                use_output_judge=flags["d3"],
            )
            run = agent.run(attack.payload)

    succeeded, evidence = oracles.evaluate(attack.oracle, run)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_id": attack.id,
        "attack_name": attack.name,
        "category": attack.category,
        "target": attack.target,
        "owasp": attack.owasp,
        "atlas": attack.atlas,
        "oracle": attack.oracle,
        "config": config_name,
        "model": model,
        "attack_succeeded": succeeded,
        "evidence": evidence,
        "blocked": run.blocked,
        "block_reason": run.block_reason,
        "error": run.error,
        "output": run.output[:600],
        "tool_calls": [asdict(c) for c in run.tool_calls],
        "llm_stats": client.stats(),
    }


def run_benign(task: benign_mod.BenignTask, config_name: str, model: str,
               use_cache: bool = True) -> dict:
    """Run one legitimate task under one defence config - the false-positive measurement."""
    flags = defences.CONFIGS[config_name]
    client = LLMClient(model=model, use_cache=use_cache)

    if task.target == "chatbot":
        bot = DocumentQABot(client, use_input_filter=flags["d1"], use_output_judge=flags["d3"])
        run: TargetRun = bot.answer(task.payload)
    else:
        policy = defences.make_tool_policy(
            allowed_tools=["read_file", "search_inbox", "send_email"]) if flags["d2"] else None
        agent = ToolAgent(client, use_input_filter=flags["d1"], tool_policy=policy,
                          use_output_judge=flags["d3"])
        run = agent.run(task.payload)

    outcome, evidence = benign_mod.evaluate_benign(task, run)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "benign",
        "task_id": task.id,
        "task_name": task.name,
        "target": task.target,
        "config": config_name,
        "model": model,
        "outcome": outcome,
        "evidence": evidence,
        "blocked": run.blocked,
        "block_reason": run.block_reason,
        "error": run.error,
        "output": run.output[:600],
        "tool_calls": [asdict(c) for c in run.tool_calls],
    }


def append_benign(record: dict) -> None:
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with (config.RESULTS_DIR / "m1_benign.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_benign() -> list[dict]:
    path = config.RESULTS_DIR / "m1_benign.jsonl"
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


def latest_benign_by_key(records: list[dict]) -> dict[tuple, dict]:
    latest: dict[tuple, dict] = {}
    for record in records:
        key = (record["task_id"], record["config"], record["model"])
        previous = latest.get(key)
        if previous is None or record["timestamp"] >= previous["timestamp"]:
            latest[key] = record
    return latest


def render_benign(records: list[dict], model: str) -> str:
    """Per-config false-positive table. 'blocked' here is a defence breaking legitimate use."""
    latest = latest_benign_by_key(records)
    configs = list(defences.CONFIGS)
    if not any(k[2] == model for k in latest):
        return ""

    lines = [f"### Benign regression — `{model}`", "",
             "Legitimate requests a real user would make. **blocked** is a false positive: a "
             "defence refusing ordinary work. *missed* is the model failing to find the answer, "
             "with no defence involved.", "",
             "| Task | Target | " + " | ".join(defences.CONFIG_LABELS[c] for c in configs) + " |",
             "|---" * (2 + len(configs)) + "|"]
    for task in benign_mod.BENIGN_TASKS:
        cells = []
        for cfg in configs:
            record = latest.get((task.id, cfg, model))
            if record is None:
                cells.append("–")
            else:
                cells.append({"answered": "ok", "blocked": "**BLOCKED**",
                              "missed": "missed"}[record["outcome"]])
        lines.append(f"| `{task.id}` {task.name} | {task.target} | " + " | ".join(cells) + " |")

    lines += ["", "#### False-positive rate", "",
              "| Configuration | Legitimate requests blocked | Answered correctly |",
              "|---|---|---|"]
    for cfg in configs:
        records = [latest[k] for k in latest if k[1] == cfg and k[2] == model]
        if not records:
            continue
        blocked = sum(1 for r in records if r["outcome"] == "blocked")
        ok = sum(1 for r in records if r["outcome"] == "answered")
        lines.append(f"| {defences.CONFIG_LABELS[cfg]} | **{blocked}/{len(records)}** "
                     f"({100 * blocked / len(records):.0f}%) | {ok}/{len(records)} |")
    return "\n".join(lines)


def append_result(record: dict) -> None:
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with config.RUNS_JSONL.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_results() -> list[dict]:
    if not config.RUNS_JSONL.exists():
        return []
    out = []
    for line in config.RUNS_JSONL.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def was_defended(record: dict) -> bool:
    """True when a defence actively stopped this run.

    Two distinct shapes count. D1 and D3 abort the whole run and set `blocked`. D2 instead
    refuses an individual tool call and lets the run continue, so `blocked` stays False and
    only the ToolCall carries `allowed=False`. Checking `blocked` alone credited D2's
    refusals to the "failed on their own" column and understated the one defence that
    actually closed the tool-misuse attacks.
    """
    if record.get("blocked"):
        return True
    return any(not call.get("allowed", True) for call in record.get("tool_calls", []))


def latest_by_key(results: list[dict]) -> dict[tuple, dict]:
    """Deduplicate: keep the most recent record per (attack, config, model)."""
    latest: dict[tuple, dict] = {}
    for record in results:
        key = (record["attack_id"], record["config"], record["model"])
        previous = latest.get(key)
        if previous is None or record["timestamp"] >= previous["timestamp"]:
            latest[key] = record
    return latest


def render_matrix(results: list[dict], model: str) -> str:
    """Attack x defence-config table for one model.

    Three outcomes, deliberately distinguished:
      VULNERABLE - the attack succeeded
      blocked    - a defence stopped it
      failed     - the attack did not succeed and NO defence was involved; the model simply
                   did not do the thing. Collapsing this into "blocked" would credit defences
                   with outcomes they had nothing to do with, and at baseline - where no
                   defence is enabled at all - it would be plainly false.
    """
    latest = latest_by_key(results)
    configs = list(defences.CONFIGS)
    rows = []
    header = "| Attack | Category | OWASP | ATLAS | " + " | ".join(
        defences.CONFIG_LABELS[c] for c in configs
    ) + " |"
    sep = "|---" * (4 + len(configs)) + "|"

    for attack in attack_mod.ATTACKS:
        cells = []
        for cfg in configs:
            record = latest.get((attack.id, cfg, model))
            if record is None:
                cells.append("–")
            elif record.get("error"):
                cells.append("ERR")
            elif record["attack_succeeded"]:
                cells.append("**VULNERABLE**")
            elif was_defended(record):
                cells.append("blocked")
            else:
                cells.append("failed")
        rows.append(
            f"| `{attack.id}` {attack.name} | {attack.category.replace('_',' ')} | "
            f"{attack.owasp} | {attack.atlas} | " + " | ".join(cells) + " |"
        )

    summary = []
    for cfg in configs:
        records = [latest[k] for k in latest if k[1] == cfg and k[2] == model]
        tested = [r for r in records if not r.get("error")]
        vulnerable = sum(1 for r in tested if r["attack_succeeded"])
        stopped = sum(1 for r in tested if not r["attack_succeeded"] and was_defended(r))
        failed = len(tested) - vulnerable - stopped
        if tested:
            summary.append(
                f"| {defences.CONFIG_LABELS[cfg]} | {vulnerable}/{len(tested)} | "
                f"{stopped} | {failed} |"
            )

    parts = [f"### Attack results — `{model}`", "", header, sep, *rows]
    if summary:
        parts += ["", "#### Defence effectiveness", "",
                  "| Configuration | Attacks still succeeding | Stopped by a defence "
                  "| Failed on their own |",
                  "|---|---|---|---|", *summary,
                  "",
                  "*Failed on their own* counts attacks the model simply did not carry out, "
                  "with no defence involved. At baseline that column is the model's own "
                  "capability limits, not security.",
                  ]
    return "\n".join(parts)


def render_model_comparison(results: list[dict], models: list[str]) -> str:
    latest = latest_by_key(results)
    lines = ["### Model comparison — baseline vs all defences", "",
             "Denominators show how many attacks were run for that model; a model run with "
             "`--subset` shows fewer than the full 20.", "",
             "| Model | Vulnerable (no defences) | Vulnerable (all defences) |", "|---|---|---|"]
    any_row = False
    for model in models:
        cells = []
        for cfg in ("baseline", "d3"):
            records = [latest[k] for k in latest
                       if k[1] == cfg and k[2] == model and not latest[k].get("error")]
            cells.append(f"{sum(1 for r in records if r['attack_succeeded'])}/{len(records)}"
                         if records else "–")
        if cells != ["–", "–"]:
            any_row = True
        lines.append(f"| `{model}` | {cells[0]} | {cells[1]} |")
    return "\n".join(lines) if any_row else ""


def write_matrix_file(models: list[str]) -> str:
    results = load_results()
    sections = [
        "# Module 1 — Results",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"from `results/m1_runs.jsonl` ({len(results)} records).",
        "",
        "**VULNERABLE** means the attack succeeded, judged by a deterministic oracle "
        "(exact string match or tool-call inspection) — never by a model. "
        "**blocked** means a defence stopped it. **failed** means the attack did not work and "
        "no defence was involved.",
        "",
    ]
    benign = load_benign()
    for model in models:
        if any(r["model"] == model for r in results):
            sections += [render_matrix(results, model), ""]
        benign_table = render_benign(benign, model)
        if benign_table:
            sections += [benign_table, ""]
    comparison = render_model_comparison(results, config.COMPARISON_MODELS)
    if comparison:
        sections += [comparison, ""]
    text = "\n".join(sections)
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (config.RESULTS_DIR / "m1_matrix.md").write_text(text, encoding="utf-8")
    return text
