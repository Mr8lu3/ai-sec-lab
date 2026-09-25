"""AI Security Testing Lab - command line interface.

    python cli.py m1 list
    python cli.py m1 chat "who approved the Q3 budget?"
    python cli.py m1 attack --id di-01 [--config baseline] [--model qwen2.5:3b]
    python cli.py m1 run [--config baseline] [--model ...] [--subset] [--category ...]
    python cli.py m1 report
    python cli.py doctor
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from aisec import config
from aisec.llm import LLMClient, OllamaUnavailable
from aisec.m1 import attacks as attack_mod
from aisec.m1 import benign as benign_mod
from aisec.m1 import defences, runner
from aisec.m1.chatbot import DocumentQABot
from aisec.m2 import analyse as m2_analyse
from aisec.m2 import parsers as m2_parsers
from aisec.m2 import review as m2_review
from aisec.m2 import verify as m2_verify
from aisec.m2.models import BASES, VERDICTS, Review
from aisec.m3 import draft as m3_draft
from aisec.m3 import report as m3_report


def cmd_doctor(args) -> int:
    """Check the environment before anyone waits an hour for a run that cannot work."""
    print(f"Ollama host : {config.OLLAMA_HOST}")
    print(f"Repo root   : {config.REPO_ROOT}")
    print(f"Corpus      : {config.CORPUS_DIR} "
          f"({len(list(config.CORPUS_DIR.glob('*.md')))} documents)")
    print(f"Inbox       : {config.INBOX_DIR} "
          f"({len(list(config.INBOX_DIR.glob('*.json')))} emails)")
    try:
        import ollama
        client = ollama.Client(host=config.OLLAMA_HOST)
        available = [m.get("model", m.get("name", "?")) for m in client.list().get("models", [])]
        print(f"Models pulled: {', '.join(available) or '(none)'}")
        for wanted in config.COMPARISON_MODELS:
            mark = "OK " if any(wanted in a for a in available) else "MISSING"
            print(f"  [{mark}] {wanted}")
    except ImportError:
        print("Models      : 'ollama' package not installed (pip install -r requirements.txt)")
        return 1
    except Exception as exc:
        print(f"Models      : cannot reach Ollama at {config.OLLAMA_HOST}: {exc}")
        return 1
    return 0


def cmd_list(args) -> int:
    print(f"{'ID':<7} {'CATEGORY':<19} {'TARGET':<8} {'OWASP':<11} {'ATLAS':<15} NAME")
    for attack in attack_mod.ATTACKS:
        flag = "*" if attack.subset else " "
        print(f"{attack.id:<7} {attack.category:<19} {attack.target:<8} "
              f"{attack.owasp:<11} {attack.atlas:<15} {attack.name}{flag}")
    print(f"\n{len(attack_mod.ATTACKS)} attacks "
          f"({len(attack_mod.subset())} marked * for the model-comparison subset)")
    return 0


def cmd_chat(args) -> int:
    """Ask the chatbot a normal question - proves the target works before attacking it."""
    client = LLMClient(model=args.model)
    bot = DocumentQABot(client)
    started = time.time()
    run = bot.answer(args.question)
    print(run.output or f"(no output) error={run.error}")
    print(f"\n[{time.time() - started:.1f}s, {client.stats()}]")
    return 0


def _run_one(attack, config_name: str, model: str, verbose: bool) -> dict:
    started = time.time()
    record = runner.run_attack(attack, config_name, model)
    runner.append_result(record)
    status = ("VULNERABLE" if record["attack_succeeded"]
              else ("ERROR" if record["error"] else "blocked"))
    print(f"  {attack.id:<7} {config_name:<9} {status:<11} "
          f"({time.time() - started:.0f}s) {record['evidence'][:90]}")
    if verbose and record["output"]:
        print(f"      output: {record['output'][:300]}")
    return record


def cmd_attack(args) -> int:
    attack = attack_mod.by_id(args.id)
    print(f"{attack.id}: {attack.name}\n  {attack.owasp} / {attack.atlas}\n"
          f"  rationale: {attack.rationale}\n")
    _run_one(attack, args.config, args.model, verbose=True)
    return 0


def cmd_run(args) -> int:
    selected = attack_mod.subset() if args.subset else attack_mod.ATTACKS
    if args.category:
        selected = [a for a in selected if a.category == args.category]
    if args.target:
        selected = [a for a in selected if a.target == args.target]
    configs = [args.config] if args.config else list(defences.CONFIGS)

    total = len(selected) * len(configs)
    print(f"Running {len(selected)} attacks x {len(configs)} configs = {total} runs "
          f"on {args.model}")
    # Measured on the development machine (i5-5300U, CPU-only): 15-25s per model call.
    # Runs blocked by D1/D2 cost nothing, so this is an upper bound in practice.
    print(f"Uncached, expect roughly {total * 15 / 60:.0f}-{total * 25 / 60:.0f} minutes "
          f"(cached runs return instantly).\n")

    for config_name in configs:
        print(f"[{config_name}] {defences.CONFIG_LABELS[config_name]}")
        for attack in selected:
            try:
                _run_one(attack, config_name, args.model, verbose=args.verbose)
            except OllamaUnavailable as exc:
                print(f"\nAborting: {exc}")
                return 1
            except KeyboardInterrupt:
                print("\nInterrupted. Completed runs are saved in results/m1_runs.jsonl.")
                return 130
    print()
    cmd_report(args)
    return 0


def cmd_benign(args) -> int:
    """Run the benign regression suite - measures what the defences cost in ordinary use."""
    tasks = benign_mod.BENIGN_TASKS
    configs = [args.config] if args.config else list(defences.CONFIGS)
    total = len(tasks) * len(configs)
    print(f"Running {len(tasks)} benign tasks x {len(configs)} configs = {total} runs "
          f"on {args.model}")
    print(f"Uncached, expect roughly {total * 15 / 60:.0f}-{total * 25 / 60:.0f} minutes.\n")

    for config_name in configs:
        print(f"[{config_name}] {defences.CONFIG_LABELS[config_name]}")
        for task in tasks:
            started = time.time()
            try:
                record = runner.run_benign(task, config_name, args.model)
            except OllamaUnavailable as exc:
                print(f"\nAborting: {exc}")
                return 1
            except KeyboardInterrupt:
                print("\nInterrupted. Completed runs are saved.")
                return 130
            runner.append_benign(record)
            label = {"answered": "ok", "blocked": "BLOCKED(FP)", "missed": "missed"}[record["outcome"]]
            print(f"  {task.id:<7} {config_name:<9} {label:<12} "
                  f"({time.time() - started:.0f}s) {record['evidence'][:80]}")
    print()
    return cmd_report(args)


def cmd_report(args) -> int:
    models = sorted({r["model"] for r in runner.load_results()}) or [config.DEFAULT_MODEL]
    text = runner.write_matrix_file(models)
    print(text)
    print(f"\nWritten to {config.RESULTS_DIR / 'm1_matrix.md'}")
    return 0


# ------------------------------------------------------------------ Module 2

def cmd_m2_parse(args) -> int:
    """Parse scanner exports into normalised findings."""
    findings = []
    for name in args.files:
        path = Path(name)
        if not path.exists():
            print(f"Error: no such file: {path}", file=sys.stderr)
            return 1
        parsed = m2_parsers.parse_file(path)
        print(f"{path.name}: {len(parsed)} findings")
        findings.extend(parsed)

    if not findings:
        print("No findings parsed - check the export is a ZAP .json or Nmap .xml report.")
        return 1

    m2_review.save_findings(findings)
    print(f"\n{'ID':<15} {'SOURCE':<6} {'SEVERITY':<14} TITLE")
    for finding in findings:
        print(f"{finding.id:<15} {finding.source:<6} {finding.severity:<14} {finding.title[:58]}")
    print(f"\n{len(findings)} findings saved to {m2_review.FINDINGS_PATH}")
    return 0


def cmd_m2_analyse(args) -> int:
    """Ask the model to triage each finding. Every answer is an unverified claim."""
    findings = m2_review.load_findings()
    if not findings:
        print("No findings loaded. Run `cli.py m2 parse <scan files>` first.")
        return 1

    client = LLMClient(model=args.model)
    print(f"Triaging {len(findings)} findings with {args.model}")
    print(f"Uncached, expect roughly {len(findings) * 20 / 60:.0f}-"
          f"{len(findings) * 35 / 60:.0f} minutes.\n")

    for finding in findings:
        started = time.time()
        try:
            assessment = m2_analyse.assess_finding(client, finding, findings)
        except OllamaUnavailable as exc:
            print(f"\nAborting: {exc}")
            return 1
        except KeyboardInterrupt:
            print("\nInterrupted. Completed assessments are saved.")
            return 130
        m2_review.save_assessment(assessment)

        flags = []
        if assessment.duplicate_of:
            flags.append(f"dup of {assessment.duplicate_of}")
        problem = assessment.raw.get("hallucinated_reference")
        if problem:
            flags.append("INVENTED ID")
        delta = assessment.raw.get("severity_delta", 0)
        if delta:
            flags.append(f"severity {finding.severity}->{assessment.severity}")
        print(f"  {finding.id:<15} {assessment.severity or '?':<14} "
              f"{assessment.exploitable or '?':<9} ({time.time() - started:.0f}s) "
              f"{' | '.join(flags)}")
        if problem:
            print(f"      ^ {problem}")
    print()
    return cmd_m2_accuracy(args)


def cmd_m2_verify(args) -> int:
    """Reproduce findings against the live target to establish ground truth."""
    findings = m2_review.load_findings()
    if not findings:
        print("No findings loaded. Run `cli.py m2 parse <scan files>` first.")
        return 1

    origins = {m2_verify.origin_of(f.target) for f in findings if f.target.startswith("http")}
    baselines = {}
    for origin in sorted(o for o in origins if o):
        print(f"Learning catch-all baseline for {origin} ...")
        baselines[origin] = m2_verify.spa_baseline(origin)
        base = baselines[origin]
        if base["error"]:
            print(f"  WARNING: {base['error']} - target may be down; "
                  f"disclosure checks will be inconclusive")
        else:
            print(f"  nonexistent URL returns HTTP {base['status']}, "
                  f"{base['size']}b, sha {base['sha']}")
    print()

    counts = {c: 0 for c in m2_verify.CONCLUSIONS}
    for finding in findings:
        baseline = baselines.get(m2_verify.origin_of(finding.target), {})
        verification = m2_verify.verify_finding(finding, baseline)
        m2_verify.save_verification(verification)
        counts[verification.conclusion] += 1
        label = {"confirmed": "CONFIRMED", "false_positive": "FALSE POSITIVE",
                 "inconclusive": "needs human"}[verification.conclusion]
        print(f"  {finding.id:<15} {label:<15} {finding.title[:34]:<36} {verification.detail[:70]}")

    print(f"\nconfirmed {counts['confirmed']} | "
          f"false positives {counts['false_positive']} | "
          f"needs human judgement {counts['inconclusive']}")
    print(f"Written to {m2_verify.VERIFICATION_PATH}")
    return 0


def cmd_m2_review(args) -> int:
    """Record a human verdict on each outstanding claim."""
    outstanding = m2_review.pending(args.model, include_reviewed=args.redo)
    if not outstanding:
        already = len([1 for (fid, m) in m2_review.latest_reviews() if m == args.model])
        if already:
            print(f"All {already} claims for {args.model} already have a verdict.")
            print("Re-review them with:  cli.py m2 review --model "
                  f"{args.model} --redo --reviewer \"your name\"")
            print("Your verdicts supersede the existing ones; nothing is deleted.")
        else:
            print(f"Nothing to review for {args.model}. Run `cli.py m2 analyse` first.")
        return 0

    # Non-interactive form, so a verdict can be recorded from a script or a one-liner.
    if args.finding:
        pair = next((p for p in outstanding if p[0].id == args.finding), None)
        if pair is None:
            print(f"No pending claim for finding {args.finding!r} by {args.model}.")
            return 1
        if not args.verdict:
            print("--verdict is required with --finding.")
            return 1
        m2_review.save_review(Review(finding_id=args.finding, model=args.model,
                                     verdict=args.verdict, note=args.note or "",
                                     basis=args.basis, reviewer=args.reviewer))
        print(f"Recorded {args.verdict} for {args.finding}.")
        return 0

    all_findings = m2_review.load_findings()
    verifications = m2_verify.load_verifications()
    reviewer = args.reviewer
    if not reviewer:
        try:
            reviewer = input("Your name or initials, for the record > ").strip()
        except (EOFError, KeyboardInterrupt):
            reviewer = ""
    print(f"{len(outstanding)} claims to review for {args.model}.")
    if not verifications:
        print("NOTE: no reproduction data. Run `cli.py m2 verify` first so verdicts can "
              "rest on ground truth rather than judgement alone.")
    print("Verdicts: " + ", ".join(f"[{v[0]}]{v[1:]}" for v in VERDICTS if v != "unverified")
          + ", [s]kip, [q]uit\n")
    shortcuts = {v[0]: v for v in VERDICTS if v != "unverified"}

    for finding, assessment in outstanding:
        print(f"--- {finding.id}  [{finding.source}] {finding.title}")
        print(f"    target          : {finding.target}")
        print(f"    scanner severity: {finding.severity}")
        print(f"    evidence        : {finding.evidence or '(none)'}")
        print(f"    AI severity     : {assessment.severity or '?'}"
              f"   AI exploitable: {assessment.exploitable or '?'}")
        if assessment.duplicate_of:
            print(f"    AI duplicate of : "
                  f"{m2_review.describe_finding(assessment.duplicate_of, all_findings)}")
        if assessment.raw.get("hallucinated_reference"):
            print(f"    AUTO-FLAG       : {assessment.raw['hallucinated_reference']}")
        print(f"    AI reasoning    : {assessment.reasoning}")
        verification = verifications.get(finding.id)
        if verification:
            label = {"confirmed": "CONFIRMED", "false_positive": "FALSE POSITIVE",
                     "inconclusive": "not mechanically checkable"}[verification.conclusion]
            print(f"    GROUND TRUTH    : {label} ({verification.method})")
            print(f"                      {verification.detail}")

        # Re-prompt rather than skip. Skipping on unrecognised input silently discarded the
        # finding - and worse, a multi-line paste desynchronised the prompts, so stray lines
        # of a note were read as verdicts for later findings and skipped them.
        verdict = None
        while verdict is None:
            try:
                choice = input("    verdict > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nStopped. Verdicts already entered are saved.")
                return 0
            if choice in {"q", "quit"}:
                print("Stopped. Verdicts already entered are saved.")
                return 0
            if choice in {"s", "skip", ""}:
                verdict = "__skip__"
                break
            verdict = shortcuts.get(choice, choice if choice in VERDICTS else None)
            if verdict is None:
                print(f"    Not a verdict. Expected one of: "
                      f"{', '.join(f'[{v[0]}]{v[1:]}' for v in shortcuts.values())}, "
                      f"[s]kip, [q]uit.")
        if verdict == "__skip__":
            print()
            continue
        # How the verdict was reached matters as much as the verdict. Default to the
        # honest answer for this finding rather than assuming the reviewer reproduced it.
        default_basis = "reproduced" if (
            verification and verification.conclusion != "inconclusive") else "evidence"
        # Re-prompt on an unrecognised basis rather than silently substituting the default.
        # Falling back quietly means a typo becomes a valid-looking value that the reviewer
        # has no way to notice, and the "how was this decided" column stops being trustworthy.
        basis = default_basis
        while True:
            try:
                raw_basis = input(
                    f"    basis [{'/'.join(BASES)}] (enter = {default_basis}) > "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            if not raw_basis:
                break
            if raw_basis in BASES:
                basis = raw_basis
                break
            matches = [b for b in BASES if b.startswith(raw_basis)]
            if len(matches) == 1:
                basis = matches[0]
                print(f"    -> {basis}")
                break
            print(f"    '{raw_basis}' is not a basis. Expected one of: "
                  f"{', '.join(sorted(BASES))}. Press enter for {default_basis}.")
        # Read a note across multiple lines, ending on a blank one. Single-line input() meant
        # a pasted paragraph saved only its first line and fed the rest into later prompts.
        print("    note (optional; paste freely, then press enter on a blank line)")
        note_lines = []
        while True:
            try:
                line = input("    > " if note_lines else "    note > ")
            except (EOFError, KeyboardInterrupt):
                break
            if not line.strip():
                break
            note_lines.append(line.strip())
        note = " ".join(note_lines)
        m2_review.save_review(Review(finding_id=finding.id, model=args.model,
                                     verdict=verdict, note=note, basis=basis,
                                     reviewer=reviewer))
        print(f"    recorded: {verdict} (basis: {basis})\n")

    print()
    return cmd_m2_accuracy(args)


def cmd_m2_accuracy(args) -> int:
    table = m2_review.render_accuracy()
    print(table)
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (config.RESULTS_DIR / "m2_accuracy.md").write_text(
        "# Module 2 - AI triage accuracy\n\n" + table + "\n", encoding="utf-8")
    return 0


# ------------------------------------------------------------------ Module 3

def cmd_m3_draft(args) -> int:
    """Have the model draft report sections for each verified finding."""
    findings, notes = m3_report.verified_findings(args.include_unverified)
    if not findings:
        print("No findings to draft.")
        for note in notes[:10]:
            print(f"  {note}")
        print("\nVerify findings with `cli.py m2 review`, or pass --include-unverified "
              "to draft anyway (the report will be marked accordingly).")
        return 1

    verifications = m2_verify.load_verifications()
    client = LLMClient(model=args.model)
    print(f"Drafting {len(findings)} findings with {args.model}")
    print(f"Uncached, expect roughly {len(findings) * 30 / 60:.0f}-"
          f"{len(findings) * 50 / 60:.0f} minutes.\n")

    for finding in findings:
        started = time.time()
        try:
            verification = verifications.get(finding.id)
            reproduction = verification.detail if verification else ""
            sections = m3_draft.draft_finding(client, finding, reproduction=reproduction)
            if reproduction:
                sections["_reproduction"] = f"{verification.conclusion} - {reproduction}"
        except OllamaUnavailable as exc:
            print(f"\nAborting: {exc}")
            return 1
        except KeyboardInterrupt:
            print("\nInterrupted. Completed drafts are saved.")
            return 130
        m3_report.write_draft(finding, sections)
        seeded = m3_report.seed_final(finding, sections)
        flag = "" if seeded else "  (final already exists, left untouched)"
        status = "PARSE FAIL" if sections.get("_parse_error") else "drafted"
        print(f"  {finding.id:<15} {status:<11} ({time.time() - started:.0f}s){flag}")

    print(f"\nRaw AI drafts : {m3_report.DRAFTS_DIR}")
    print(f"Edit these    : {m3_report.FINAL_DIR}")
    print("\nEdit the files in m3_final/, then run `cli.py m3 report`.")
    return 0


def cmd_m3_report(args) -> int:
    m3_report.build_report(args.include_unverified)
    m3_report.build_diff()
    findings, notes = m3_report.verified_findings(args.include_unverified)
    edited = sum(1 for f in findings if m3_report.edit_stats(f.id).get("any_changed"))
    print(f"Report written  : {m3_report.REPORT_PATH}")
    print(f"AI vs final     : {m3_report.DIFF_PATH}")
    print(f"Findings included: {len(findings)}   excluded: {len(notes)}")
    print(f"Drafts a human edited: {edited}/{len(findings)}")
    return 0


def main(argv=None) -> int:
    # Windows consoles default to cp1252, which mangles the em-dashes in the generated
    # tables. The files themselves are always written UTF-8; this fixes only the terminal.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(prog="cli.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check environment and models").set_defaults(func=cmd_doctor)

    m1 = sub.add_parser("m1", help="Module 1 - LLM application assessment")
    m1sub = m1.add_subparsers(dest="m1command", required=True)

    m1sub.add_parser("list", help="list the attack suite").set_defaults(func=cmd_list)

    p_chat = m1sub.add_parser("chat", help="ask the chatbot a normal question")
    p_chat.add_argument("question")
    p_chat.add_argument("--model", default=config.DEFAULT_MODEL)
    p_chat.set_defaults(func=cmd_chat)

    p_attack = m1sub.add_parser("attack", help="run a single attack")
    p_attack.add_argument("--id", required=True)
    p_attack.add_argument("--config", default="baseline", choices=list(defences.CONFIGS))
    p_attack.add_argument("--model", default=config.DEFAULT_MODEL)
    p_attack.set_defaults(func=cmd_attack)

    p_run = m1sub.add_parser("run", help="run the attack matrix")
    p_run.add_argument("--config", default=None, choices=list(defences.CONFIGS),
                       help="one config only (default: all four, cumulative)")
    p_run.add_argument("--model", default=config.DEFAULT_MODEL)
    p_run.add_argument("--subset", action="store_true", help="only the model-comparison subset")
    p_run.add_argument("--category", default=None, choices=attack_mod.CATEGORIES)
    p_run.add_argument("--target", default=None, choices=attack_mod.TARGETS)
    p_run.add_argument("--verbose", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_benign = m1sub.add_parser(
        "benign", help="run the benign regression suite (false-positive measurement)")
    p_benign.add_argument("--config", default=None, choices=list(defences.CONFIGS))
    p_benign.add_argument("--model", default=config.DEFAULT_MODEL)
    p_benign.set_defaults(func=cmd_benign)

    m1sub.add_parser("report", help="regenerate the results tables").set_defaults(func=cmd_report)

    m2 = sub.add_parser("m2", help="Module 2 - AI-assisted vulnerability analysis")
    m2sub = m2.add_subparsers(dest="m2command", required=True)

    p_parse = m2sub.add_parser("parse", help="parse ZAP .json / Nmap .xml exports")
    p_parse.add_argument("files", nargs="+")
    p_parse.set_defaults(func=cmd_m2_parse)

    p_an = m2sub.add_parser("analyse", help="AI triage of the parsed findings")
    p_an.add_argument("--model", default=config.DEFAULT_MODEL)
    p_an.set_defaults(func=cmd_m2_analyse)

    p_rev = m2sub.add_parser("review", help="record human verdicts on AI claims")
    p_rev.add_argument("--model", default=config.DEFAULT_MODEL)
    p_rev.add_argument("--finding", default=None, help="record one verdict non-interactively")
    p_rev.add_argument("--verdict", default=None,
                       choices=[v for v in VERDICTS if v != "unverified"])
    p_rev.add_argument("--note", default=None)
    p_rev.add_argument("--basis", default="evidence", choices=sorted(BASES))
    p_rev.add_argument("--redo", action="store_true",
                       help="re-review claims that already have a verdict (yours supersedes)")
    p_rev.add_argument("--reviewer", default="",
                       help="who recorded this verdict; recorded verbatim in the accuracy table")
    p_rev.set_defaults(func=cmd_m2_review)

    m2sub.add_parser("verify", help="reproduce findings against the live target"
                     ).set_defaults(func=cmd_m2_verify)

    m2sub.add_parser("accuracy", help="accuracy table per model").set_defaults(func=cmd_m2_accuracy)

    m3 = sub.add_parser("m3", help="Module 3 - AI-assisted reporting")
    m3sub = m3.add_subparsers(dest="m3command", required=True)

    p_draft = m3sub.add_parser("draft", help="draft report sections for verified findings")
    p_draft.add_argument("--model", default=config.DEFAULT_MODEL)
    p_draft.add_argument("--include-unverified", action="store_true",
                         help="draft findings with no human review (marked in the report)")
    p_draft.set_defaults(func=cmd_m3_draft)

    p_rep = m3sub.add_parser("report", help="assemble the report and the AI-vs-final diff")
    p_rep.add_argument("--include-unverified", action="store_true")
    p_rep.set_defaults(func=cmd_m3_report)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OllamaUnavailable as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
