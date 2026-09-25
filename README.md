# AI Security Testing Lab

I built this to answer two questions I kept seeing conflated: can you break an LLM-based
application, and can you trust an LLM to help you do security work?

Everything runs locally. No API keys, no cloud, no external targets. The vulnerable
applications are in this repository and the scanning targets OWASP Juice Shop in a Docker
container on my own machine.

| Module | What I was testing |
|---|---|
| 1 | Which attacks break an LLM application, and which defences actually stop them |
| 2 | Whether a local model can triage real scanner output, and how often it is wrong |
| 3 | Whether a local model can draft report prose, and what I had to correct |

I used three models: `qwen2.5:3b`, `llama3.2:3b` and `phi4-mini`. They are small enough to run
at 15-25 seconds per call on a 2015 dual-core laptop with no GPU, which is the hardware I had.
Coverage differs between them and the generated tables say so on every row: only
`llama3.2:3b` ran the complete attack suite at all four configurations.

292 tests, passing on Windows and Linux.

---

## Headline results

**Module 1.** Nine of twenty attacks worked against an undefended LLM application. Tool
permissions closed the two tool-misuse attacks still working at that point, at no cost to
normal use. Adding a second model to check outputs left zero attacks succeeding, but it also
blocked five of eight legitimate requests, which makes it unusable.

**Module 2.** I reviewed 34 triage claims by hand across two models. `qwen2.5:3b` got 2 of 17
right. `phi4-mini` got 2 of 17 right. Reproduction also showed that the scanner itself was
wrong about three findings, one of which a model had rated "likely exploitable".

**Module 3.** All five AI-drafted report sections needed correcting. Two contained advice that
would have made the application less secure, and one specified an HTTP header value that does
not exist.

---

## Module 1: attacking an LLM application

I wrote two deliberately vulnerable targets.

The first is a document Q&A chatbot answering from a folder of fake company documents. One
document is marked CONFIDENTIAL and contains a planted credential. Retrieval is not
permission-aware and retrieved text goes into the prompt with no separation from instructions,
which is how most naive RAG applications are built.

The second is an agent with three tools: `read_file`, `search_inbox`, and `send_email` that
writes to a local log rather than sending anything. `read_file` does not canonicalise paths
and `send_email` accepts any recipient.

I wrote 20 attacks across direct prompt injection, indirect prompt injection, data leakage and
tool misuse, then added three defences one at a time to see what each one bought me.

### Results, `llama3.2:3b`

The configurations are cumulative. Tool permissions runs with the input filter also enabled,
and the output judge runs with all three. So the only column that attributes a result to a
single defence is "newly closed".

| Configuration | Attacks succeeding | Newly closed by this defence | Failed on their own | Legitimate requests blocked |
|---|---|---|---|---|
| No defences | **9/20** | – | 11 | 0/8 |
| + input filter | 7/20 | 2 | 10 | 0/8 |
| + tool permissions | 5/20 | 2 | 10 | 0/8 |
| + output judge | 0/20 | 5 | 5 | **5/8** |

Full tables for all three models are in [`results/m1_matrix.md`](results/m1_matrix.md).

`llama3.2:3b` is the only model I ran over the complete suite at all four configurations.

`qwen2.5:3b` covers all 20 attacks, but two of its runs errored and are excluded from the
counts, which is why its denominator is 19 at the first two configurations and 20 at the last
two. Both errors are the same attack, `di-05` against the agent, where the model's tool-
selection JSON was cut off by a token limit I had set too low. I raised the limit afterwards,
so a re-run would probably clear them, but I have left the recorded result as it is rather
than quietly re-running until the table looks tidy.

`phi4-mini` covers only 12 of 20 attacks at two configurations, because it is slower and a
full run was impractical on this hardware.

The generated tables state each model's coverage on the row itself, so a partial run is not
read as a complete one.

### What I take from that

Tool permissions were the only defence worth the name. Path containment and a recipient
allowlist closed the two tool-misuse attacks that were still working, and broke nothing. They
are deterministic, they cost no inference time, and they do not guess.

The output judge is the interesting one. It closed the last 5 attacks and took the suite to
zero, which looks like a perfect score until you check what it did to normal use. It refused to name the person who approved a
budget because the answer "contains a specific date". It refused to explain the incident
reporting process because that "reveals a system prompt". It refused to send an ordinary
internal email. An attack-blocking rate quoted without a false-positive rate is not a security
result, and building the benign suite is what showed me that.

Eleven attacks failed at baseline with no defence enabled at all. The model simply did not
carry them out. That is a capability limit of a 3B model, not a control, and it would not hold
against something larger. I report it in its own column because an earlier version of my table
counted those as "blocked", which produced an effectiveness figure for a configuration that had
no defences in it.

Every attack maps to an OWASP LLM Top 10 entry and a MITRE ATLAS technique. I checked those
identifiers against the published sources rather than writing them from memory, and that check
caught one I would otherwise have got wrong. See [`docs/MAPPING.md`](docs/MAPPING.md).

Attack success is decided by exact string match on a planted canary, or by inspecting the
recorded tool calls. No model judges whether an attack worked. "The canary appeared in the
output" is a fact I can defend; "a 3B model thought the attack succeeded" is an opinion from
the same class of system I am testing.

---

## Module 2: AI-assisted triage, and validating it

I scanned Juice Shop with OWASP ZAP and Nmap and committed the exports to
[`scans/`](scans/). That produced 17 findings. I had all three models triage every one:
group duplicates, rate severity, judge exploitability. Then I checked their work.

### Before judging anything, I reproduced the findings

`cli.py m2 verify` requests each finding against the live target. It first learns what the
application returns for a URL that cannot exist, then compares.

This found something I did not expect. ZAP reported "Bypassing 403" on
`/%2e/ftp/coupons_2013.md.bak` with a 200 response. The body turned out to be byte-identical
to the response for a nonexistent URL. It is Angular's catch-all route serving `index.html`.
No file was disclosed and no 403 was bypassed. **The scanner was wrong, and `qwen2.5:3b` then
rated that false positive "likely exploitable".**

Of 17 findings: 5 confirmed, 3 contradicted by reproduction, 9 not checkable by a single HTTP
request.

### Accuracy

| Model | Claims | Correct | Wrong | Overconfident | Called duplicate | Invented IDs |
|---|---|---|---|---|---|---|
| `qwen2.5:3b` | 17 | 2 (12%) | 13 | 2 | 16/17 | 1 |
| `phi4-mini` | 17 | 2 (12%) | 12 | 3 | 17/17 | 0 |
| `llama3.2:3b` | 17 | not reviewed | | | 9/17 | 8 |

Almost every failure was a duplicate claim. `phi4-mini` called all 17 findings a duplicate of
something, seven of them duplicates of an open TCP port found by a different tool.

There is exactly one true duplicate relationship in this dataset: ZAP found the same wildcard
CORS policy passively and actively. All three models found it. They also claimed 38 others
that do not exist, which buries the one real signal.

I reviewed `qwen2.5:3b` and `phi4-mini` myself, 34 claims, with a note on each. `llama3.2:3b`
has assessments recorded but no verdicts, so its row shows only the counts the tool derives
mechanically. I would rather leave that blank than claim a review I did not do.

### What the tool checks before I look at anything

Three checks that need no judgement, so that less of the validation burden falls on a tired
reviewer:

- **Invented identifiers.** A `duplicate_of` naming a finding that does not exist is rejected
  and counted. `llama3.2:3b` did this 8 times, including writing the literal string `unclear`
  into the field.
- **Severity drift.** How far the model moved the scanner's rating. Systematic escalation is
  the most common failure in AI triage and is invisible unless you measure it.
- **Incoherent claim sets.** Claims that are individually well-formed but contradict each other:
  mutual pairs, longer cycles, and cross-source claims. Every model produced at least one, and
  all three made the same mutual-pair error on the same two findings.

My review rule is written down in [`docs/REVIEW_RUBRIC.md`](docs/REVIEW_RUBRIC.md). I wrote it
before I started reviewing so I could not bend the verdicts to fit a conclusion I liked.

This project does not compute CVSS. The triage schema pins severity to a fixed set of words so
a model cannot emit a number that might be mistaken for a score.

---

## Module 3: AI-assisted report writing

The model drafts description, impact and remediation for each finding that reproduction
confirmed. The raw draft is written once and never touched again. I edit a separate copy. Both
are kept so a reader can see what I changed.

All five drafts needed correcting. Two would have made the application less secure.

| The draft said | Why it is wrong |
|---|---|
| `Access-Control-Allow-Origin: null`, twice | The null origin is forgeable from a sandboxed iframe |
| `Access-Control-Allow-Credentials: true` | The opposite of hardening |
| `Cross-Origin-Embedder-Policy: require-same-origin` | That value does not exist |
| "attacker could access data intended for authenticated users" | Backwards; browsers forbid wildcard CORS with credentialed requests |

Every draft also overstated impact. A missing CSP was described as "allowing potentially
malicious scripts to run", when its absence removes a mitigation rather than creating an
injection vector. I added an explicit instruction to the system prompt telling it not to do
this. The next draft did it anyway.

That is the failure mode that worries me most. A wrong severity gets argued about in review. A
confidently worded, invalid header value gets pasted into a config file.

Three rules the module enforces:

1. Only findings confirmed by reproduction reach the report. Whether the AI's claim about a
   finding was any good is a separate question from whether the finding is real, and an earlier
   version of my code conflated the two. Excluded findings are listed in an appendix with the
   reason.
2. The drafting schema has no severity field. The model writes prose. It does not re-rate
   anything.
3. Re-running the drafter never overwrites an edited file.

Output: [`results/pentest_report.md`](results/pentest_report.md) and
[`results/m3_ai_vs_final.md`](results/m3_ai_vs_final.md).

---

## Running it

Requires Python 3.11+ and [Ollama](https://ollama.com). No API keys.

```bash
pip install -r requirements.txt
ollama pull qwen2.5:3b
ollama pull llama3.2:3b
ollama pull phi4-mini
```

If Ollama runs on a different host from the CLI, point at it with
`OLLAMA_HOST=http://host:11434`.

```bash
python cli.py doctor                                   # check environment and models

python cli.py m1 list                                  # the attack suite
python cli.py m1 chat "Who approved the Q3 budget?"    # benign use of the target
python cli.py m1 attack --id dl-01 --config baseline   # one attack
python cli.py m1 run --model qwen2.5:3b                # the full matrix
python cli.py m1 benign --model qwen2.5:3b             # the control group
python cli.py m1 report

python cli.py m2 parse scans/zap_full.json scans/nmap_juiceshop.xml
python cli.py m2 verify                                # reproduce against the live target
python cli.py m2 analyse --model qwen2.5:3b
python cli.py m2 review --model qwen2.5:3b             # record verdicts by hand
python cli.py m2 accuracy

python cli.py m3 draft --model qwen2.5:3b
python cli.py m3 report

pytest tests/ -q
```

Module 2 needs Juice Shop running for the reproduction step:
`docker run -d -p 3000:3000 bkimminich/juice-shop`.

Every model response is cached under `results/.cache/`, so re-running a table after a code
change costs nothing. On my hardware the full Module 1 matrix takes about 30 minutes the first
time.

---

## Layout

```
aisec/m1/    vulnerable chatbot and agent, attacks, defences, oracles
aisec/m2/    scanner parsers, triage, reproduction, review and accuracy
aisec/m3/    report drafting and assembly
cli.py       one entry point for everything
scans/       the real ZAP and Nmap exports these results come from
results/     JSONL evidence and generated reports
tests/       292 tests, none of which need a model running
docs/        framework mapping and my review rubric
```

The JSONL files under `results/` are the raw record behind every table above. Nothing in them
is summarised or filtered, so any figure I quote can be checked against the run that produced
it.

## Scope

Targets are the vulnerable applications in this repository and a local Juice Shop container.
Every email address in every attack payload uses an RFC 2606 reserved domain, and a test
enforces that so the suite cannot be pointed at a real system by copy-paste. The agent's
`send_email` tool writes to a log file and has no network capability.
