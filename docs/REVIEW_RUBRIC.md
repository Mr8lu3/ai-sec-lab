# Review rubric

This is the rule I used to turn an AI triage claim into a verdict. I wrote it before I started
reviewing, not afterwards, so the verdicts could not be bent to fit a conclusion I liked.

Each triage claim contains three separate assertions. I check each one, and the worst of the
three decides the verdict.

## The three checks, in order

**1. Exploitability against ground truth.**
If `cli.py m2 verify` reproduced the finding, compare the model's `exploitable` answer to what
actually happened. A model calling a reproduced false positive "likely exploitable" is wrong,
and no security knowledge is needed to say so. This settles 8 of my 17 findings on its own.

**2. The duplicate claim.**
Does the referenced finding describe the *same* issue? Not related, not the same category —
the same issue. "Backup File Disclosure duplicates Non-Storable Content" is readable as false
from the two titles alone.

**3. Severity.**
Did the model move the scanner's rating, and is the move supported by evidence? An unexplained
escalation is not a judgement, it is noise.

## Verdicts

| Verdict | When |
|---|---|
| `correct` | All three assertions hold up. |
| `overconfident` | Directionally reasonable but oversold — an unsupported severity move, or a duplicate claim against something genuinely related but distinct. |
| `wrong` | Any assertion is false. |

## What is counted separately, not in the verdict

Faults the tool catches mechanically are reported in their own columns and mentioned in the
note, but do not decide the verdict:

- **invented identifiers** — a `duplicate_of` naming a finding that does not exist
- **incoherent claim sets** — mutual pairs, cycles, cross-source duplicates

Counting these twice would conflate "did the model reason soundly" with "did the model format
its output correctly". They are different questions and the table reports them separately.

## Recording how I decided

Every verdict carries a `basis`:

- `reproduced` — checked against the live target
- `evidence` — judged from the scanner output without reproducing it
- `knowledge` — judged from what I know about the finding class
- `unsure` — recorded a verdict but with low confidence

This matters more than it looks. A verdict backed by reproduction and a verdict backed by a
hunch are not the same evidence, and a table that stored them identically would overstate how
much of the review was actually grounded. The accuracy table reports the split.

## The limit of this rubric

It works because most of these findings are mechanically checkable. Where they are not — is
`bypassSecurityTrustHtml` reachable from user input? — no rubric substitutes for source review,
and the honest answer is `unsure`. I would rather publish a low-confidence marker than a
confident guess.
