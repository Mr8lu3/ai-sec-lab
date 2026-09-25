# Framework mapping — sources and verification

Every attack in `aisec/m1/attacks.py` carries an OWASP LLM Top 10 ID and a MITRE ATLAS
technique ID. These were **looked up and verified**, not written from memory, because a
portfolio project that cites framework IDs incorrectly is worse than one that cites none.

`tests/test_attacks.py` fails the build if any attack is missing either ID or if an ID is
malformed.

## One correction this check produced

Two secondary web sources described **`AML.T0053` as "LLM Plugin Compromise"**. Checking the
machine-readable ATLAS dataset showed the technique is actually named
**"AI Agent Tool Invocation"**. The older "plugin" naming appears to be out of date, and it is
repeated widely enough that it would have been easy to copy.

This is itself a finding worth carrying into `RESEARCH.md`: secondary sources about AI security
frameworks drift from the primary source, and *verifying an identifier costs about a minute*
while a wrong one undermines an entire report.

## OWASP Top 10 for LLM Applications (2025)

Source: <https://genai.owasp.org/llm-top-10/>

| ID | Title | Used by |
|---|---|---|
| LLM01:2025 | Prompt Injection | `di-01`, `di-02`, `di-04`, `di-05`, `ii-01`, `ii-03`, `ii-05` |
| LLM02:2025 | Sensitive Information Disclosure | `ii-02`, `ii-04`, `dl-01`–`dl-04` |
| LLM06:2025 | Excessive Agency | `tm-01`–`tm-05` |
| LLM07:2025 | System Prompt Leakage | `di-03` |
| LLM08:2025 | Vector and Embedding Weaknesses | `dl-05` |

## MITRE ATLAS techniques

Source: the ATLAS attack-pattern dataset mirrored at
<https://github.com/MISP/misp-galaxy/blob/main/clusters/mitre-atlas-attack-pattern.json>,
cross-checked against <https://atlas.mitre.org/>.

| ID | Name | Used by |
|---|---|---|
| AML.T0051.000 | LLM Prompt Injection: Direct | `di-01`, `di-05` |
| AML.T0051.001 | LLM Prompt Injection: Indirect | `ii-01`–`ii-05` |
| AML.T0053 | AI Agent Tool Invocation | `tm-01`–`tm-05` |
| AML.T0054 | LLM Jailbreak | `di-02` |
| AML.T0056 | Extract LLM System Prompt | `di-03` |
| AML.T0057 | LLM Data Leakage | `dl-01`–`dl-05` |
| AML.T0068 | LLM Prompt Obfuscation | `di-04` |

## A note on what the mapping does and does not claim

The mapping says "this test exercises the weakness that this framework entry describes".
It does **not** claim coverage of the framework: five of the ten OWASP entries are not touched
here at all (supply chain, data poisoning, improper output handling, misinformation, unbounded
consumption), because those are not what these two targets are built to demonstrate.
