# Module 2 - AI triage accuracy

### AI triage accuracy, by model

Reviewers: `MrBlue`

Every row is a count of **claims a human checked by hand**. `unverified` is shown rather than hidden: a table that drops unchecked claims lets a model look accurate because only its easy claims were reviewed.

| Model | Claims | Correct | Wrong | Overconfident | Unverified | Verdicts backed by reproduction | Called duplicate | Invented IDs | Escalated |
|---|---|---|---|---|---|---|---|---|---|
| `llama3.2:3b` | 17 | 0 (–) | 0 | 0 | 17 | 0 | 9/17 | 8 | 8 |
| `phi4-mini` | 17 | 2 (12%) | 12 | 3 | 0 | 8 | 17/17 | 0 | 1 |
| `qwen2.5:3b` | 17 | 2 (12%) | 13 | 2 | 0 | 8 | 16/17 | 1 | 3 |

*Verdicts backed by reproduction* counts verdicts the reviewer reached by checking the finding against the live target rather than judging from the scanner evidence alone. A verdict and a reproduction are not the same evidence.

*Correct %* is over claims actually reviewed, not over all claims. *Invented IDs* counts duplicate references to findings that do not exist — caught automatically, not by the reviewer.

### Automatic claim-set validation

Individually well-formed claims that contradict each other as a set. Found by the tool before any human review.

**`llama3.2:3b`**
- mutual: zap-67a2a068 and zap-707f9920 each claim the other as the original
- mutual: zap-6b914d64 and zap-706cff2a each claim the other as the original

**`phi4-mini`**
- mutual: nmap-68fc8788 and zap-b859431a each claim the other as the original
- cross-source: nmap-68fc8788 (nmap) claimed as duplicate of zap-b859431a (zap)
- mutual: zap-28cf0c8a and zap-e50391e9 each claim the other as the original
- cross-source: zap-4d0c58ff (zap) claimed as duplicate of nmap-68fc8788 (nmap)
- mutual: zap-6b914d64 and zap-706cff2a each claim the other as the original
- cross-source: zap-72f8cd8c (zap) claimed as duplicate of nmap-68fc8788 (nmap)
- cross-source: zap-85307566 (zap) claimed as duplicate of nmap-68fc8788 (nmap)
- cross-source: zap-afa85b4d (zap) claimed as duplicate of nmap-68fc8788 (nmap)
- cross-source: zap-b859431a (zap) claimed as duplicate of nmap-68fc8788 (nmap)
- cross-source: zap-c6a841eb (zap) claimed as duplicate of nmap-68fc8788 (nmap)

**`qwen2.5:3b`**
- cross-source: nmap-68fc8788 (nmap) claimed as duplicate of zap-b859431a (zap)
- mutual: zap-28cf0c8a and zap-e50391e9 each claim the other as the original
- cycle: zap-6b914d64 -> zap-afa85b4d -> zap-c6a841eb -> zap-6b914d64

