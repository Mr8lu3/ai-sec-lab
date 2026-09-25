"""Keyword retrieval for the document Q&A target.

Deliberately not embeddings and not a vector database. Reasons, in order of importance:
  1. It is ~60 lines of pure, deterministic logic that a reviewer can read and pytest can test.
  2. It removes a heavyweight dependency and an extra model download from a CPU-only laptop.
  3. Retrieval quality is not what this project is measuring — the attack surface is.

Scoring is IDF-weighted term overlap: terms that appear in few documents count for more,
which is the useful half of TF-IDF without the machinery.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

_WORD = re.compile(r"[a-z0-9]+")

# Function words carry no topical signal but appear in nearly every chunk. Without removing
# them, a query like "what is the holiday allowance for new starters?" scores mostly on
# "what/is/the/for": their IDF weight is small, but it is multiplied by how often they occur,
# so a long chunk full of common words outranks the short chunk that actually answers the
# question. Dropping them is the standard fix and keeps scoring explainable.
STOPWORDS = frozenset("""
a an and are as at be but by can do does for from had has have how i if in into is it its
me my no not of on or our should so than that the their them then there these they this to
until was we were what when where which who why will with would you your
""".split())


def tokenize(text: str, drop_stopwords: bool = False) -> list[str]:
    tokens = _WORD.findall(text.lower())
    if drop_stopwords:
        tokens = [t for t in tokens if t not in STOPWORDS]
    return tokens


@dataclass(frozen=True)
class Chunk:
    source: str      # filename it came from
    text: str

    @property
    def is_confidential(self) -> bool:
        return "CONFIDENTIAL" in self.text or "CONFIDENTIAL" in self.source


def split_into_chunks(source: str, text: str) -> list[Chunk]:
    """Split a document on markdown headings, falling back to the whole document.

    Heading-sized chunks keep retrieved context small, which matters here: every extra token
    of context is extra prompt-processing time on a CPU-only machine.
    """
    parts = re.split(r"\n(?=## )", text.strip())
    return [Chunk(source=source, text=p.strip()) for p in parts if p.strip()]


def load_corpus(corpus_dir: Path) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted(corpus_dir.glob("*.md")):
        # encoding is explicit: Windows Python defaults to cp1252 and this corpus is UTF-8.
        chunks.extend(split_into_chunks(path.name, path.read_text(encoding="utf-8")))
    return chunks


def compute_idf(chunks: list[Chunk]) -> dict[str, float]:
    n = len(chunks)
    if n == 0:
        return {}
    doc_freq: dict[str, int] = {}
    for chunk in chunks:
        for term in set(tokenize(chunk.text)):
            doc_freq[term] = doc_freq.get(term, 0) + 1
    # +1 smoothing keeps a term present in every chunk at a small positive weight, not zero.
    return {term: math.log((n + 1) / (df + 1)) + 1.0 for term, df in doc_freq.items()}


def score_chunk(query: str, chunk: Chunk, idf: dict[str, float]) -> float:
    # Stopwords are dropped from the QUERY only. The chunk keeps its full token count so the
    # length normalisation below still reflects the real size of the text.
    query_terms = set(tokenize(query, drop_stopwords=True))
    if not query_terms:
        return 0.0
    chunk_terms = tokenize(chunk.text)
    if not chunk_terms:
        return 0.0
    counts: dict[str, int] = {}
    for term in chunk_terms:
        counts[term] = counts.get(term, 0) + 1
    total = sum(idf.get(t, 1.0) * counts.get(t, 0) for t in query_terms)
    # Length-normalise so a long document cannot win on sheer size alone.
    return total / math.sqrt(len(chunk_terms))


def retrieve(query: str, chunks: list[Chunk], k: int) -> list[Chunk]:
    """Return the k highest-scoring chunks, best first. Ties break on source name for determinism."""
    if not chunks:
        return []
    idf = compute_idf(chunks)
    ranked = sorted(
        chunks,
        key=lambda c: (-score_chunk(query, c, idf), c.source, c.text[:40]),
    )
    return [c for c in ranked[:k] if score_chunk(query, c, idf) > 0]
