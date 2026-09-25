"""Thin Ollama wrapper.

Two jobs, and deliberately nothing more:
  1. chat()      -> free text. Used by the TARGETS, because a realistic vulnerable app
                    returns prose, not JSON.
  2. chat_json() -> schema-constrained JSON. Used by the AGENT's tool selection and by the
                    D3 output judge, because a 3B model asked for free-form structure gets it
                    wrong often enough to ruin a results table.

Every response is cached on disk by a hash of its inputs. On CPU-only hardware a single call
costs 45-90s, so without caching, regenerating the results table after any code change would
cost hours. With it, a re-run is instant.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from aisec import config


class OllamaUnavailable(RuntimeError):
    """Raised when the Ollama daemon isn't reachable, with a fix-it hint."""


def _cache_key(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


class LLMClient:
    def __init__(self, model: str = config.DEFAULT_MODEL, use_cache: bool = True):
        self.model = model
        self.use_cache = use_cache
        self.calls_made = 0      # real inference calls, i.e. cache misses
        self.cache_hits = 0
        self.total_seconds = 0.0

    # ---------- cache ----------

    def _read_cache(self, key: str) -> dict | None:
        path = config.CACHE_DIR / f"{key}.json"
        if not (self.use_cache and path.exists()):
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None  # a corrupt cache entry should never break a run

    def _write_cache(self, key: str, value: dict) -> None:
        if not self.use_cache:
            return
        config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (config.CACHE_DIR / f"{key}.json").write_text(
            json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # ---------- calls ----------

    def _call(self, messages: list[dict], fmt: dict | None,
              num_predict: int | None = None) -> dict:
        tokens = num_predict or config.NUM_PREDICT
        key_payload = {"model": self.model, "messages": messages, "format": fmt}
        # num_predict joins the cache key only when it differs from the default. Adding it
        # unconditionally would change every existing key and discard hours of cached
        # inference for calls whose behaviour did not change.
        if tokens != config.NUM_PREDICT:
            key_payload["num_predict"] = tokens
        key = _cache_key(key_payload)
        cached = self._read_cache(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        try:
            import ollama
        except ImportError as exc:  # pragma: no cover - environment problem, not logic
            raise OllamaUnavailable(
                "The 'ollama' python package is missing. Run: pip install -r requirements.txt"
            ) from exc

        started = time.time()
        try:
            client = ollama.Client(host=config.OLLAMA_HOST)
            resp = client.chat(
                model=self.model,
                messages=messages,
                format=fmt,
                options={
                    "temperature": config.TEMPERATURE,
                    "num_predict": tokens,
                },
            )
        except Exception as exc:  # ollama raises several distinct types; treat them alike
            raise OllamaUnavailable(
                f"Could not reach Ollama at {config.OLLAMA_HOST} "
                f"for model '{self.model}': {exc}\n"
                f"Check the daemon is up, the model is pulled ('ollama pull {self.model}'), "
                f"and that OLLAMA_HOST points at the right place."
            ) from exc

        elapsed = time.time() - started
        self.calls_made += 1
        self.total_seconds += elapsed

        result = {"content": resp["message"]["content"], "seconds": round(elapsed, 1)}
        self._write_cache(key, result)
        return result

    def chat(self, system: str, user: str, num_predict: int | None = None) -> str:
        """Free-text completion. Used by the deliberately-vulnerable targets."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return self._call(messages, None, num_predict)["content"]

    def chat_json(self, system: str, user: str, schema: dict,
                  num_predict: int | None = None) -> dict:
        """Schema-constrained completion.

        Ollama's `format` parameter takes a JSON Schema and constrains decoding to match it,
        so the model physically cannot emit non-conforming output. We still json.loads in a
        try/except: a model that hits the token limit can be cut off mid-document.
        """
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        raw = self._call(messages, schema, num_predict)["content"]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_parse_error": True, "_raw": raw}

    def stats(self) -> dict:
        return {
            "model": self.model,
            "inference_calls": self.calls_made,
            "cache_hits": self.cache_hits,
            "total_seconds": round(self.total_seconds, 1),
        }
