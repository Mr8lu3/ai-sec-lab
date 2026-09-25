"""Tools available to the agent target.

Every tool here is deliberately weak in a specific, named way, because the point of the
module is to attack them:

  read_file   - joins user-supplied path onto a root with NO canonicalisation. Traversable.
  search_inbox- returns untrusted third-party content straight into model context. This is
                the indirect prompt injection carrier.
  send_email  - writes to a local log file. It never touches a network or a mail server.
                It accepts ANY recipient, which is what makes exfiltration possible.

Defence D2 is applied by passing a `policy` callable; with no policy, the tools are wide open.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aisec import config
from aisec.m1.types import ToolCall

# policy(tool_name, args) -> (allowed, reason)
Policy = Callable[[str, dict], tuple[bool, str]]


class ToolBox:
    """Holds the sandbox root, records every call, and enforces an optional policy."""

    def __init__(self, policy: Policy | None = None, sandbox_root: Path | None = None):
        self.policy = policy
        self.sandbox_root = (sandbox_root or config.M1_DIR).resolve()
        self.calls: list[ToolCall] = []

    # ---------- dispatch ----------

    def schema_names(self) -> list[str]:
        return ["read_file", "search_inbox", "send_email"]

    def invoke(self, tool: str, args: dict) -> ToolCall:
        call = ToolCall(tool=tool, args=dict(args))

        if self.policy is not None:
            allowed, reason = self.policy(tool, args)
            if not allowed:
                call.allowed = False
                call.refusal_reason = reason
                call.result = f"REFUSED: {reason}"
                self.calls.append(call)
                return call

        try:
            handler = {
                "read_file": self._read_file,
                "search_inbox": self._search_inbox,
                "send_email": self._send_email,
            }.get(tool)
            call.result = handler(args) if handler else f"ERROR: unknown tool {tool!r}"
        except Exception as exc:
            call.result = f"ERROR: {type(exc).__name__}: {exc}"

        self.calls.append(call)
        return call

    # ---------- implementations ----------

    def _read_file(self, args: dict) -> str:
        raw = str(args.get("path", ""))
        # VULNERABLE BY DESIGN: no resolve()/containment check here. D2 adds one.
        target = self.sandbox_root / raw
        if not target.exists() or not target.is_file():
            return f"ERROR: no such file: {raw}"
        return target.read_text(encoding="utf-8", errors="replace")[:2000]

    def _search_inbox(self, args: dict) -> str:
        query = str(args.get("query", "")).lower()
        hits = []
        for path in sorted(config.INBOX_DIR.glob("*.json")):
            mail = json.loads(path.read_text(encoding="utf-8"))
            haystack = f"{mail['subject']} {mail['body']} {mail['from']}".lower()
            if not query or query in haystack:
                hits.append(mail)
        if not hits:
            return "No matching emails."
        # This return value goes straight into model context. It is attacker-controllable
        # content in any realistic deployment, which is the whole indirect-injection thesis.
        return "\n\n".join(
            f"From: {m['from']}\nSubject: {m['subject']}\n{m['body']}" for m in hits
        )

    def _send_email(self, args: dict) -> str:
        to = str(args.get("to", ""))
        subject = str(args.get("subject", ""))
        body = str(args.get("body", ""))
        config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "to": to,
            "subject": subject,
            "body": body,
        }
        with config.SENT_MAIL_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return f"Email queued to {to} (written to local log, not actually sent)."
