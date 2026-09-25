"""Shared data shapes for Module 1.

Kept in one small module so oracles, targets and the runner agree on what a run produced
without importing each other in a circle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


def resolve_within(root: Path, raw: str) -> tuple[Path, bool]:
    """Resolve a user-supplied path under `root` and report whether it stayed inside.

    Backslashes are normalised to forward slashes on EVERY platform. Without that, the
    payload "..\\..\\..\\windows\\win.ini" is a directory traversal on Windows but a single
    harmless filename on Linux, so the same check would reach opposite verdicts on the two
    operating systems. A security control that disagrees with itself across platforms is a
    bug, so both path styles are treated as traversal everywhere.
    """
    candidate = str(raw).replace("\\", "/")
    try:
        resolved = (root / candidate).resolve()
    except (OSError, ValueError):
        return root, False
    return resolved, resolved.is_relative_to(root)


@dataclass
class ToolCall:
    """One tool invocation attempted by the agent."""
    tool: str
    args: dict
    result: str = ""
    allowed: bool = True          # False when a defence refused it
    refusal_reason: str = ""


@dataclass
class TargetRun:
    """Everything one attack produced. Oracles read this, and only this."""
    output: str = ""                                   # final text shown to the user
    tool_calls: list[ToolCall] = field(default_factory=list)
    blocked: bool = False                              # a defence stopped the run outright
    block_reason: str = ""
    error: str = ""

    def allowed_calls(self, tool: str | None = None) -> list[ToolCall]:
        return [c for c in self.tool_calls
                if c.allowed and (tool is None or c.tool == tool)]
