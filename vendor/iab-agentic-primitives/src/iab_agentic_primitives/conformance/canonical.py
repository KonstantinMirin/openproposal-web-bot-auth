"""Canonical JSON (JavaScript Object Notation) helpers for the conformance kit.

Golden-vector byte comparison only works if both sides serialize the same
way, so the kit defines ONE canonical text form: UTF-8 JSON with sorted
object keys, compact separators, and no ASCII escaping. Both the fixture
generator and the runner go through :func:`canonical_json`, which makes
"re-serialize and byte-compare" a real equality check instead of a
whitespace lottery.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Render ``value`` (parsed JSON data) as canonical JSON text."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _render(value: Any, limit: int = 80) -> str:
    text = canonical_json(value)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def json_diff(
    expected: Any, actual: Any, path: str = "$", *, max_entries: int = 20
) -> list[dict[str, str]]:
    """Structured diff between two parsed-JSON values.

    Returns a list of ``{"path", "expected", "actual"}`` entries — the
    useful part of a failed byte-compare, so a gap report can say *which
    field* drifted instead of dumping two blobs.
    """
    diffs: list[dict[str, str]] = []

    def add(p: str, exp: Any, act: Any) -> None:
        if len(diffs) < max_entries:
            diffs.append({"path": p, "expected": _render(exp), "actual": _render(act)})

    def walk(exp: Any, act: Any, p: str) -> None:
        if len(diffs) >= max_entries:
            return
        if isinstance(exp, dict) and isinstance(act, dict):
            for key in sorted(set(exp) | set(act)):
                child = f"{p}.{key}"
                if key not in exp:
                    add(child, "<absent>", act[key])
                elif key not in act:
                    add(child, exp[key], "<absent>")
                else:
                    walk(exp[key], act[key], child)
        elif isinstance(exp, list) and isinstance(act, list):
            if len(exp) != len(act):
                add(f"{p}.length", len(exp), len(act))
            for i, (e, a) in enumerate(zip(exp, act)):
                walk(e, a, f"{p}[{i}]")
        elif exp != act or type(exp) is not type(act):
            # bool is an int subclass; True == 1 must still be a diff,
            # and 1 vs 1.0 is a wire-type difference worth reporting.
            add(p, exp, act)

    walk(expected, actual, path)
    return diffs


__all__ = ["canonical_json", "json_diff"]
