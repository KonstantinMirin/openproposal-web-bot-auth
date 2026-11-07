"""The binding record, its digest, and the composed record (OpenProposal 3.0 § 4.1.1).

Both parties run these functions, so both compute the same `record_digest` from
the same document and writes. The canonical form is RFC 8785, from the
`rfc8785` package; this module owns only the steps § 4.1.1 defines.
"""

from __future__ import annotations

import copy
import hashlib
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

import rfc8785

#: The paths § 4.1.1 removes from the binding record, and no others.
REMOVED_PATHS = (
    "$.version",
    "$.status",
    "$.assent",
    "$.negotiation_history",
    "$.change_requests",
    "$.best_for",
    "$.not_suitable_for",
    "$.seasonality_notes",
    "$.line_items[*].status",
    "$.line_items[*].availability",
    "$.line_items[*].addressable_scale",
    "$.line_items[*].assets",
    "$.line_items[*].buyer_supplied.expected_match_rate",
    "$.line_items[*].buyer_supplied.segments",
    "$.line_items[*].buyer_supplied.suppression_list",
    "$.line_items[*].pricing[*].min_rate",
    "$.line_items[*].hold",
    "$.line_items[*].commitment.derived_units",
    "$.line_items[*].external_references",
)

#: Cost methods whose rate a `delta_cpm` enters (§ 5.6, § 3.1).
IMPRESSION_COST_METHODS = ("CPM", "CPMV")

#: The § 3.4 `BuyerWrites` paths, plus `commitment` from `LineItemWrites`.
#: `*` stands for a `selectable` field (`.selected`) or a `settable` one (`.value`).
WRITE_PATHS = (
    ("commitment",),
    ("exclusions",),
    ("buyer_requirements", "seats"),
    ("buyer_requirements", "seat_owner"),
    ("audiences", "excluded"),
    ("audiences", "combine", "selected"),
    ("frequency_cap", "count", "value"),
    ("*", "selected"),
    ("*", "value"),
)


class WriteError(ValueError):
    """A `LineItemWrites` value names a path § 3.4 doesn't list."""


def line_items_of(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Every line item: `line_items[]`, or each package's `line_items[]` and `add_ons[]`."""
    if "packages" in doc:
        return [i for p in doc["packages"] for i in p.get("line_items", []) + p.get("add_ons", [])]
    return doc.get("line_items", [])


def _remove(node: Any, parts: list[str]) -> None:
    if not parts or not isinstance(node, dict):
        return
    head, rest = parts[0], parts[1:]
    if head.endswith("[*]"):
        for item in node.get(head[:-3]) or []:
            _remove(item, rest)
    elif not rest:
        node.pop(head, None)
    else:
        _remove(node.get(head), rest)


def binding_record(doc: dict[str, Any], line_item_ids: list[str]) -> dict[str, Any]:
    """The binding record of `doc` for the line items in `line_item_ids`."""
    record = copy.deepcopy(doc)
    named = set(line_item_ids)
    # Restrict to S, in document order however S is named.
    if "packages" in record:
        for package in record["packages"]:
            for key in ("line_items", "add_ons"):
                if key in package:
                    package[key] = [i for i in package[key] if i["line_item_id"] in named]
        record["packages"] = [
            p for p in record["packages"] if p.get("line_items") or p.get("add_ons")
        ]
    else:
        record["line_items"] = [
            i for i in record.get("line_items", []) if i["line_item_id"] in named
        ]
    for path in REMOVED_PATHS:
        parts = path.removeprefix("$.").split(".")
        _remove(record, parts)
        # Each $.line_items[*] path also selects the same path under each package.
        if parts[0] == "line_items[*]":
            for package in record.get("packages", []):
                for key in ("line_items", "add_ons"):
                    _remove(package, [f"{key}[*]", *parts[1:]])
    # The one exception: a buyer_supplied that holds no key is removed too.
    for item in line_items_of(record):
        if item.get("buyer_supplied") == {}:
            del item["buyer_supplied"]
    return record


def digest_input(doc: dict[str, Any], line_item_ids: list[str]) -> bytes:
    """The RFC 8785 serialization of the binding record, as UTF-8."""
    return rfc8785.dumps(binding_record(doc, line_item_ids))


def digest_of(data: bytes) -> str:
    """A § 2.2 `Digest`: `sha256:` and 64 lowercase hexadecimal characters."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def record_digest(doc: dict[str, Any], line_item_ids: list[str]) -> str:
    return digest_of(digest_input(doc, line_item_ids))


def committed_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    """The `pricing[]` entry the commitment is under (§ 5.6)."""
    commitment, entries = item.get("commitment"), item.get("pricing") or []
    if not isinstance(commitment, dict) or not commitment:
        return None
    named = commitment.get("pricing_id")
    if named is None:
        return entries[0] if len(entries) == 1 else None
    return next((e for e in entries if e.get("pricing_id") == named), None)


def agreed_rate(item: dict[str, Any], entry: dict[str, Any]) -> float:
    """`agreed_rate` on the committed entry (§ 5.6): exact decimal, rounded once, half up."""
    cpm, factor = Decimal(0), Decimal(1)
    for value in item.values():
        if not isinstance(value, dict) or "available" not in value:
            continue  # not a selectable field
        included = value.get("included", [])
        in_effect = [n for n in value.get("selected", included) if n not in included]
        in_effect += value.get("excluded", [])  # § 5.3: excluded audience options
        for name in in_effect:
            delta = (value.get("deltas") or {}).get(name, {})
            if entry.get("cost_method") in IMPRESSION_COST_METHODS:
                cpm += Decimal(str(delta.get("delta_cpm", 0)))
            factor *= 1 + Decimal(str(delta.get("delta_fraction", 0)))
    rate = (Decimal(str(entry["list_rate"])) + cpm) * factor
    return float(rate.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP))


def _write_leaves(
    writes: dict[str, Any], item: dict[str, Any]
) -> list[tuple[tuple[str, ...], Any]]:
    """The (path, value) pairs a `LineItemWrites` sets; raises `WriteError` for any other path."""
    leaves: list[tuple[tuple[str, ...], Any]] = []

    def listed(path: tuple[str, ...]) -> bool:
        for pattern in WRITE_PATHS:
            if len(pattern) != len(path):
                continue
            if pattern[0] == "*":
                field = item.get(path[0])
                if not isinstance(field, dict) or path[0] == "frequency_cap":
                    continue
                if path[1] == "selected" and "available" not in field:
                    continue
                if path[1:] == pattern[1:]:
                    return True
            elif pattern == path:
                return True
        return False

    def walk(node: dict[str, Any], prefix: tuple[str, ...]) -> None:
        for key, value in node.items():
            path = (*prefix, key)
            if listed(path):
                leaves.append((path, value))
            elif isinstance(value, dict) and len(path) < 3:
                walk(value, path)
            else:
                raise WriteError(f"/{'/'.join(path)} is not a buyer write (§ 3.4)")

    walk(writes, ())
    return leaves


def apply_writes(item: dict[str, Any], writes: dict[str, Any]) -> dict[str, Any]:
    """The line item with `writes` applied: each write sets the key it names and nothing else."""
    out = copy.deepcopy(item)
    for path, value in _write_leaves(writes, item):
        node = out
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = copy.deepcopy(value)
    return out


def compose(doc: dict[str, Any], writes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The composed record: `doc` with the buyer's writes applied (§ 4.1.1).

    On each line item with a `commitment`, it sets the derived `agreed_rate` of
    the committed entry before anything is serialized.
    """
    composed = copy.deepcopy(doc)
    for item in line_items_of(composed):
        if item["line_item_id"] in writes:
            item.update(apply_writes(item, writes[item["line_item_id"]]))
        entry = committed_entry(item)
        if entry is not None:
            entry["agreed_rate"] = agreed_rate(item, entry)
    return composed
