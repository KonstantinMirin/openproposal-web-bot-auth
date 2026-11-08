"""The binding record, its digest, and the composed record (OpenProposal 3.0 § 4.1.1).

Both parties run these functions, so both compute the same `record_digest` from
the same document and writes. Everything here works over the raw JSON, never
over a parsed SDK value: the digest input keeps the members a receiver doesn't
know and every value exactly as written. The canonical form is RFC 8785, from
the `rfc8785` package; this module owns only the steps § 4.1.1 defines.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Iterator, Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal

from openproposal import Digest, LineItem, LineItemWrites, Proposal, dump
from pydantic import BaseModel

from .values import JsonObject, JsonValue, canonical, objects, strings

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

#: The arrays of a package that hold line items (§ 3.1 `Package`).
PACKAGE_CONTAINERS = ("line_items", "add_ons")


def _expand(path: str) -> list[tuple[str, ...]]:
    """A § 4.1.1 path as parts. A `$.line_items[*]` path also names each package's arrays."""
    parts = tuple(path.removeprefix("$.").split("."))
    if parts[0] != "line_items[*]":
        return [parts]
    under = [("packages[*]", f"{key}[*]", *parts[1:]) for key in PACKAGE_CONTAINERS]
    return [parts, *under]


#: REMOVED_PATHS, expanded once into the concrete paths a document can hold.
_REMOVALS = tuple(parts for path in REMOVED_PATHS for parts in _expand(path))
#: The WRITE_PATHS a write names exactly.
_EXACT_WRITES = frozenset(p for p in WRITE_PATHS if p[0] != "*")
#: What a wildcard WRITE_PATHS entry allows under a field: `selected` or `value`.
_FIELD_WRITES = frozenset(p[1:] for p in WRITE_PATHS if p[0] == "*")
_SELECTED = ("selected",)
#: The longest path a write can name.
MAX_WRITE_DEPTH = max(map(len, WRITE_PATHS))
#: `frequency_cap` is settable only at `count.value`, which WRITE_PATHS names exactly.
_NOT_A_FIELD_WRITE = "frequency_cap"


class WriteError(ValueError):
    """A `LineItemWrites` value names a path § 3.4 doesn't list."""

    def __init__(self, path: tuple[str, ...]) -> None:
        super().__init__(f"/{'/'.join(path)} is not a buyer write (§ 3.4)")


# ── Where line items live ──────────────────────────────────────────────────


def _places(doc: JsonObject | Proposal) -> Iterator[tuple[JsonObject | BaseModel, str]]:
    """Where the line items live: `line_items[]`, or each package's `PACKAGE_CONTAINERS`.

    It is the one place that knows the two forms a document takes. It names each
    array by its holder and member, so the raw JSON and the parsed `Proposal`
    are walked the same way.
    """
    packages: object
    if isinstance(doc, dict):
        packaged, packages = "packages" in doc, doc.get("packages")
    else:
        packaged, packages = doc.packages is not None, doc.packages
    if not packaged:
        yield doc, "line_items"
        return
    for package in packages if isinstance(packages, list) else []:
        if isinstance(package, dict | BaseModel):
            yield from ((package, key) for key in PACKAGE_CONTAINERS)


def line_item_containers(doc: JsonObject) -> Iterator[list[JsonValue]]:
    """The arrays of the raw JSON that hold the line items, in document order."""
    for holder, key in _places(doc):
        container = holder.get(key) if isinstance(holder, dict) else None
        if isinstance(container, list):
            yield container


def line_items_of(doc: JsonObject) -> list[JsonObject]:
    """Every line item, in document order."""
    return [item for c in line_item_containers(doc) for item in objects(c)]


def items_by_id(doc: JsonObject) -> dict[str, JsonObject]:
    """Every line item, by `line_item_id`."""
    return {str(item.get("line_item_id")): item for item in line_items_of(doc)}


def proposal_items(proposal: Proposal) -> dict[str, LineItem]:
    """Every line item of a parsed proposal, by `line_item_id`: `items_by_id`, typed."""
    items = [
        item
        for holder, key in _places(proposal)
        for item in getattr(holder, key, None) or []
        if isinstance(item, LineItem)
    ]
    return {item.line_item_id: item for item in items}


# ── The binding record ─────────────────────────────────────────────────────


def _restrict(record: JsonObject, named: set[str]) -> None:
    """Keeps the line items in `named`, in document order, and the packages that hold one."""
    for container in line_item_containers(record):
        container[:] = [i for i in objects(container) if i.get("line_item_id") in named]
    if "packages" in record:
        packages = objects(record["packages"])
        kept: list[JsonValue] = [p for p in packages if any(p.get(k) for k in PACKAGE_CONTAINERS)]
        record["packages"] = kept


def _remove(node: JsonValue, parts: tuple[str, ...]) -> None:
    if not parts or not isinstance(node, dict):
        return
    head, rest = parts[0], parts[1:]
    if head.endswith("[*]"):
        items = node.get(head[:-3])
        for item in items if isinstance(items, list) else []:
            _remove(item, rest)
    elif not rest:
        node.pop(head, None)
    else:
        _remove(node.get(head), rest)


def _strip(record: JsonObject) -> None:
    """Removes every § 4.1.1 path."""
    for parts in _REMOVALS:
        _remove(record, parts)


def _drop_empty_buyer_supplied(record: JsonObject) -> None:
    """The one exception: a `buyer_supplied` that holds no key is removed too."""
    for item in line_items_of(record):
        if item.get("buyer_supplied") == {}:
            del item["buyer_supplied"]


def binding_record(doc: JsonObject, line_item_ids: Sequence[str]) -> JsonObject:
    """The binding record of `doc` for the line items in `line_item_ids`."""
    record = copy.deepcopy(doc)
    _restrict(record, set(line_item_ids))
    _strip(record)
    _drop_empty_buyer_supplied(record)
    return record


def digest_input(doc: JsonObject, line_item_ids: Sequence[str]) -> bytes:
    """The RFC 8785 serialization of the binding record, as UTF-8."""
    return canonical(binding_record(doc, line_item_ids))


def sha256_hex(data: bytes) -> str:
    """The SHA-256 of `data`, as 64 lowercase hexadecimal characters."""
    return hashlib.sha256(data).hexdigest()


def digest_of(data: bytes) -> Digest:
    """A § 2.2 `Digest`: `sha256:` and 64 lowercase hexadecimal characters."""
    return "sha256:" + sha256_hex(data)


def record_digest(doc: JsonObject, line_item_ids: Sequence[str]) -> Digest:
    return digest_of(digest_input(doc, line_item_ids))


# ── The committed entry and its rate ───────────────────────────────────────


def committed_entry(item: JsonObject) -> JsonObject | None:
    """The `pricing[]` entry the commitment is under (§ 5.6)."""
    commitment, entries = item.get("commitment"), objects(item.get("pricing"))
    if not isinstance(commitment, dict) or not commitment:
        return None
    named = commitment.get("pricing_id")
    if named is None:
        return entries[0] if len(entries) == 1 else None
    return next((e for e in entries if e.get("pricing_id") == named), None)


def _number(value: JsonValue) -> Decimal:
    return Decimal(str(value)) if isinstance(value, int | float) else Decimal(0)


def agreed_rate(item: JsonObject, entry: JsonObject) -> float:
    """`agreed_rate` on the committed entry (§ 5.6): exact decimal, rounded once, half up."""
    cpm, factor = Decimal(0), Decimal(1)
    impressions = entry.get("cost_method") in IMPRESSION_COST_METHODS
    for value in item.values():
        if not isinstance(value, dict) or "available" not in value:
            continue  # not a selectable field
        included = strings(value.get("included"))
        selected = strings(value["selected"]) if "selected" in value else included
        in_effect = [n for n in selected if n not in included]
        in_effect += strings(value.get("excluded"))  # § 5.3: excluded audience options
        deltas = value.get("deltas")
        for name in in_effect:
            delta = deltas.get(name) if isinstance(deltas, dict) else None
            if not isinstance(delta, dict):
                delta = {}
            if impressions:
                cpm += _number(delta.get("delta_cpm", 0))
            factor *= 1 + _number(delta.get("delta_fraction", 0))
    rate = (_number(entry.get("list_rate")) + cpm) * factor
    return float(rate.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP))


# ── § 3.4 buyer writes ─────────────────────────────────────────────────────


def _is_field_write(path: tuple[str, ...], item: JsonObject) -> bool:
    """`<field>.selected` on a selectable field, or `<field>.value` on a settable one."""
    if path[1:] not in _FIELD_WRITES or path[0] == _NOT_A_FIELD_WRITE:
        return False
    field = item.get(path[0])
    return isinstance(field, dict) and (path[1:] != _SELECTED or "available" in field)


def _is_write_path(path: tuple[str, ...], item: JsonObject) -> bool:
    return path in _EXACT_WRITES or _is_field_write(path, item)


def _write_leaves(
    node: JsonObject, item: JsonObject, prefix: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], JsonValue]]:
    """The (path, value) pairs a `LineItemWrites` sets; raises `WriteError` for any other path."""
    for key, value in node.items():
        path = (*prefix, key)
        if _is_write_path(path, item):
            yield path, value
        elif isinstance(value, dict) and len(path) < MAX_WRITE_DEPTH:
            yield from _write_leaves(value, item, path)
        else:
            raise WriteError(path)


def _apply(item: JsonObject, writes: LineItemWrites) -> None:
    """Sets, in place, each key `writes` names on `item`, and nothing else."""
    raw: JsonObject = dump(writes)
    for path, value in list(_write_leaves(raw, item)):
        node = item
        for key in path[:-1]:
            child = node.setdefault(key, {})
            if not isinstance(child, dict):
                raise WriteError(path)
            node = child
        node[path[-1]] = value


def apply_writes(item: JsonObject, writes: LineItemWrites) -> JsonObject:
    """The line item with `writes` applied: each write sets the key it names and nothing else."""
    out = copy.deepcopy(item)
    _apply(out, writes)
    return out


def compose(doc: JsonObject, writes: Mapping[str, LineItemWrites]) -> JsonObject:
    """The composed record: `doc` with the buyer's writes applied (§ 4.1.1).

    On each line item with a `commitment`, it sets the derived `agreed_rate` of
    the committed entry before anything is serialized.
    """
    composed = copy.deepcopy(doc)
    for item in line_items_of(composed):
        name = item.get("line_item_id")
        if isinstance(name, str) and name in writes:
            _apply(item, writes[name])
        entry = committed_entry(item)
        if entry is not None:
            entry["agreed_rate"] = agreed_rate(item, entry)
    return composed
