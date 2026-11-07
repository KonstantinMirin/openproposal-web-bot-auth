"""One conformance vector per § 4.1.1 removed path and per § 3.4 write path, and the packages form.

Each removed path gets a value inserted, and the digest must not move; a
member beside it that the binding record keeps must move it. Each write path
must land where it names. So deleting any entry of REMOVED_PATHS or WRITE_PATHS
fails a test here. Every inserted value is a value of its generated type, so
each vector document still validates as `Proposal`.

tests/fixtures/proposal-package.yaml and line-item-display.yaml are unchanged
copies of the OpenProposal 3.0 examples of the same name.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from openproposal import LineItemWrites, Proposal

from protocol.documents import load_yaml
from protocol.record import (
    REMOVED_PATHS,
    WRITE_PATHS,
    WriteError,
    apply_writes,
    binding_record,
    compose,
    line_items_of,
    record_digest,
)
from protocol.values import JsonObject, JsonValue
from seller.seed import issued_document

FIXTURES = Path(__file__).parent / "fixtures"
PLAN = load_yaml(Path(__file__).parent.parent / "buyer" / "plan.yaml")
ISSUED = load_yaml(FIXTURES / "proposal-issued.yaml")
AGREED = load_yaml(FIXTURES / "proposal-agreed.yaml")
NAMED = ["business-daily-display"]


def _base() -> JsonObject:
    """The demo's issued proposal, composed with the buyer's plan, so it has a commitment."""
    issued = issued_document("demo-wba-1", "Demo Buyer Agency LLC", "buyer.wba-demo.noetis.dev")
    return compose(issued, {n: LineItemWrites.model_validate(PLAN[n]) for n in NAMED})


def _first(value: JsonValue) -> JsonObject:
    assert isinstance(value, list) and isinstance(value[0], dict)
    return value[0]


#: A value of the member's generated type, for each removed path.
INSERTED: dict[str, JsonValue] = {
    "$.version": 9,
    "$.status": "under_review",
    "$.assent": AGREED["assent"],
    "$.negotiation_history": AGREED["negotiation_history"],
    "$.change_requests": ISSUED["change_requests"],
    "$.best_for": ["Brand campaigns in Q4"],
    "$.not_suitable_for": ["Performance-only buys"],
    "$.seasonality_notes": "Demand peaks in late November.",
    "$.line_items[*].status": "agreed",
    "$.line_items[*].availability": {
        "certainty": "forecast",
        "computed_at": "2026-10-04T09:00:00Z",
        "quantity": 1000000,
        "unit": "impressions",
        "window": {"start": "2026-11-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
    },
    "$.line_items[*].addressable_scale": load_yaml(FIXTURES / "line-item-display.yaml")[
        "addressable_scale"
    ],
    "$.line_items[*].assets": [{"asset_id": "asset-1", "format_id": "display/300x250"}],
    "$.line_items[*].buyer_supplied.expected_match_rate": 0.4,
    "$.line_items[*].buyer_supplied.segments": [{"list_id": "segment-1"}],
    "$.line_items[*].buyer_supplied.suppression_list": {"list_id": "suppression-1"},
    "$.line_items[*].pricing[*].min_rate": 20.0,
    "$.line_items[*].hold": next(i["hold"] for i in line_items_of(ISSUED) if "hold" in i),
    "$.line_items[*].commitment.derived_units": 3333333,
    "$.line_items[*].external_references": _first(AGREED["line_items"])["external_references"],
}

#: For each removed path's parent, a member the binding record keeps, and a new value for it.
KEPT_SIBLING: dict[str, tuple[str, JsonValue]] = {
    "$": ("description", "Another description."),
    "$.line_items[*]": ("time_zone", "UTC"),
    "$.line_items[*].buyer_supplied": ("suppression_allowed", False),
    "$.line_items[*].pricing[*]": ("list_rate", 25.0),
    "$.line_items[*].commitment": ("amount", 90000.0),
}


def _set(doc: JsonObject, path: str, value: JsonValue) -> None:
    """Sets `path` in `doc`; a `[*]` step means the first entry, the line item `NAMED` names."""
    *parents, last = path.removeprefix("$.").split(".")
    node = doc
    for part in parents:
        node = _first(node[part[:-3]]) if part.endswith("[*]") else _object(node[part])
    node[last] = copy.deepcopy(value)


def _object(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def test_every_removed_path_has_a_vector() -> None:
    assert set(INSERTED) == set(REMOVED_PATHS)


@pytest.mark.parametrize("path", list(INSERTED))
def test_a_removed_path_moves_no_digest(path: str) -> None:
    doc = _base()
    before = record_digest(doc, NAMED)
    _set(doc, path, INSERTED[path])
    Proposal.model_validate(doc)  # still a proposal
    assert record_digest(doc, NAMED) == before


@pytest.mark.parametrize("path", list(INSERTED))
def test_a_kept_sibling_moves_the_digest(path: str) -> None:
    parent = path.rsplit(".", 1)[0]
    member, value = KEPT_SIBLING[parent]
    doc = _base()
    before = record_digest(doc, NAMED)
    _set(doc, f"{parent}.{member}", value)
    assert record_digest(doc, NAMED) != before


# ── The packages form ──────────────────────────────────────────────────────

PACKAGE = load_yaml(FIXTURES / "proposal-package.yaml")


def test_the_package_example_is_a_proposal() -> None:
    Proposal.model_validate(PACKAGE)


def test_line_items_of_a_package_include_its_add_ons() -> None:
    assert [i["line_item_id"] for i in line_items_of(PACKAGE)] == [
        "streaming-audio",
        "weather-app-ctv",
        "weather-app-ctv-bonus",
    ]


def test_the_binding_record_keeps_only_the_named_items_and_their_package() -> None:
    record = binding_record(PACKAGE, ["weather-app-ctv-bonus"])
    package = _first(record["packages"])
    assert package["line_items"] == []
    assert [i["line_item_id"] for i in line_items_of(record)] == ["weather-app-ctv-bonus"]
    assert binding_record(PACKAGE, ["no-such-item"])["packages"] == []


@pytest.mark.parametrize("name", ["streaming-audio", "weather-app-ctv-bonus"])
def test_removed_paths_apply_inside_packages(name: str) -> None:
    doc = copy.deepcopy(PACKAGE)
    item = next(i for i in line_items_of(doc) if i["line_item_id"] == name)
    before = record_digest(doc, [name])
    item["status"] = "agreed"
    assert record_digest(doc, [name]) == before
    item["time_zone"] = "UTC"
    assert record_digest(doc, [name]) != before


# ── § 3.4 write paths ──────────────────────────────────────────────────────

DISPLAY = load_yaml(FIXTURES / "line-item-display.yaml")
COMMITMENT: JsonObject = {
    "pricing_id": _first(DISPLAY["pricing"])["pricing_id"],
    "basis": "spend",
    "amount": 50000.0,
    "advertisers": [{"domain": "brand-a.example"}],
    "flight": {"start": "2026-11-02T00:00:00Z", "end": "2026-12-21T23:59:59Z"},
}

#: (write path, the LineItemWrites member that writes it, the value it lands)
WRITES: list[tuple[tuple[str, ...], JsonObject, JsonValue]] = [
    (("commitment",), {}, COMMITMENT),
    (("exclusions",), {"exclusions": {"domains": ["x.example"]}}, {"domains": ["x.example"]}),
    (
        ("buyer_requirements", "seats"),
        {"buyer_requirements": {"seats": {"dsp": "dsp-a.example", "ids": ["s-1"]}}},
        {"dsp": "dsp-a.example", "ids": ["s-1"]},
    ),
    (
        ("buyer_requirements", "seat_owner"),
        {"buyer_requirements": {"seat_owner": {"domain": "agency-a.example"}}},
        {"domain": "agency-a.example"},
    ),
    (
        ("audiences", "excluded"),
        {"audiences": {"excluded": ["cfo-finance-leaders"]}},
        ["cfo-finance-leaders"],
    ),
    (
        ("audiences", "combine", "selected"),
        {"audiences": {"combine": {"selected": ["all"]}}},
        ["all"],
    ),
    (("frequency_cap", "count", "value"), {"frequency_cap": {"count": {"value": 4}}}, 4),
    (("formats", "selected"), {"formats": {"selected": ["display/728x90"]}}, ["display/728x90"]),
    (("geo", "value"), {"geo": {"value": {"include": ["US-NY"]}}}, {"include": ["US-NY"]}),
]


def _leaf(node: JsonValue, path: tuple[str, ...]) -> JsonValue:
    for key in path:
        assert isinstance(node, dict)
        node = node[key]
    return node


def test_every_write_path_has_a_vector() -> None:
    wildcards = {p[1:] for p in WRITE_PATHS if p[0] == "*"}
    covered = {p for p, _, _ in WRITES if p in WRITE_PATHS} | {
        ("*", *p[1:]) for p, _, _ in WRITES if p[1:] in wildcards
    }
    assert covered >= set(WRITE_PATHS)


@pytest.mark.parametrize(("path", "member", "value"), WRITES, ids=[".".join(w[0]) for w in WRITES])
def test_a_write_path_lands_where_it_names(
    path: tuple[str, ...], member: JsonObject, value: JsonValue
) -> None:
    writes = LineItemWrites.model_validate({"commitment": COMMITMENT, **member})
    written = apply_writes(DISPLAY, writes)
    assert _leaf(written, path) == value
    # Everything beside the write stays as it was.
    parent = path[:-1]
    if parent:
        before, after = _leaf(DISPLAY, parent), _leaf(written, parent)
        assert isinstance(before, dict) and isinstance(after, dict)
        assert {k: v for k, v in after.items() if k != path[-1]} == before


def test_a_write_to_a_field_the_line_item_lacks_is_refused() -> None:
    item = {k: v for k, v in DISPLAY.items() if k != "daypart"}
    daypart = {"value": {"include": [{"days": ["monday"], "start": "06:00", "before": "22:00"}]}}
    writes = LineItemWrites.model_validate({"commitment": COMMITMENT, "daypart": daypart})
    with pytest.raises(WriteError):
        apply_writes(item, writes)


def test_writes_are_applied_to_a_copy() -> None:
    before = copy.deepcopy(DISPLAY)
    apply_writes(DISPLAY, LineItemWrites.model_validate({"commitment": COMMITMENT}))
    assert before == DISPLAY
