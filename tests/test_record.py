"""The record rules reproduce the digests the specification's examples carry.

tests/fixtures holds unchanged copies of examples/proposal-issued.yaml and
examples/proposal-agreed.yaml from the OpenProposal 3.0 text.
"""

from pathlib import Path

import pytest
from openproposal import AssentEntry, LineItemWrites

from protocol.attribution import attributes
from protocol.documents import load_yaml
from protocol.record import WriteError, apply_writes, compose, line_items_of, record_digest
from protocol.values import JsonObject, objects, strings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "proposal-issued.yaml",
            "sha256:72e0993149a037d841e7b6611abd5abd7cff810151c211ce04653862f1f05aed",
        ),
        (
            "proposal-agreed.yaml",
            "sha256:a9290958d7f148d212b552b51b6cc3ccca86edbc817f2058252b3ee9d7d3a10a",
        ),
    ],
)
def test_record_digest_reproduces_the_examples(name: str, expected: str) -> None:
    doc = load_yaml(FIXTURES / name)
    for entry in objects(doc["assent"]):
        ids = strings(entry["line_item_ids"])
        assert AssentEntry.model_validate(entry).record_digest == expected
        assert record_digest(doc, ids) == expected
        # Recomputing the derived agreed_rate (§ 4.1.1) changes nothing.
        assert record_digest(compose(doc, {}), ids) == expected


def _first_item(doc: JsonObject) -> JsonObject:
    return line_items_of(doc)[0]


def test_an_empty_buyer_supplied_moves_no_digest() -> None:
    doc = load_yaml(FIXTURES / "proposal-agreed.yaml")
    ids = [str(_first_item(doc)["line_item_id"])]
    before = record_digest(doc, ids)
    _first_item(doc)["buyer_supplied"] = {"expected_match_rate": 0.5}
    assert record_digest(doc, ids) == before


COMMITMENT = {
    "basis": "spend",
    "amount": 1000.0,
    "advertisers": [{"domain": "brand-a.example"}],
    "flight": {"start": "2026-11-02T00:00:00Z", "end": "2026-12-21T23:59:59Z"},
}


def _properties(item: JsonObject) -> JsonObject:
    properties = item["properties"]
    assert isinstance(properties, dict)
    return properties


def test_writes_set_only_the_keys_they_name() -> None:
    item = line_items_of(load_yaml(FIXTURES / "proposal-issued.yaml"))[1]
    writes = {"commitment": COMMITMENT, "properties": {"selected": ["weather-app"]}}
    written = apply_writes(item, LineItemWrites.model_validate(writes))
    assert _properties(written)["selected"] == ["weather-app"]
    assert _properties(written)["available"] == _properties(item)["available"]
    with pytest.raises(WriteError):
        # The line item has no `daypart`, so there is nothing settable to write.
        daypart = {
            "value": {"include": [{"days": ["monday"], "start": "06:00", "before": "22:00"}]}
        }
        apply_writes(item, LineItemWrites.model_validate({**writes, "daypart": daypart}))


@pytest.mark.parametrize(
    ("host", "domain", "covered", "expected"),
    [
        ("buyer.wba-demo.noetis.dev", "buyer.wba-demo.noetis.dev", True, True),
        ("signing.agency-a.com", "agency-a.com", True, True),
        ("agency-a.com.evil.com", "agency-a.com", True, False),
        ("buyer.wba-demo.noetis.dev", "buyer.wba-demo.noetis.dev", False, False),
        ("anything.github.io", "github.io", True, False),  # a public suffix names no party
    ],
)
def test_attribution(host: str, domain: str, covered: bool, expected: bool) -> None:
    assert attributes(host, domain, body_covered=covered) is expected
