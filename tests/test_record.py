"""The record rules reproduce the digests the specification's examples carry.

tests/fixtures holds unchanged copies of examples/proposal-issued.yaml and
examples/proposal-agreed.yaml from the OpenProposal 3.0 text.
"""

from pathlib import Path

import pytest

from demo_types.stack import AssentEntry
from shared.attribution import attributes
from shared.documents import load_yaml
from shared.record import WriteError, apply_writes, compose, record_digest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("proposal-issued.yaml", "sha256:72e0993149a037d841e7b6611abd5abd7cff810151c211ce04653862f1f05aed"),
        ("proposal-agreed.yaml", "sha256:a9290958d7f148d212b552b51b6cc3ccca86edbc817f2058252b3ee9d7d3a10a"),
    ],
)
def test_record_digest_reproduces_the_examples(name, expected):
    doc = load_yaml(FIXTURES / name)
    for entry in doc["assent"]:
        assert AssentEntry.model_validate(entry).record_digest == expected
        assert record_digest(doc, entry["line_item_ids"]) == expected
        # Recomputing the derived agreed_rate (§ 4.1.1) changes nothing.
        assert record_digest(compose(doc, {}), entry["line_item_ids"]) == expected


def test_an_empty_buyer_supplied_moves_no_digest():
    doc = load_yaml(FIXTURES / "proposal-agreed.yaml")
    ids = [doc["line_items"][0]["line_item_id"]]
    before = record_digest(doc, ids)
    doc["line_items"][0]["buyer_supplied"] = {"expected_match_rate": 0.5}
    assert record_digest(doc, ids) == before


def test_writes_set_only_the_keys_they_name():
    item = load_yaml(FIXTURES / "proposal-issued.yaml")["line_items"][1]
    written = apply_writes(item, {"properties": {"selected": ["weather-app"]}})
    assert written["properties"]["selected"] == ["weather-app"]
    assert written["properties"]["available"] == item["properties"]["available"]
    with pytest.raises(WriteError):
        apply_writes(item, {"pricing": [{"list_rate": 1}]})


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
def test_attribution(host, domain, covered, expected):
    assert attributes(host, domain, body_covered=covered) is expected
