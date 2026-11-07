"""The seller's commit checks return the code § 5.6.1 names first."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from demo_types.stack import Commit
from seller.errors import OfferError
from seller.offers import _checks
from shared.documents import load_yaml

SEED = load_yaml(Path(__file__).parent.parent / "seller" / "seed" / "proposal.yaml")


def _commit(line_item: str, *, version: int = 1, pricing_id: str | None = None) -> Commit:
    commitment = {"basis": "spend", "amount": 50000.0, "advertisers": [{"domain": "brand-a.example"}],
                  "flight": {"start": "2029-11-02T00:00:00Z", "end": "2029-12-21T23:59:59Z"}}
    if pricing_id:
        commitment["pricing_id"] = pricing_id
    return Commit.model_validate({
        "entry": {"role": "commitment", "version": version, "record_digest": "sha256:" + "0" * 64,
                  "line_item_ids": [line_item], "at": "2029-01-01T00:00:00Z",
                  "idempotency_key": "k"},
        "writes": {line_item: {"commitment": commitment}},
    })


def _code(commit: Commit, now: datetime) -> str:
    with pytest.raises(OfferError) as e:
        _checks(SEED, [], commit, now)
    return e.value.error["code"]


def test_expired_comes_first():
    after_end = datetime(2030, 1, 5, tzinfo=UTC)
    assert _code(_commit("no-such-line-item"), after_end) == "expired"
    after_price = datetime(2029, 11, 20, tzinfo=UTC)
    assert _code(_commit("business-daily-display", pricing_id="bd-cpm-usd", version=0),
                 after_price) == "expired"


def test_stale_version_comes_before_anything_the_new_version_lacks():
    now = datetime(2027, 1, 1, tzinfo=UTC)
    assert _code(_commit("weather-app-ctv", version=0, pricing_id="old-entry"), now) == "stale_version"
    assert _code(_commit("no-such-line-item", version=0), now) == "stale_version"


def test_otherwise_record_mismatch():
    assert _code(_commit("weather-app-ctv"), datetime(2027, 1, 1, tzinfo=UTC)) == "record_mismatch"
