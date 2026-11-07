"""9. The buyer refuses a seller response it can't verify, then retries the same commit.

The seller's test-only fault toggle (seller/faults.py) strips the response
signature, or signs it unbound or bound to another request. Each time the
seller has accepted, but the buyer refuses the answer and records no agreement.
It then re-sends the same Commit, with the same idempotency_key. The seller
returns the stored result and writes no second entry (§ 5.6.1). Once the
response verifies, the buyer records the agreement.
"""

import pytest
from conftest import BUYER_OPERATOR, SELLER_FAULTS

COMMIT = {"proposal_id": "demo-wba-2", "line_item_ids": ["weather-app-ctv"]}


@pytest.fixture
def fault(web):
    def set_mode(mode: str) -> None:
        assert web.put(SELLER_FAULTS, json={"mode": mode}).status_code == 200

    yield set_mode
    set_mode("none")


def test_buyer_refuses_unverifiable_responses(web, fault, seller_db, buyer_db):
    for mode, reason in [("strip", "response-unsigned"), ("unbound", "response-not-bound"),
                         ("rebound", "signature-invalid")]:
        fault(mode)
        outcome = web.post(f"{BUYER_OPERATOR}/commit", json=COMMIT).json()
        assert outcome["state"] == "refused", (mode, outcome)
        assert reason in outcome["detail"], (mode, outcome)

    pending = buyer_db.execute(
        "SELECT * FROM commits WHERE proposal_id = 'demo-wba-2'").fetchall()
    assert [p["state"] for p in pending] == ["pending"]  # one Commit, still unconfirmed

    fault("none")
    outcome = web.post(f"{BUYER_OPERATOR}/commit", json=COMMIT).json()
    assert outcome["state"] == "agreed", outcome

    entries = seller_db.execute(
        "SELECT role, idempotency_key FROM assent WHERE proposal_id = 'demo-wba-2' ORDER BY id"
    ).fetchall()
    assert [e["role"] for e in entries] == ["commitment", "acceptance"]
    assert entries[0]["idempotency_key"] == pending[0]["idempotency_key"]
