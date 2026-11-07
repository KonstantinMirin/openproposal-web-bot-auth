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


def _seller_state(seller_db) -> tuple[list[tuple[str, str]], list[str]]:
    entries = seller_db.execute(
        "SELECT role, idempotency_key FROM assent WHERE proposal_id = 'demo-wba-2' ORDER BY id"
    ).fetchall()
    processed = seller_db.execute(
        "SELECT idempotency_key FROM commits WHERE proposal_id = 'demo-wba-2'"
    ).fetchall()
    return [(e["role"], e["idempotency_key"]) for e in entries], [p[0] for p in processed]


def test_buyer_refuses_unverifiable_responses(web, fault, seller_db, buyer_db):
    accepted = None
    for mode, reason in [
        # The library's reason for a response with no signature (wbalib-r1g.3).
        ("strip", "signature-missing"),
        ("unbound", "response-not-bound"),
        ("rebound", "signature-invalid"),
    ]:
        fault(mode)
        outcome = web.post(f"{BUYER_OPERATOR}/commit", json=COMMIT).json()
        assert outcome["state"] == "refused", (mode, outcome)
        assert reason in outcome["detail"], (mode, outcome)

        pending = buyer_db.execute(
            "SELECT * FROM commits WHERE proposal_id = 'demo-wba-2'"
        ).fetchall()
        assert [p["state"] for p in pending] == ["pending"]  # one Commit, still unconfirmed
        key = pending[0]["idempotency_key"]
        state = _seller_state(seller_db)
        if accepted is None:
            # The first faulted attempt reached the offer logic: the seller accepted it.
            assert state == ([("commitment", key), ("acceptance", None)], [key])
            accepted = state
        else:
            # Each retry is a replay of that commit: the stored result, and no new entry.
            assert state == accepted

    fault("none")
    outcome = web.post(f"{BUYER_OPERATOR}/commit", json=COMMIT).json()
    assert outcome["state"] == "agreed", outcome
    assert _seller_state(seller_db) == accepted
