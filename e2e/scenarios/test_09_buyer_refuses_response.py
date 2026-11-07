"""9. The buyer refuses a seller answer it can't verify, then retries the same commit.

The seller's test-only fault toggle (seller/faults.py) strips the answer's
signature, signs it unbound or bound to another request, or signs it over a
body with one byte changed. It breaks the answers to reads or to commits. For
each credential, each fault the buyer must refuse is refused, on a read and on
a commit. A bearer request is unsigned, so it has no signature for an answer to
be bound to: an unbound or rebound answer is what it should get.

On a commit, the seller has accepted, but the buyer refuses the answer and
records no agreement. It then re-sends the same Commit, with the same
idempotency_key. The seller returns the stored result and writes no second
entry (§ 5.6.1). Once the answer verifies, the buyer records the agreement.
"""

import json

import pytest
from conftest import BUYER_OPERATOR, SELLER_FAULTS

#: Each credential's own proposal and line item, which no earlier scenario commits to.
TRIGGER = {
    "web_bot_auth": {"proposal_id": "demo-wba-2", "line_item_ids": ["weather-app-ctv"]},
    "bearer": {
        "proposal_id": "demo-bearer-1",
        "line_item_ids": ["weather-app-ctv"],
        "credential": "bearer",
    },
}
#: The faults each credential must refuse, with the library's reason for each.
FAULTS = {
    "web_bot_auth": [
        ("strip", "signature-missing"),
        ("unbound", "response-not-bound"),
        ("rebound", "signature-invalid"),
        ("wrong_digest", "content-digest"),
    ],
    "bearer": [("strip", "signature-missing"), ("wrong_digest", "content-digest")],
}
CREDENTIALS = list(TRIGGER)


@pytest.fixture
def fault(web):
    def set_fault(mode: str, on: str = "commit") -> None:
        assert web.put(SELLER_FAULTS, json={"mode": mode, "on": on}).status_code == 200

    yield set_fault
    set_fault("none")


def _seller_state(seller_db, proposal_id: str) -> tuple[list[tuple[str, str]], list[str]]:
    entries = seller_db.execute(
        "SELECT role, idempotency_key FROM assent WHERE proposal_id = ? ORDER BY id",
        (proposal_id,),
    ).fetchall()
    processed = seller_db.execute(
        "SELECT idempotency_key FROM commits WHERE proposal_id = ? ORDER BY idempotency_key",
        (proposal_id,),
    ).fetchall()
    return [(e["role"], e["idempotency_key"]) for e in entries], sorted(p[0] for p in processed)


@pytest.mark.parametrize("credential", CREDENTIALS)
def test_buyer_refuses_unverifiable_reads(web, fault, credential):
    read = {k: v for k, v in TRIGGER[credential].items() if k != "line_item_ids"}
    for mode, reason in FAULTS[credential]:
        fault(mode, "read")
        outcome = web.post(f"{BUYER_OPERATOR}/read", json=read).json()
        assert (outcome["state"], outcome["reason"]) == ("refused", reason), (mode, outcome)
        assert outcome["authentication_method"] == credential

    fault("none")
    assert web.post(f"{BUYER_OPERATOR}/read", json=read).json()["state"] == "read"


@pytest.mark.parametrize("credential", CREDENTIALS)
def test_buyer_refuses_unverifiable_commit_answers(web, fault, seller_db, buyer_db, credential):
    trigger = TRIGGER[credential]
    proposal_id, items = trigger["proposal_id"], json.dumps(sorted(trigger["line_item_ids"]))
    before_entries, before_processed = _seller_state(seller_db, proposal_id)
    accepted = None
    for mode, reason in FAULTS[credential]:
        fault(mode)
        outcome = web.post(f"{BUYER_OPERATOR}/commit", json=trigger).json()
        assert (outcome["state"], outcome["reason"]) == ("refused", reason), (mode, outcome)

        pending = buyer_db.execute(
            "SELECT * FROM commits WHERE proposal_id = ? AND line_item_ids = ?",
            (proposal_id, items),
        ).fetchall()
        assert [p["state"] for p in pending] == ["pending"]  # one Commit, still unconfirmed
        key = pending[0]["idempotency_key"]
        state = _seller_state(seller_db, proposal_id)
        if accepted is None:
            # The first faulted attempt reached the offer logic: the seller accepted it.
            assert state == (
                [*before_entries, ("commitment", key), ("acceptance", None)],
                sorted([*before_processed, key]),
            )
            accepted = state
        else:
            # Each retry is a replay of that commit: the stored result, and no new entry.
            assert state == accepted

    fault("none")
    outcome = web.post(f"{BUYER_OPERATOR}/commit", json=trigger).json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == credential
    assert _seller_state(seller_db, proposal_id) == accepted
