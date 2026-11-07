"""2. The same flow with a bearer token: the same frozen identity, no signature evidence.

A second buyer principal holds a bearer token. The boundary confirms it by its
hash and resolves the same `ResolvedCaller` type a signature resolves, with
`authentication_method: bearer`. The offer logic is the same code either way.
"""

from conftest import BUYER, BUYER_OPERATOR, SELLER, signed
from settings import BEARER_TOKEN


def test_bearer_token_resolves_the_same_identity_type(web):
    by_token = web.get(
        f"{SELLER}/whoami", headers={"Authorization": f"Bearer {BEARER_TOKEN}"}
    ).json()
    by_signature = web.get(f"{SELLER}/whoami", headers=signed("GET", f"{SELLER}/whoami")).json()

    assert by_token["kind"] == by_signature["kind"] == "resolved"
    assert (
        by_token.keys() == by_signature.keys() == {"kind", "principal", "credential", "attributed"}
    )
    assert by_token["principal"]["id"] == "buyer-bearer"
    assert by_token["credential"] == {"method": "bearer"}  # no origin, no evidence
    assert by_signature["principal"]["id"] == "buyer-wba"
    assert by_signature["credential"]["method"] == "web_bot_auth"
    assert by_signature["credential"]["origin"] == BUYER


def test_commit_with_a_bearer_token(web, seller_records):
    outcome = web.post(
        f"{BUYER_OPERATOR}/commit",
        json={
            "proposal_id": "demo-bearer-1",
            "line_item_ids": ["business-daily-display"],
            "credential": "bearer",
        },
    ).json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == "bearer"

    (entry,) = [e for e in seller_records.entries("demo-bearer-1") if e.role == "commitment"]
    assert entry.principal_id == "buyer-bearer"
    assert entry.authentication_method == "bearer"
    assert entry.evidence_id is None  # nothing was signed, so there is no signature evidence
    assert entry.attributed is False
