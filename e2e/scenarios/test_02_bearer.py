"""2. The same flow with a bearer token: the same frozen identity, no signature evidence.

A second buyer principal holds a bearer token. The boundary confirms it by its
hash and resolves the same `ResolvedCaller` type a signature resolves, with
`authentication_method: bearer`. The offer logic is the same code either way.
"""

import os

from conftest import BUYER_OPERATOR, SELLER, signed


def test_bearer_token_resolves_the_same_identity_type(web):
    by_token = web.get(f"{SELLER}/whoami",
                       headers={"Authorization": f"Bearer {os.environ['DEMO_BEARER_TOKEN']}"}).json()
    by_signature = web.get(f"{SELLER}/whoami", headers=signed("GET", f"{SELLER}/whoami")).json()

    assert by_token["kind"] == by_signature["kind"] == "resolved"
    assert by_token.keys() == by_signature.keys()
    assert by_token["authentication_method"] == "bearer"
    assert by_token["principal"]["id"] == "buyer-bearer"
    assert by_token["origin"] is None and by_token["evidence_id"] is None
    assert by_signature["authentication_method"] == "web_bot_auth"
    assert by_signature["principal"]["id"] == "buyer-wba"


def test_commit_with_a_bearer_token(web, seller_db):
    outcome = web.post(f"{BUYER_OPERATOR}/commit", json={
        "proposal_id": "demo-bearer-1", "line_item_ids": ["business-daily-display"],
        "credential": "bearer",
    }).json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == "bearer"

    entry = seller_db.execute(
        "SELECT * FROM assent WHERE proposal_id = 'demo-bearer-1' AND role = 'commitment'").fetchone()
    assert entry["principal_id"] == "buyer-bearer"
    assert entry["authentication_method"] == "bearer"
    assert entry["evidence_id"] is None  # nothing was signed, so there is no signature evidence
    assert entry["attributed"] == 0
