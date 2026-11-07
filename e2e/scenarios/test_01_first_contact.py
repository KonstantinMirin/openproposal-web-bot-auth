"""1. First contact by signature: neither party knows the other's keys, and the offer is agreed.

The buyer reads its issued proposal and commits, signed. The seller has the
buyer's origin on file and no key, so it fetches the buyer's directory,
verifies the request, and resolves the origin to the principal in its own
database. Both sides keep the agreed record and the counterparty's signed
message, and both compute the same record_digest.
"""

import hashlib
import json

from conftest import BUYER, BUYER_OPERATOR, SELLER, stored_keys
from iab_agentic_primitives.web_bot_auth import (
    HTTPRequest,
    HTTPResponse,
    Origin,
    RequestVerifier,
    ResponseVerifier,
)


def test_first_contact_by_signature(web, seller_db, buyer_db):
    # Neither side holds a key or a directory of the other yet.
    assert seller_db.execute("SELECT COUNT(*) FROM directories").fetchone()[0] == 0
    assert buyer_db.execute("SELECT COUNT(*) FROM directories").fetchone()[0] == 0
    credential = dict(
        seller_db.execute("SELECT * FROM credentials WHERE principal_id = 'buyer-wba'").fetchone()
    )
    assert credential == {
        "id": credential["id"],
        "principal_id": "buyer-wba",
        "type": "web_bot_auth",
        "token_hash": None,
        "origin": BUYER,
    }

    outcome = web.post(
        f"{BUYER_OPERATOR}/commit",
        json={
            "proposal_id": "demo-wba-1",
            "line_item_ids": ["business-daily-display"],
        },
    ).json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == "web_bot_auth"
    assert outcome["seller"]["origin"] == SELLER
    assert outcome["attributed"] is True  # the seller's host is its party's domain (§ 4.1.2)
    commitment, acceptance = outcome["entries"]
    assert (commitment["role"], acceptance["role"]) == ("commitment", "acceptance")

    # The seller resolved the signature to its principal and kept the signed request.
    rows = seller_db.execute(
        "SELECT * FROM assent WHERE proposal_id = 'demo-wba-1' ORDER BY id"
    ).fetchall()
    assert [r["role"] for r in rows] == ["commitment", "acceptance"]
    entry = rows[0]
    assert entry["principal_id"] == "buyer-wba"
    assert entry["authentication_method"] == "web_bot_auth"
    assert entry["attributed"] == 1
    bought = buyer_db.execute(
        "SELECT * FROM commits WHERE id = ?", (outcome["commit_id"],)
    ).fetchone()
    assert bought["state"] == "agreed"
    evidence = seller_db.execute(
        "SELECT * FROM evidence WHERE id = ?", (entry["evidence_id"],)
    ).fetchone()
    assert evidence["origin"] == BUYER and evidence["method"] == "POST"
    assert evidence["body"] == bought["body"]  # the exact bytes the buyer signed and sent
    directory = seller_db.execute(
        "SELECT * FROM directories WHERE digest = ?", (evidence["directory_digest"],)
    ).fetchone()
    assert directory["url"] == f"{BUYER}/.well-known/http-message-signatures-directory"

    # The seller's evidence verifies again, offline, against the directory bytes it kept.
    request_headers = [tuple(line) for line in json.loads(evidence["headers"])]
    again = RequestVerifier(
        stored_keys(seller_db, evidence["directory_digest"], BUYER)
    ).verify_sync(
        HTTPRequest(evidence["method"], evidence["url"], request_headers, evidence["body"])
    )
    assert str(again.origin) == BUYER and again.keyid == evidence["keyid"] and again.body_covered

    # The buyer kept the seller's signed answer as received, bound to its request.
    answer = buyer_db.execute(
        "SELECT * FROM evidence WHERE id = ?", (outcome["evidence_id"],)
    ).fetchone()
    assert answer["origin"] == SELLER and answer["status"] == 200
    assert answer["request_body"] == bought["body"]
    assert json.loads(answer["body"])["entries"] == outcome["entries"]
    sent = HTTPRequest(
        answer["request_method"],
        answer["request_url"],
        [tuple(line) for line in json.loads(answer["request_headers"])],
        answer["request_body"],
    )
    answered = ResponseVerifier(
        stored_keys(buyer_db, answer["directory_digest"], SELLER)
    ).verify_sync(
        HTTPResponse(
            answer["status"],
            [tuple(line) for line in json.loads(answer["headers"])],
            answer["body"],
            sent,
        ),
        expected_origin=Origin.parse(SELLER),
    )
    assert answered.bound and answered.body_covered and answered.keyid == answer["keyid"]

    # Both parties hold the same digest input, and it hashes to the entries' record_digest.
    agreed = seller_db.execute(
        "SELECT * FROM agreed_records WHERE proposal_id = 'demo-wba-1'"
    ).fetchone()
    assert agreed["digest_input"] == bought["digest_input"]
    digest = "sha256:" + hashlib.sha256(bought["digest_input"]).hexdigest()
    assert (
        digest == agreed["record_digest"] == commitment["record_digest"] == outcome["record_digest"]
    )
