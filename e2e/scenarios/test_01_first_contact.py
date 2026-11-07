"""1. First contact by signature: neither party knows the other's keys, and the offer is agreed.

The buyer reads its issued proposal and commits, signed. The seller has the
buyer's origin on file and no key, so it fetches the buyer's directory,
verifies the request, and resolves the origin to the principal in its own
database. Both sides keep the agreed record and the counterparty's signed
message, and both compute the same record_digest.
"""

import hashlib
import json

from conftest import BUYER, BUYER_OPERATOR, SELLER


def test_first_contact_by_signature(web, seller_db, buyer_db):
    # Neither side holds a key or a directory of the other yet.
    assert seller_db.execute("SELECT COUNT(*) FROM directories").fetchone()[0] == 0
    assert buyer_db.execute("SELECT COUNT(*) FROM directories").fetchone()[0] == 0
    credential = dict(seller_db.execute(
        "SELECT * FROM credentials WHERE principal_id = 'buyer-wba'").fetchone())
    assert credential == {"id": credential["id"], "principal_id": "buyer-wba",
                          "type": "web_bot_auth", "token_hash": None, "origin": BUYER}

    outcome = web.post(f"{BUYER_OPERATOR}/commit", json={
        "proposal_id": "demo-wba-1", "line_item_ids": ["business-daily-display"],
    }).json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == "web_bot_auth"
    assert outcome["seller"]["origin"] == SELLER
    assert outcome["attributed"] is True  # the seller's host is its party's domain (§ 4.1.2)
    commitment, acceptance = outcome["entries"]
    assert (commitment["role"], acceptance["role"]) == ("commitment", "acceptance")

    # The seller resolved the signature to its principal and kept the signed request.
    rows = seller_db.execute(
        "SELECT * FROM assent WHERE proposal_id = 'demo-wba-1' ORDER BY id").fetchall()
    assert [r["role"] for r in rows] == ["commitment", "acceptance"]
    entry = rows[0]
    assert entry["principal_id"] == "buyer-wba"
    assert entry["authentication_method"] == "web_bot_auth"
    assert entry["attributed"] == 1
    evidence = seller_db.execute("SELECT * FROM evidence WHERE id = ?",
                                 (entry["evidence_id"],)).fetchone()
    assert evidence["origin"] == BUYER and evidence["method"] == "POST"
    assert json.loads(evidence["body"])["entry"] == commitment  # the exact bytes the buyer sent
    directory = seller_db.execute("SELECT * FROM directories WHERE digest = ?",
                                  (evidence["directory_digest"],)).fetchone()
    assert directory["url"] == f"{BUYER}/.well-known/http-message-signatures-directory"
    fetched = json.loads(directory["evidence"])  # VerifiedDirectory.evidence()
    assert fetched["status"] == 200
    assert any(name.lower() == "signature" for name, _ in fetched["headers"])
    assert evidence["keyid"] in {k["kid"] for k in json.loads(fetched["body"])["keys"]}

    # The buyer kept the seller's signed answer, bound to its request.
    bought = buyer_db.execute("SELECT * FROM commits WHERE id = ?", (outcome["commit_id"],)).fetchone()
    assert bought["state"] == "agreed"
    answer = buyer_db.execute("SELECT * FROM evidence WHERE id = ?",
                              (outcome["evidence_id"],)).fetchone()
    assert answer["origin"] == SELLER and answer["status"] == 200
    assert json.loads(answer["body"])["entries"] == outcome["entries"]
    seller_directory = json.loads(buyer_db.execute(
        "SELECT evidence FROM directories WHERE digest = ?", (answer["directory_digest"],)
    ).fetchone()["evidence"])
    assert seller_directory["url"] == f"{SELLER}/.well-known/http-message-signatures-directory"
    assert answer["keyid"] in {k["kid"] for k in json.loads(seller_directory["body"])["keys"]}

    # Both parties hold the same digest input, and it hashes to the entries' record_digest.
    agreed = seller_db.execute(
        "SELECT * FROM agreed_records WHERE proposal_id = 'demo-wba-1'").fetchone()
    assert agreed["digest_input"] == bought["digest_input"]
    digest = "sha256:" + hashlib.sha256(bought["digest_input"]).hexdigest()
    assert digest == agreed["record_digest"] == commitment["record_digest"] == outcome["record_digest"]
