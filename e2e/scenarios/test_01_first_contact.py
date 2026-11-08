"""1. First contact by signature: neither party knows the other's keys, and the offer is agreed.

The buyer reads its issued proposal and commits, signed. The seller has the
buyer's origin on file and no key, so it fetches the buyer's directory,
verifies the request, and resolves the origin to the principal in its own
database. Both sides keep the agreed record and the counterparty's signed
message, and both compute the same record_digest.
"""

import asyncio
import hashlib
import json

import httpx
from conftest import BUYER, BUYER_OPERATOR, SELLER
from iab_agentic_primitives.web_bot_auth import ServerIdentity

from persistence.observe import BuyerRecords, SellerRecords
from transport.reverify import reverify_request, reverify_response


def test_first_contact_by_signature(
    web: httpx.Client, seller_records: SellerRecords, buyer_records: BuyerRecords
) -> None:
    # Neither side holds a key or a directory of the other yet.
    assert seller_records.directories() == 0
    assert buyer_records.directories() == 0
    (credential,) = seller_records.credentials("buyer-wba")
    assert (credential.type, credential.origin, credential.token_hash) == (
        "web_bot_auth",
        BUYER,
        None,
    )

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
    entries = seller_records.entries("demo-wba-1")
    assert [e.role for e in entries] == ["commitment", "acceptance"]
    entry = entries[0]
    assert entry.principal_id == "buyer-wba"
    assert entry.authentication_method == "web_bot_auth"
    assert entry.attributed is True
    bought = buyer_records.commit(outcome["commit_id"])
    assert bought is not None and bought.state == "agreed"
    assert entry.evidence_id is not None
    evidence = seller_records.request(entry.evidence_id)
    signer = evidence.signer
    assert str(signer.origin) == BUYER and evidence.request.method == "POST"
    assert evidence.request.body == bought.body  # the exact bytes the buyer signed and sent
    assert signer.directory is not None
    assert signer.directory.url == f"{BUYER}/.well-known/http-message-signatures-directory"

    # The seller's evidence verifies again, offline, against the directory bytes it kept.
    identity = ServerIdentity.from_config(SELLER)
    again = asyncio.run(reverify_request(evidence, identity))
    assert str(again.origin) == BUYER and again.keyid == signer.keyid and again.body_covered

    # The buyer kept the seller's signed answer as received, bound to its request.
    answer = buyer_records.response(outcome["evidence_id"])
    assert str(answer.signer.origin) == SELLER and answer.response.status == 200
    assert answer.response.request.body == bought.body
    assert json.loads(answer.response.body)["entries"] == outcome["entries"]
    answered = asyncio.run(reverify_response(answer))
    assert answered.bound and answered.body_covered and answered.keyid == answer.signer.keyid
    assert str(answered.origin) == SELLER

    # Both parties hold the same digest input, and it hashes to the entries' record_digest.
    # The hash is computed here with hashlib, independently of protocol/.
    (agreed,) = seller_records.agreed("demo-wba-1")
    assert agreed.digest_input == bought.digest_input
    digest = "sha256:" + hashlib.sha256(bought.digest_input).hexdigest()
    assert digest == agreed.record_digest == commitment["record_digest"] == outcome["record_digest"]
