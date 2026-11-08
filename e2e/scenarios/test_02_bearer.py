"""2. The same buyer with a bearer token: the same principal, no signature evidence.

A party owns its identity, and a credential only points at it. The seller holds
two credentials for its one buyer: the buyer's origin, and the hash of the
token it issued the buyer. The boundary confirms the token by its hash and
resolves the same principal a signature resolves, with
`authentication_method: bearer`. The buyer commits with the token to the
proposal it committed to by signature in scenario 1, and the offer logic is the
same code either way.
"""

import httpx

from e2e.scenarios.stack import BEARER_TOKEN, BUYER, SELLER, buyer_principal, signed
from persistence.observe import KeptOriginCredential, KeptTokenCredential, SellerRecords
from persistence.values import Origin
from protocol.record import sha256_hex
from seller.caller import WHOAMI, BearerCredential, ResolvedView, SignatureCredential
from transport.client import ControlClient
from transport.control import COMMIT, Agreed, CommitTrigger


def _resolved(web: httpx.Client, headers: dict[str, str]) -> ResolvedView:
    """The caller `/whoami` resolves, read as the seller declares it: an answer with any
    member beyond the view's, such as the provenance, fails to read."""
    caller = WHOAMI.validate_json(web.get(f"{SELLER}/whoami", headers=headers).content)
    assert isinstance(caller, ResolvedView), caller
    return caller


def test_both_credentials_resolve_the_same_principal(
    web: httpx.Client, seller_records: SellerRecords
) -> None:
    principal = buyer_principal(seller_records)
    assert principal.domain == Origin.parse(BUYER).host
    # Both of the buyer's credentials point at that one principal.
    token_hash = sha256_hex(BEARER_TOKEN.encode())
    assert seller_records.credentials(principal.id) == [
        KeptOriginCredential(origin=Origin.parse(BUYER)),
        KeptTokenCredential(token_hash=token_hash),
    ]

    by_token = _resolved(web, {"Authorization": f"Bearer {BEARER_TOKEN}"})
    by_signature = _resolved(web, signed("GET", f"{SELLER}/whoami"))

    assert by_token.principal == by_signature.principal
    assert by_signature.principal.model_dump() == principal.model_dump()
    assert isinstance(by_token.credential, BearerCredential)  # no origin, no evidence
    assert isinstance(by_signature.credential, SignatureCredential)
    assert str(by_signature.credential.origin) == BUYER


def test_commit_with_a_bearer_token(
    buyer_control: ControlClient, seller_records: SellerRecords
) -> None:
    trigger = CommitTrigger(
        proposal_id="demo-wba-1", line_item_ids=["weather-app-ctv"], credential="bearer"
    )
    outcome = buyer_control.call(COMMIT, trigger)
    assert isinstance(outcome, Agreed), outcome
    assert outcome.authentication_method == "bearer"
    key = outcome.entries[0].idempotency_key

    (entry,) = [e for e in seller_records.entries("demo-wba-1") if e.idempotency_key == key]
    assert entry.principal_id == buyer_principal(seller_records).id
    assert entry.authentication_method == "bearer"
    assert entry.evidence_id is None  # nothing was signed, so there is no signature evidence
    assert entry.attributed is False
