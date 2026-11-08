"""2. The same flow with a bearer token: the same frozen identity, no signature evidence.

A second buyer principal holds a bearer token. The boundary confirms it by its
hash and resolves the same `ResolvedCaller` type a signature resolves, with
`authentication_method: bearer`. The offer logic is the same code either way.
"""

import httpx
from conftest import BUYER, SELLER, signed
from settings import BEARER_TOKEN

from persistence.observe import SellerRecords
from seller.caller import WHOAMI, BearerCredential, ResolvedView, SignatureCredential
from transport.client import ControlClient
from transport.control import COMMIT, Agreed, CommitTrigger


def _resolved(web: httpx.Client, headers: dict[str, str]) -> ResolvedView:
    """The caller `/whoami` resolves, read as the seller declares it: an answer with any
    member beyond the view's, such as the provenance, fails to read."""
    caller = WHOAMI.validate_json(web.get(f"{SELLER}/whoami", headers=headers).content)
    assert isinstance(caller, ResolvedView), caller
    return caller


def test_bearer_token_resolves_the_same_identity_type(web: httpx.Client) -> None:
    by_token = _resolved(web, {"Authorization": f"Bearer {BEARER_TOKEN}"})
    by_signature = _resolved(web, signed("GET", f"{SELLER}/whoami"))

    assert by_token.principal.id == "buyer-bearer"
    assert isinstance(by_token.credential, BearerCredential)  # no origin, no evidence
    assert by_signature.principal.id == "buyer-wba"
    assert isinstance(by_signature.credential, SignatureCredential)
    assert str(by_signature.credential.origin) == BUYER


def test_commit_with_a_bearer_token(
    buyer_control: ControlClient, seller_records: SellerRecords
) -> None:
    trigger = CommitTrigger(
        proposal_id="demo-bearer-1", line_item_ids=["business-daily-display"], credential="bearer"
    )
    outcome = buyer_control.call(COMMIT, trigger)
    assert isinstance(outcome, Agreed), outcome
    assert outcome.authentication_method == "bearer"

    (entry,) = [e for e in seller_records.entries("demo-bearer-1") if e.role == "commitment"]
    assert entry.principal_id == "buyer-bearer"
    assert entry.authentication_method == "bearer"
    assert entry.evidence_id is None  # nothing was signed, so there is no signature evidence
    assert entry.attributed is False
