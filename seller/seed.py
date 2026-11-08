"""The seller's buyer, onboarded from its settings on every boot, and the proposals it issues it.

A party owns its identity, and a credential only points at it. The seller
knows one buyer, one principal, whichever credential it presents: its domain
is the host of the buyer's origin (`PEER_BUYER_ORIGIN`), and its legal name is
the settings' own (`PEER_BUYER_LEGAL_NAME`). Two credentials point at it: the
buyer's origin, for a Web Bot Auth signature, and the hash of the token the
seller issued it (`DEMO_BEARER_TOKEN`), for a bearer token. The seller never
knows the buyer by a key.

The credentials follow the settings: each boot writes them over what the
database holds, so a changed token takes effect on the next start, and the
token it replaces stops working. The identity doesn't. Onboarding records the
principal's domain and legal name once, the first time, and never rewrites
them, because the proposals issued to it name them: a record's `buyer` stays
the party that every attribution (§ 4.1.2) and every agreement about it was
computed against. Settings that name the buyer under another domain or legal
name are refused with `IdentityChanged`, and the seller doesn't start; another
buyer is onboarded into a database of its own.

A seed proposal is issued once, the first time its principal is onboarded, and
kept after that.
"""

from __future__ import annotations

from pydantic import SecretStr

from persistence.values import Origin

from .errors import IdentityChanged
from .offers.issuance import Issuer, issue
from .ports import Onboarding, Principal

#: The principal of the seller's one buyer, whichever credential it presents.
BUYER = "demo-buyer"
#: The proposals the seller issues its buyer when it first onboards it.
SEED_PROPOSALS = ("demo-wba-1", "demo-wba-2")


def onboard(
    store: Onboarding,
    issuer: Issuer,
    *,
    buyer_origin: Origin,
    buyer_legal_name: str,
    bearer_token: SecretStr | None,
) -> None:
    """Records the buyer the settings name, points its credentials at it, and issues each
    seed proposal not yet issued, in one transaction. With no bearer token, the buyer has no
    bearer credential. Raises `IdentityChanged` when the settings would rewrite the identity
    already recorded."""
    buyer = Principal(id=BUYER, kind="buyer", legal_name=buyer_legal_name, domain=buyer_origin.host)
    with store.transaction():
        recorded = store.principal(buyer.id)
        if recorded is None:
            store.add_principal(buyer)
        elif recorded != buyer:
            raise IdentityChanged(recorded, buyer)
        store.set_origin_credential(buyer.id, buyer_origin)
        token = None if bearer_token is None else bearer_token.get_secret_value()
        store.set_token_credential(buyer.id, token)
        for proposal_id in SEED_PROPOSALS:
            if store.issued(proposal_id) is None:
                issue(store, issuer, buyer, proposal_id)
