"""The seller's counterparties, applied from its settings on every boot, and the proposals
it issues them.

The settings are the one source of truth for who the seller's buyers are: each
boot writes them over what the database holds, so a changed `PEER_BUYER_ORIGIN`
or `DEMO_BEARER_TOKEN` takes effect on the next start, and the credential it
replaces stops working. Each setting names one credential of one principal:
the signing buyer's origin, and the bearer buyer's token. A seed proposal is
issued once, the first time its principal is onboarded, and kept after that.

The seller knows the signing buyer only by its origin, never by a key. It knows
the bearer buyer only by its token's hash.
"""

from __future__ import annotations

from pydantic import SecretStr

from persistence.values import Origin

from .offers.issuance import Issuer, issue
from .ports import Onboarding, Principal

#: The principal that signs, and the one that presents a bearer token.
SIGNING_BUYER = "buyer-wba"
BEARER_BUYER = "buyer-bearer"


def onboard(
    store: Onboarding,
    issuer: Issuer,
    *,
    buyer_origin: Origin,
    bearer_token: SecretStr | None,
) -> None:
    """Applies the settings' counterparties to the store, in one transaction, and issues each
    seed proposal not yet issued. With no bearer token, the bearer buyer has no credential."""
    with store.transaction():
        # A buyer that signs: the seller's onboarding recorded its origin, and its domain.
        signing = Principal(
            id=SIGNING_BUYER,
            kind="buyer",
            legal_name="Demo Buyer Agency LLC",
            domain=buyer_origin.host,
        )
        _onboarded(store, issuer, signing, ("demo-wba-1", "demo-wba-2"))
        store.set_origin_credential(signing.id, buyer_origin)

        # A buyer that presents a bearer token the seller issued it.
        if bearer_token is None:
            store.set_token_credential(BEARER_BUYER, None)
            return
        bearer = Principal(
            id=BEARER_BUYER,
            kind="buyer",
            legal_name="Bearer Agency LLC",
            domain="bearer-buyer.wba-demo.noetis.dev",
        )
        _onboarded(store, issuer, bearer, ("demo-bearer-1",))
        store.set_token_credential(bearer.id, bearer_token.get_secret_value())


def _onboarded(
    store: Onboarding, issuer: Issuer, principal: Principal, proposals: tuple[str, ...]
) -> None:
    """Writes `principal` as the settings name it, and issues it each of `proposals` once."""
    store.put_principal(principal)
    for proposal_id in proposals:
        if store.issued(proposal_id) is None:
            issue(store, issuer, principal, proposal_id)
