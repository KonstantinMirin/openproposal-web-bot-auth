"""First-boot records: the seller's two buyers and the proposals it issued to them.

The seller knows the signing buyer only by its origin, never by a key. It knows
the bearer buyer only by its token's hash.
"""

from __future__ import annotations

from pydantic import SecretStr

from persistence.values import Origin

from .offers.issuance import Issuer, issue
from .ports import Onboarding, PrincipalRecord


def seed(
    store: Onboarding,
    issuer: Issuer,
    *,
    buyer_origin: Origin,
    bearer_token: SecretStr | None,
) -> None:
    """Writes the first-boot records into an empty store; does nothing to a seeded one."""
    if not store.is_empty():
        return
    with store.transaction():
        # A buyer that signs: the seller's onboarding recorded its origin, and its domain.
        signing = PrincipalRecord(
            id="buyer-wba", legal_name="Demo Buyer Agency LLC", domain=buyer_origin.host
        )
        store.add_principal(signing)
        store.add_origin_credential(signing.id, buyer_origin)
        for n in (1, 2):
            issue(store, issuer, signing, f"demo-wba-{n}")

        # A buyer that presents a bearer token the seller issued it.
        if bearer_token is not None:
            bearer = PrincipalRecord(
                id="buyer-bearer",
                legal_name="Bearer Agency LLC",
                domain="bearer-buyer.wba-demo.noetis.dev",
            )
            store.add_principal(bearer)
            store.add_token_credential(bearer.id, bearer_token.get_secret_value())
            issue(store, issuer, bearer, "demo-bearer-1")
