"""First-boot records: the seller's two buyers and the proposals it issued to them.

The seller knows the signing buyer only by its origin, never by a key. It knows
the bearer buyer only by its token's hash.
"""

from __future__ import annotations

from pydantic import SecretStr

from persistence.values import Origin
from protocol.values import JsonObject

from .offers.issuance import issue
from .ports import Onboarding, PrincipalRecord


def seed(
    store: Onboarding,
    template: JsonObject,
    *,
    buyer_origin: Origin,
    bearer_token: SecretStr | None,
) -> None:
    """Writes the first-boot records into an empty store; does nothing to a seeded one."""
    if not store.is_empty():
        return
    with store.transaction():
        # A buyer that signs: the seller's onboarding recorded its origin, and its domain.
        signing = PrincipalRecord("buyer-wba", "Demo Buyer Agency LLC", buyer_origin.host)
        store.add_principal(signing)
        store.add_origin_credential(signing.id, buyer_origin)
        for n in (1, 2):
            issue(store, signing, template, f"demo-wba-{n}")

        # A buyer that presents a bearer token the seller issued it.
        if bearer_token is not None:
            bearer = PrincipalRecord(
                "buyer-bearer", "Bearer Agency LLC", "bearer-buyer.wba-demo.noetis.dev"
            )
            store.add_principal(bearer)
            store.add_token_credential(bearer.id, bearer_token.get_secret_value())
            issue(store, bearer, template, "demo-bearer-1")
