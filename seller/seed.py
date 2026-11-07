"""First-boot records: the seller's two buyers and the proposals it issued to them.

The seller knows the signing buyer only by its origin, never by a key. It knows
the bearer buyer only by its token's hash.
"""

from __future__ import annotations

from pathlib import Path

from iab_agentic_primitives.web_bot_auth import Origin
from pydantic import SecretStr

from protocol.documents import load_yaml
from protocol.record import line_items_of
from protocol.values import JsonObject

from .store import Store

TEMPLATE = Path(__file__).parent / "seed" / "proposal.yaml"


def issued_document(proposal_id: str, legal_name: str, domain: str) -> JsonObject:
    """The template, issued to the buyer at `domain` as `proposal_id` (§ 4.3)."""
    document = load_yaml(TEMPLATE)  # a fresh copy on every read
    document["proposal_id"] = proposal_id
    document["buyer"] = {"domain": domain, "legal_name": legal_name}
    for item in line_items_of(document):
        item["eligible_buyers"] = [domain]
    return document


def issue(store: Store, principal_id: str, proposal_id: str, legal_name: str, domain: str) -> None:
    store.add_proposal(principal_id, issued_document(proposal_id, legal_name, domain))


def seed(store: Store, *, buyer_origin: Origin, bearer_token: SecretStr | None) -> None:
    """Writes the first-boot records into an empty store; does nothing to a seeded one."""
    if not store.is_empty():
        return
    with store.transaction():
        # A buyer that signs: the seller's onboarding recorded its origin, and its domain.
        host = buyer_origin.host
        store.add_principal("buyer-wba", "Demo Buyer Agency LLC", host)
        store.add_origin_credential("buyer-wba", str(buyer_origin))
        for n in (1, 2):
            issue(store, "buyer-wba", f"demo-wba-{n}", "Demo Buyer Agency LLC", host)

        # A buyer that presents a bearer token the seller issued it.
        if bearer_token is not None:
            domain = "bearer-buyer.wba-demo.noetis.dev"
            store.add_principal("buyer-bearer", "Bearer Agency LLC", domain)
            store.add_token_credential("buyer-bearer", bearer_token.get_secret_value())
            issue(store, "buyer-bearer", "demo-bearer-1", "Bearer Agency LLC", domain)
