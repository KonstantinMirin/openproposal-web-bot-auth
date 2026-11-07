"""First-boot records: the seller's two buyers and the proposals it issued to them.

The seller knows the signing buyer only by its origin, never by a key. It knows
the bearer buyer only by its token's hash.
"""

from __future__ import annotations

import copy
from pathlib import Path
from urllib.parse import urlsplit

from shared.documents import load_yaml

from .store import Store

TEMPLATE = Path(__file__).parent / "seed" / "proposal.yaml"


def issue(store: Store, principal_id: str, proposal_id: str, legal_name: str, domain: str) -> None:
    document = copy.deepcopy(load_yaml(TEMPLATE))
    document["proposal_id"] = proposal_id
    document["buyer"] = {"domain": domain, "legal_name": legal_name}
    for item in document["line_items"]:
        item["eligible_buyers"] = [domain]
    store.add_proposal(principal_id, document)


def seed(store: Store, *, buyer_origin: str, bearer_token: str | None) -> None:
    if not store.is_empty():
        return
    with store.transaction():
        # A buyer that signs: the seller's onboarding recorded its origin.
        host = urlsplit(buyer_origin).hostname
        store.add_principal("buyer-wba", "Demo Buyer Agency LLC", host)
        store.add_origin_credential("buyer-wba", buyer_origin)
        for n in (1, 2):
            issue(store, "buyer-wba", f"demo-wba-{n}", "Demo Buyer Agency LLC", host)

        # A buyer that presents a bearer token the seller issued it.
        if bearer_token:
            domain = "bearer-buyer.wba-demo.noetis.dev"
            store.add_principal("buyer-bearer", "Bearer Agency LLC", domain)
            store.add_token_credential("buyer-bearer", bearer_token)
            issue(store, "buyer-bearer", "demo-bearer-1", "Bearer Agency LLC", domain)
