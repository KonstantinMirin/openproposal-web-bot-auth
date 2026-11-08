"""The demo's seed proposal, as the tests share it."""

from __future__ import annotations

from protocol.values import JsonObject
from seller.offers.issuance import issued, load_template
from seller.ports import PrincipalRecord


def seed_document() -> JsonObject:
    """The demo's seed proposal as the seller issues it to buyer-wba, as demo-wba-1."""
    buyer = PrincipalRecord("buyer-wba", "Demo Buyer Agency LLC", "buyer.wba-demo.noetis.dev")
    return issued(load_template(), buyer, "demo-wba-1").document
