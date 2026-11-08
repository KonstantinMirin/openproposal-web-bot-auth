"""The documents the tests share: YAML files read as § 4.1.1 reads them, and the seed proposal."""

from __future__ import annotations

from pathlib import Path

from protocol.documents import loads_yaml
from protocol.values import JsonObject
from seller.app import TEMPLATE
from seller.offers.issuance import issued
from seller.ports import PrincipalRecord


def load_yaml(path: Path) -> JsonObject:
    """The YAML document in `path`."""
    return loads_yaml(path.read_text(encoding="utf-8"))


def seed_template() -> JsonObject:
    """The proposal every buyer is issued, as seller/app.py reads it."""
    return load_yaml(TEMPLATE)


def seed_document() -> JsonObject:
    """The demo's seed proposal as the seller issues it to buyer-wba, as demo-wba-1."""
    buyer = PrincipalRecord(
        id="buyer-wba", legal_name="Demo Buyer Agency LLC", domain="buyer.wba-demo.noetis.dev"
    )
    return issued(seed_template(), buyer, "demo-wba-1").document
