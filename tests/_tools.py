"""The documents the tests share: YAML files read as § 4.1.1 reads them, the seed proposal,
the buyer's plan, and a commit composed from it."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from openproposal import LineItemWrites, Proposal, dump_json

from buyer.settings import PLAN_FILE
from persistence.values import Origin
from protocol.documents import loads_yaml
from protocol.operations import ComposedCommit, compose_commit
from protocol.values import JsonObject
from seller.offers.issuance import Issuer, issued
from seller.ports import Principal
from seller.settings import TEMPLATE_FILE
from shared.party import OwnParty


def load_yaml(path: Path) -> JsonObject:
    """The YAML document in `path`."""
    return loads_yaml(path.read_text(encoding="utf-8"))


def seed_template() -> JsonObject:
    """The proposal every buyer is issued: the template file the seller ships by default."""
    return load_yaml(TEMPLATE_FILE)


def seed_issuer(template: JsonObject | None = None) -> Issuer:
    """The demo seller, issuing `template` (by default, the seed proposal)."""
    seller = OwnParty(
        origin=Origin.parse("https://seller.wba-demo.noetis.dev"), legal_name="Demo Seller Inc."
    )
    return Issuer(seller, seed_template() if template is None else template)


def seed_document() -> JsonObject:
    """The demo's seed proposal as the seller issues it to buyer-wba, as demo-wba-1."""
    buyer = Principal(
        id="buyer-wba",
        kind="buyer",
        legal_name="Demo Buyer Agency LLC",
        domain="buyer.wba-demo.noetis.dev",
    )
    return issued(seed_issuer(), buyer, "demo-wba-1").document


#: The buyer's plan: the file the buyer's settings name by default.
PLAN = load_yaml(PLAN_FILE)


def plan_writes(*names: str) -> dict[str, LineItemWrites]:
    """The plan's writes for each named line item, in the order named."""
    return {name: LineItemWrites.model_validate(PLAN[name]) for name in names}


def composed_commit(
    document: JsonObject, *names: str, key: str = "k-1", at: datetime | None = None
) -> ComposedCommit:
    """The buyer's commit to the named line items of `document`, with the plan's writes,
    composed with the protocol operations at `at` (by default, now)."""
    when = datetime.now(UTC) if at is None else at
    writes = plan_writes(*names)
    return compose_commit(Proposal.model_validate(document), document, writes, at=when, key=key)


def commit_body(
    document: JsonObject, *names: str, key: str = "k-1", at: datetime | None = None
) -> bytes:
    """The bytes the buyer sends for `composed_commit`'s commit."""
    return dump_json(composed_commit(document, *names, key=key, at=at).commit).encode()
