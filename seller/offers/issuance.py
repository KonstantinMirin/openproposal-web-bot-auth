"""Issuing a proposal to a buyer (§ 4.3): the template, made out by this seller to one principal.

The seller's composition root (seller/app.py) reads the template file its
settings name once, at startup, and builds the `Issuer` from the parsed
template and the seller's own party. Every
issued document is a fresh copy of the template.
"""

from __future__ import annotations

import copy
import secrets
from dataclasses import dataclass
from datetime import datetime

from protocol.record import line_items_of
from protocol.values import JsonObject, instant
from seller.errors import UnknownPrincipal
from seller.ports import Onboarding, Principal, StoredProposal
from shared.party import OwnParty


@dataclass(frozen=True)
class Issuer:
    """What every proposal this seller issues starts from: the seller itself, and the template."""

    seller: OwnParty
    template: JsonObject


def issued(issuer: Issuer, principal: Principal, proposal_id: str) -> StoredProposal:
    """A copy of the template issued to `principal` as `proposal_id`. Its seller is this
    seller's own party; its buyer, and every line item's `eligible_buyers`, name the
    principal's domain."""
    document = copy.deepcopy(issuer.template)
    document["proposal_id"] = proposal_id
    seller = issuer.seller
    document["seller"] = {"domain": seller.domain, "legal_name": seller.legal_name}
    document["buyer"] = {"domain": principal.domain, "legal_name": principal.legal_name}
    for item in line_items_of(document):
        item["eligible_buyers"] = [principal.domain]
    return StoredProposal(principal.id, document)


def issue(
    store: Onboarding, issuer: Issuer, principal: Principal, proposal_id: str
) -> StoredProposal:
    """Issues the template to `principal`, inside the caller's transaction."""
    proposal = issued(issuer, principal, proposal_id)
    store.save_proposal(proposal)
    return proposal


def issue_fresh(
    store: Onboarding, issuer: Issuer, principal_id: str, now: datetime
) -> StoredProposal:
    """Issues a fresh copy, with a new id, to a principal this seller knows.

    The live runner commits to a fresh proposal on every run, because an
    agreed line item can't be committed to again. Raises `UnknownPrincipal`.
    """
    with store.transaction():
        principal = store.principal(principal_id)
        if principal is None:
            raise UnknownPrincipal(principal_id)
        stamp = instant(now).replace("-", "").replace(":", "")
        proposal_id = f"live-{principal_id}-{stamp}-{secrets.token_hex(2)}"
        return issue(store, issuer, principal, proposal_id)
