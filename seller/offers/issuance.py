"""Issuing a proposal to a buyer (§ 4.3): the template, made out to one principal.

The template is loaded once, at startup (`load_template`), and every issued
document is a fresh copy of it.
"""

from __future__ import annotations

import copy
import secrets
from datetime import datetime
from pathlib import Path

from protocol.documents import load_yaml
from protocol.record import line_items_of
from protocol.values import JsonObject, instant
from seller.errors import UnknownPrincipal
from seller.ports import Onboarding, PrincipalRecord, StoredProposal

#: The proposal every buyer is issued, as the seller's onboarding wrote it.
TEMPLATE = Path(__file__).resolve().parent.parent / "seed" / "proposal.yaml"


def load_template(path: Path = TEMPLATE) -> JsonObject:
    return load_yaml(path)


def issued(template: JsonObject, principal: PrincipalRecord, proposal_id: str) -> StoredProposal:
    """A copy of `template` issued to `principal` as `proposal_id`: its buyer, and every
    line item's `eligible_buyers`, name the principal's domain."""
    document = copy.deepcopy(template)
    document["proposal_id"] = proposal_id
    document["buyer"] = {"domain": principal.domain, "legal_name": principal.legal_name}
    for item in line_items_of(document):
        item["eligible_buyers"] = [principal.domain]
    return StoredProposal(principal.id, document)


def issue(
    store: Onboarding, principal: PrincipalRecord, template: JsonObject, proposal_id: str
) -> StoredProposal:
    """Issues the template to `principal`, inside the caller's transaction."""
    proposal = issued(template, principal, proposal_id)
    store.save_proposal(proposal)
    return proposal


def issue_fresh(
    store: Onboarding, principal_id: str, template: JsonObject, now: datetime
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
        return issue(store, principal, template, proposal_id)
