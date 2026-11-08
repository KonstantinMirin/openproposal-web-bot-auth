"""Cross-agent state reconciliation (flagged decision FD-8).

Both agents track lifecycle state independently — there is deliberately no
distributed transaction. FD-8 ruling: the SELLER's record is authoritative
for order/fulfillment state (and for the seller-owned deal and
change-request lifecycles); the buyer's record is authoritative only for
its own campaign/budget state, which is buyer-internal and not a shared
machine. Reconciliation does not force agreement — it makes disagreement
VISIBLE, so a sync job (or a human) can act on it.

This module is a pure comparison helper: no input/output, no storage, no
clock reads beyond the timestamps the caller passes in. Agents call
:func:`reconcile_deal` / :func:`reconcile_order` /
:func:`reconcile_change_request` from their sync jobs with the two
observed statuses and get back a classification:

- ``consistent`` — both sides report the same state.
- ``buyer_behind`` — the seller's state is strictly ahead: reachable from
  the buyer's state via FORWARD-PROGRESS transitions (rework/recovery
  edges such as ``failed -> draft`` excluded — see
  :class:`~.machine.TransitionRule`). The buyer has not yet observed
  progress the seller already made.
- ``seller_behind`` — the mirror case (e.g. the buyer already knows about
  a cancellation the seller has not yet processed).
- ``divergent`` — neither state precedes the other in the forward-progress
  partial order (two conflicting terminal outcomes, for example).
  Divergence produces a structured :class:`DisagreementReport` naming both
  states, both observation timestamps, and the authoritative side per
  FD-8.

Precedence deliberately ignores rework edges: with the recovery loops
included, almost every pair of order states would be mutually reachable
and every lag would misclassify as divergent. The trade-off: a side that
has genuinely looped back (e.g. seller reset a failed order to ``draft``
while the buyer still shows ``failed``) classifies as the LOOPED-BACK side
being behind (here ``seller_behind``) rather than divergent — acceptable,
because either way the sync job re-fetches from the authoritative side.

The classification for every (buyer, seller) status pair is precomputed
from the canonical transition tables into small explicit equivalence
tables (``DEAL_COMPARISON_TABLE`` etc.), which are also exported to
``spec/jsonschema/state/Reconciliation.json`` for non-Python implementers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ..primitives.lifecycle import ChangeRequestStatus, DealStatus, OrderStatus
from .change_request_lifecycle import CHANGE_REQUEST_LIFECYCLE
from .deal_lifecycle import DEAL_LIFECYCLE
from .machine import StateMachine
from .order_lifecycle import ORDER_LIFECYCLE


class ReconciliationOutcome(str, Enum):
    """Classification of a (buyer-side, seller-side) status pair."""

    CONSISTENT = "consistent"
    BUYER_BEHIND = "buyer_behind"
    SELLER_BEHIND = "seller_behind"
    DIVERGENT = "divergent"


class AuthoritativeSide(str, Enum):
    """Which agent's record wins when the two disagree (FD-8)."""

    BUYER = "buyer"
    SELLER = "seller"


#: FD-8: the seller's record is authoritative for every SHARED lifecycle
#: (order/fulfillment state, and the seller-issued deal and change-request
#: lifecycles). The buyer is authoritative only for buyer-internal
#: campaign/budget state, which is not a shared machine and never
#: reconciled here.
AUTHORITATIVE_SIDE: dict[str, AuthoritativeSide] = {
    "deal": AuthoritativeSide.SELLER,
    "order": AuthoritativeSide.SELLER,
    "change_request": AuthoritativeSide.SELLER,
}


def classify(
    machine: StateMachine, buyer_status: Enum, seller_status: Enum
) -> ReconciliationOutcome:
    """Classify one (buyer, seller) status pair against a canonical machine."""
    if buyer_status == seller_status:
        return ReconciliationOutcome.CONSISTENT
    # Strict partial order over the forward-progress subgraph (acyclic by
    # construction), so at most one of these can hold.
    if machine.can_progress_to(buyer_status, seller_status):
        return ReconciliationOutcome.BUYER_BEHIND
    if machine.can_progress_to(seller_status, buyer_status):
        return ReconciliationOutcome.SELLER_BEHIND
    return ReconciliationOutcome.DIVERGENT


def comparison_table(
    machine: StateMachine,
) -> dict[tuple[str, str], ReconciliationOutcome]:
    """Explicit equivalence table: {(buyer value, seller value): outcome}."""
    return {
        (buyer.value, seller.value): classify(machine, buyer, seller)
        for buyer in machine.states
        for seller in machine.states
    }


# Precomputed explicit tables — importable, inspectable, and spec-exported.
DEAL_COMPARISON_TABLE = comparison_table(DEAL_LIFECYCLE)
ORDER_COMPARISON_TABLE = comparison_table(ORDER_LIFECYCLE)
CHANGE_REQUEST_COMPARISON_TABLE = comparison_table(CHANGE_REQUEST_LIFECYCLE)


@dataclass(frozen=True)
class DisagreementReport:
    """Structured record of a divergent (buyer, seller) status pair.

    ``authoritative_status`` is the authoritative side's reported status —
    per FD-8 that is the seller for every shared lifecycle — but a
    divergence should still be surfaced to a human/sync policy rather than
    silently overwritten: that visibility is the point of FD-8.
    """

    lifecycle: str
    entity_id: str
    buyer_status: str
    seller_status: str
    buyer_observed_at: datetime | None
    seller_observed_at: datetime | None
    authoritative_side: AuthoritativeSide
    authoritative_status: str
    detail: str = ""


@dataclass(frozen=True)
class ReconciliationResult:
    """Outcome of comparing one entity's buyer-side and seller-side status."""

    lifecycle: str
    entity_id: str
    buyer_status: str
    seller_status: str
    outcome: ReconciliationOutcome
    authoritative_side: AuthoritativeSide
    disagreement: DisagreementReport | None = None


def _require_aware(name: str, value: datetime | None) -> None:
    if value is not None and value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware (UTC — Coordinated Universal Time)")


def reconcile(
    machine: StateMachine,
    *,
    entity_id: str,
    buyer_status: Enum,
    seller_status: Enum,
    buyer_observed_at: datetime | None = None,
    seller_observed_at: datetime | None = None,
) -> ReconciliationResult:
    """Compare one entity's two independently-tracked statuses (pure; no I/O).

    ``buyer_observed_at`` / ``seller_observed_at`` are when each side's
    status was recorded or last confirmed; they ride into the
    :class:`DisagreementReport` so a sync job can judge staleness.
    """
    _require_aware("buyer_observed_at", buyer_observed_at)
    _require_aware("seller_observed_at", seller_observed_at)
    buyer_status = machine.states(buyer_status)
    seller_status = machine.states(seller_status)
    outcome = classify(machine, buyer_status, seller_status)
    side = AUTHORITATIVE_SIDE[machine.name]
    disagreement = None
    if outcome is ReconciliationOutcome.DIVERGENT:
        disagreement = DisagreementReport(
            lifecycle=machine.name,
            entity_id=entity_id,
            buyer_status=buyer_status.value,
            seller_status=seller_status.value,
            buyer_observed_at=buyer_observed_at,
            seller_observed_at=seller_observed_at,
            authoritative_side=side,
            authoritative_status=(
                seller_status.value if side is AuthoritativeSide.SELLER else buyer_status.value
            ),
            detail=(
                f"buyer reports {buyer_status.value!r}, seller reports "
                f"{seller_status.value!r}; neither strictly precedes the other in the "
                f"canonical {machine.name} lifecycle"
            ),
        )
    return ReconciliationResult(
        lifecycle=machine.name,
        entity_id=entity_id,
        buyer_status=buyer_status.value,
        seller_status=seller_status.value,
        outcome=outcome,
        authoritative_side=side,
        disagreement=disagreement,
    )


def reconcile_deal(
    *,
    deal_id: str,
    buyer_status: DealStatus | str,
    seller_status: DealStatus | str,
    buyer_observed_at: datetime | None = None,
    seller_observed_at: datetime | None = None,
) -> ReconciliationResult:
    """Reconcile one deal's buyer-side vs seller-side ``DealStatus``."""
    return reconcile(
        DEAL_LIFECYCLE,
        entity_id=deal_id,
        buyer_status=DealStatus(buyer_status),
        seller_status=DealStatus(seller_status),
        buyer_observed_at=buyer_observed_at,
        seller_observed_at=seller_observed_at,
    )


def reconcile_order(
    *,
    order_id: str,
    buyer_status: OrderStatus | str,
    seller_status: OrderStatus | str,
    buyer_observed_at: datetime | None = None,
    seller_observed_at: datetime | None = None,
) -> ReconciliationResult:
    """Reconcile one order's buyer-side vs seller-side ``OrderStatus``."""
    return reconcile(
        ORDER_LIFECYCLE,
        entity_id=order_id,
        buyer_status=OrderStatus(buyer_status),
        seller_status=OrderStatus(seller_status),
        buyer_observed_at=buyer_observed_at,
        seller_observed_at=seller_observed_at,
    )


def reconcile_change_request(
    *,
    change_request_id: str,
    buyer_status: ChangeRequestStatus | str,
    seller_status: ChangeRequestStatus | str,
    buyer_observed_at: datetime | None = None,
    seller_observed_at: datetime | None = None,
) -> ReconciliationResult:
    """Reconcile one change request's buyer-side vs seller-side status."""
    return reconcile(
        CHANGE_REQUEST_LIFECYCLE,
        entity_id=change_request_id,
        buyer_status=ChangeRequestStatus(buyer_status),
        seller_status=ChangeRequestStatus(seller_status),
        buyer_observed_at=buyer_observed_at,
        seller_observed_at=seller_observed_at,
    )


__all__ = [
    "AUTHORITATIVE_SIDE",
    "AuthoritativeSide",
    "CHANGE_REQUEST_COMPARISON_TABLE",
    "DEAL_COMPARISON_TABLE",
    "DisagreementReport",
    "ORDER_COMPARISON_TABLE",
    "ReconciliationOutcome",
    "ReconciliationResult",
    "classify",
    "comparison_table",
    "reconcile",
    "reconcile_change_request",
    "reconcile_deal",
    "reconcile_order",
]
