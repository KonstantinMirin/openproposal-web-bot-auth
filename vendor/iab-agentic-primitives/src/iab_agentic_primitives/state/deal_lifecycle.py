"""Canonical Deal lifecycle machine over the unified ``DealStatus`` vocabulary.

Reconciles the buyer agent's ``DealStateMachine`` (27 transition rules over
``BuyerDealStatus`` in ``ad_buyer/models/state_machine.py``) into the
12-value canonical ``DealStatus`` defined by the primitives layer. The
seller agent had no formal deal machine (its ``DealBookingStatus`` was an
enum with ad-hoc assignment); this machine is the one both agents adopt.

Reconciliation summary (full per-transition table in
``STATE_RECONCILIATION.md`` at the repo root):

- ``quoted`` -> ``proposed``: the deal entry state is the seller's
  proposed deal; "quoted" belongs to the Quote lifecycle, not the Deal.
- ``delivering`` -> ``active``: renamed per the primitives alias table.
- ``booking`` (in-flight booking) is not a wire state: the buyer's
  ``accepted -> booking -> booked`` pair collapses to ``accepted ->
  booked``, and booking failures/cancellations land on ``accepted ->
  failed`` / ``accepted -> cancelled``.
- ``partially_canceled`` -> ``partially_cancelled``: spelling normalized.
- Added ``proposed -> rejected`` and ``negotiating -> rejected``: the
  canonical ``DealStatus`` includes ``rejected`` (both repos' response
  models used it) but the buyer machine had no path into it.

Terminal states are explicit: ``completed``, ``rejected``, ``failed``,
``cancelled``, ``expired``. Per flagged decision FD-8 the seller's record
is authoritative for deal state; see ``reconciliation.py``.
"""

from __future__ import annotations

from ..primitives.lifecycle import DealStatus
from .machine import StateMachine, TransitionRule

_S = DealStatus

DEAL_TERMINAL_STATES: frozenset[DealStatus] = frozenset(
    {_S.COMPLETED, _S.REJECTED, _S.FAILED, _S.CANCELLED, _S.EXPIRED}
)

_TRANSITIONS: list[
    tuple[DealStatus, DealStatus, str] | tuple[DealStatus, DealStatus, str, bool]
] = [
    # Happy path
    (_S.PROPOSED, _S.NEGOTIATING, "Buyer initiates negotiation"),
    (_S.PROPOSED, _S.ACCEPTED, "Deal accepted without negotiation"),
    (_S.NEGOTIATING, _S.ACCEPTED, "Deal terms accepted"),
    (_S.NEGOTIATING, _S.PROPOSED, "Counter-offer received, terms re-proposed", True),
    (_S.ACCEPTED, _S.BOOKED, "Booking confirmed by seller"),
    (_S.BOOKED, _S.ACTIVE, "Campaign delivery started"),
    (_S.ACTIVE, _S.COMPLETED, "Campaign delivery completed"),
    # Rejection (seller declines; or buyer walks away in negotiation)
    (_S.PROPOSED, _S.REJECTED, "Proposed deal rejected"),
    (_S.NEGOTIATING, _S.REJECTED, "Negotiation ended in walk-away"),
    # Failure from active states
    (_S.PROPOSED, _S.FAILED, "Proposal processing failed"),
    (_S.NEGOTIATING, _S.FAILED, "Negotiation failed"),
    (_S.ACCEPTED, _S.FAILED, "Booking failed"),
    (_S.ACTIVE, _S.FAILED, "Delivery failed"),
    # Cancellation from non-terminal states
    (_S.PROPOSED, _S.CANCELLED, "Deal cancelled"),
    (_S.NEGOTIATING, _S.CANCELLED, "Deal cancelled during negotiation"),
    (_S.ACCEPTED, _S.CANCELLED, "Deal cancelled after acceptance"),
    (_S.BOOKED, _S.CANCELLED, "Booked deal cancelled"),
    (_S.ACTIVE, _S.CANCELLED, "Delivery cancelled"),
    # Expiry (acceptance window lapsed)
    (_S.PROPOSED, _S.EXPIRED, "Proposed deal expired"),
    (_S.NEGOTIATING, _S.EXPIRED, "Negotiation expired"),
    # Linear TV (television) extensions
    (_S.ACTIVE, _S.MAKEGOOD_PENDING, "Makegood requested for under-delivery"),
    (_S.MAKEGOOD_PENDING, _S.ACTIVE, "Makegood resolved, delivery resumed", True),
    (_S.MAKEGOOD_PENDING, _S.COMPLETED, "Makegood resolved, campaign complete"),
    (_S.MAKEGOOD_PENDING, _S.FAILED, "Makegood could not be fulfilled"),
    (_S.BOOKED, _S.PARTIALLY_CANCELLED, "Partial cancellation of booked units"),
    (_S.PARTIALLY_CANCELLED, _S.ACTIVE, "Partially cancelled deal begins delivery"),
    (_S.PARTIALLY_CANCELLED, _S.CANCELLED, "Remaining units cancelled"),
]

DEAL_LIFECYCLE: StateMachine[DealStatus] = StateMachine(
    name="deal",
    states=DealStatus,
    initial=DealStatus.PROPOSED,
    terminal=DEAL_TERMINAL_STATES,
    rules=[
        TransitionRule(from_state=row[0], to_state=row[1], description=row[2], rework=len(row) > 3)
        for row in _TRANSITIONS
    ],
)

__all__ = ["DEAL_LIFECYCLE", "DEAL_TERMINAL_STATES"]
