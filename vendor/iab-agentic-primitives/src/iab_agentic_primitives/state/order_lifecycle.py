"""Canonical Order lifecycle machine over the unified ``OrderStatus`` vocabulary.

Reconciles the seller agent's ``OrderStateMachine`` (21 transition rules in
``ad_seller/models/order_state_machine.py``, ``_DEFAULT_TRANSITIONS``) into
the 11-value canonical ``OrderStatus``. The buyer agent's OpenDirect (the
IAB — Interactive Advertising Bureau — direct-buying API standard) order
statuses were already folded into this vocabulary by the primitives layer.

The 'syncing' decision
----------------------
The seller's internal ``syncing`` state (in-flight ad-server sync between
``in_progress`` and ``booked``) is NOT a wire state — the primitives layer
dropped it from ``OrderStatus``, and this machine collapses the seller's
``in_progress -> syncing -> booked`` pair into ``in_progress -> booked``
(and ``syncing -> failed`` into the existing ``in_progress -> failed``).
In-flight sync is seller-internal mechanics, not a lifecycle fact the buyer
can act on. The seller represents it as an audit note on the
``in_progress`` state: write an :class:`~.machine.AuditEntry`-shaped record
with ``reason=AD_SERVER_SYNC_STARTED`` when sync begins (and the eventual
``in_progress -> booked`` / ``in_progress -> failed`` transition closes it
out). A seller may also keep a local boolean substate flag; neither the
flag nor the note ever crosses the wire.

Terminal states are explicit: ``completed`` and ``cancelled`` only.
``rejected``, ``failed``, and ``unbooked`` are recoverable (each returns to
``draft``), so they are deliberately NOT terminal. Per flagged decision
FD-8 the seller's record is authoritative for order/fulfillment state; see
``reconciliation.py``.
"""

from __future__ import annotations

from ..primitives.lifecycle import OrderStatus
from .machine import StateMachine, TransitionRule

_S = OrderStatus

# Shared audit-note reason for in-flight ad-server sync (see module docstring).
# Using one constant keeps both agents' audit trails grep-able for the same
# string; it is an audit detail, never a state and never a wire value.
AD_SERVER_SYNC_STARTED = "syncing to ad server"

ORDER_TERMINAL_STATES: frozenset[OrderStatus] = frozenset({_S.COMPLETED, _S.CANCELLED})

_TRANSITIONS: list[
    tuple[OrderStatus, OrderStatus, str] | tuple[OrderStatus, OrderStatus, str, bool]
] = [
    # Happy path
    (_S.DRAFT, _S.SUBMITTED, "Order submitted for review"),
    (_S.SUBMITTED, _S.PENDING_APPROVAL, "Awaiting human approval"),
    (_S.SUBMITTED, _S.APPROVED, "Auto-approved (no gate)"),
    (_S.PENDING_APPROVAL, _S.APPROVED, "Human approved"),
    (_S.PENDING_APPROVAL, _S.REJECTED, "Human rejected"),
    (_S.APPROVED, _S.IN_PROGRESS, "Execution started"),
    (_S.IN_PROGRESS, _S.BOOKED, "Ad server confirmed booking"),
    (_S.BOOKED, _S.COMPLETED, "Order fulfilled"),
    (_S.BOOKED, _S.UNBOOKED, "Booking reversed by ad server"),
    # Failure / cancellation from active states
    (_S.DRAFT, _S.CANCELLED, "Cancelled before submission"),
    (_S.SUBMITTED, _S.CANCELLED, "Cancelled after submission"),
    (_S.SUBMITTED, _S.FAILED, "Submission processing failed"),
    (_S.PENDING_APPROVAL, _S.CANCELLED, "Cancelled during approval"),
    (_S.APPROVED, _S.CANCELLED, "Cancelled after approval"),
    (_S.IN_PROGRESS, _S.FAILED, "Execution or ad-server sync failed"),
    (_S.IN_PROGRESS, _S.CANCELLED, "Cancelled during execution"),
    # Re-submission (recoverable non-terminal states; rework edges)
    (_S.REJECTED, _S.DRAFT, "Returned to draft for revision", True),
    (_S.FAILED, _S.DRAFT, "Reset to draft after failure", True),
    (_S.UNBOOKED, _S.DRAFT, "Reset to draft after unbooking", True),
]

ORDER_LIFECYCLE: StateMachine[OrderStatus] = StateMachine(
    name="order",
    states=OrderStatus,
    initial=OrderStatus.DRAFT,
    terminal=ORDER_TERMINAL_STATES,
    rules=[
        TransitionRule(from_state=row[0], to_state=row[1], description=row[2], rework=len(row) > 3)
        for row in _TRANSITIONS
    ],
)

__all__ = ["AD_SERVER_SYNC_STARTED", "ORDER_LIFECYCLE", "ORDER_TERMINAL_STATES"]
