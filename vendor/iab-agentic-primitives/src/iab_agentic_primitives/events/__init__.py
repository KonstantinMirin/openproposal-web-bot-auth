"""Shared event types crossing the buyer/seller boundary.

The single event vocabulary (event enum and event payload types) shared by
both agents, so that lifecycle notifications, negotiation moves, and audit
trails are emitted and consumed against one definition rather than two
drifting copies. Defining events in the shared contract is what lets a
future DecisionRecord/AuditEvent backfill reconstruct why money moved --
which counterparty inputs and which model outputs drove a booking -- with
both repos agreeing on the event shapes.
"""

from .models import LEGACY_ALIASES, Event, EventType, utc_now

__all__ = ["LEGACY_ALIASES", "Event", "EventType", "utc_now"]
