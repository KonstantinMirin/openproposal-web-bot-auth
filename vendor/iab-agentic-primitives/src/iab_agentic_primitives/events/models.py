"""Canonical event vocabulary and envelope shared by the buyer and seller agents.

This module is the single source of truth for the event types both agents emit
and for the ``Event`` envelope that carries them. It reconciles the two diverged
per-repo copies (buyer ``ad_buyer/events/models.py``, 38 types; seller
``ad_seller/events/models.py``, 22 types) into one vocabulary. The full
per-value mapping, including which legacy values were renamed or dropped as
duplicates, lives in ``EVENTS_RECONCILIATION.md`` at the repo root; the
machine-readable subset of that mapping (legacy string -> canonical member) is
:data:`LEGACY_ALIASES` below.

Emitter conventions (who emits what):

- **buyer-emitted domains**: ``quote.*``, ``campaign.*``, ``budget.*``,
  ``order.*``, ``inventory.*``, ``pacing.*``, ``creative.*``, ``portfolio.*``
- **seller-emitted domains**: ``proposal.*``, ``package.*``, ``execution.*``
- **either side**: ``deal.*``, ``negotiation.*``, ``approval.*``, ``session.*``
  (the ``Event.source_agent`` field disambiguates the emitter)
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC (Coordinated Universal Time) datetime.

    Defined locally so the events package has no dependency on utilities
    elsewhere in this library.
    """
    return datetime.now(UTC)


class EventType(str, Enum):
    """Canonical event vocabulary for the buyer/seller agent pair.

    Values are dot-namespaced, lowercase, and grouped by domain. Every
    genuinely distinct concept from either source repo is preserved;
    same-concept variants were merged (see ``EVENTS_RECONCILIATION.md``).
    """

    # Approval gates -- emitted by either agent when a human gate is involved.
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    # Canonical for buyer "approval.rejected" AND seller "approval.denied".
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_TIMED_OUT = "approval.timed_out"

    # Budget lifecycle -- buyer-emitted.
    BUDGET_ALLOCATED = "budget.allocated"

    # Campaign lifecycle -- buyer-emitted.
    CAMPAIGN_CREATED = "campaign.created"
    CAMPAIGN_BRIEF_VALIDATED = "campaign.brief_validated"
    CAMPAIGN_PLAN_GENERATED = "campaign.plan_generated"
    CAMPAIGN_PLAN_APPROVED = "campaign.plan_approved"
    CAMPAIGN_BOOKING_STARTED = "campaign.booking_started"
    CAMPAIGN_BOOKING_COMPLETED = "campaign.booking_completed"
    CAMPAIGN_READY = "campaign.ready"
    CAMPAIGN_ACTIVATED = "campaign.activated"
    CAMPAIGN_COMPLETED = "campaign.completed"
    # Spelling normalized to "cancelled" (legacy buyer value: "campaign.canceled").
    CAMPAIGN_CANCELLED = "campaign.cancelled"

    # Creative lifecycle -- buyer-emitted.
    CREATIVE_UPLOADED = "creative.uploaded"
    CREATIVE_VALIDATED = "creative.validated"
    CREATIVE_MATCHED = "creative.matched"
    CREATIVE_ROTATION_UPDATED = "creative.rotation_updated"
    CREATIVE_AD_SERVER_PUSHED = "creative.ad_server_pushed"

    # Deal lifecycle -- both sides emit deal events for their own stages:
    # seller: created, registered, synced; buyer: booked, cancelled, imported,
    # template_created, manual_action_required.
    DEAL_CREATED = "deal.created"
    DEAL_REGISTERED = "deal.registered"
    DEAL_SYNCED = "deal.synced"
    DEAL_BOOKED = "deal.booked"
    DEAL_CANCELLED = "deal.cancelled"
    DEAL_IMPORTED = "deal.imported"
    DEAL_TEMPLATE_CREATED = "deal.template_created"
    DEAL_MANUAL_ACTION_REQUIRED = "deal.manual_action_required"

    # Execution lifecycle -- seller-emitted.
    EXECUTION_COMPLETED = "execution.completed"

    # Inventory lifecycle -- buyer-emitted.
    INVENTORY_DISCOVERED = "inventory.discovered"

    # Negotiation lifecycle -- emitted by either agent.
    NEGOTIATION_STARTED = "negotiation.started"
    NEGOTIATION_ROUND = "negotiation.round"
    NEGOTIATION_CONCLUDED = "negotiation.concluded"

    # Order lifecycle -- buyer-emitted (legacy buyer value: "booking.submitted").
    ORDER_SUBMITTED = "order.submitted"

    # Pacing lifecycle -- buyer-emitted.
    PACING_SNAPSHOT_TAKEN = "pacing.snapshot_taken"
    PACING_DEVIATION_DETECTED = "pacing.deviation_detected"
    PACING_REALLOCATION_RECOMMENDED = "pacing.reallocation_recommended"
    PACING_REALLOCATION_APPLIED = "pacing.reallocation_applied"

    # Package lifecycle -- seller-emitted.
    PACKAGE_CREATED = "package.created"
    PACKAGE_UPDATED = "package.updated"
    PACKAGE_SYNCED = "package.synced"

    # Portfolio lifecycle -- buyer-emitted.
    PORTFOLIO_INSPECTED = "portfolio.inspected"

    # Proposal lifecycle -- seller-emitted (the seller's view of the
    # request-for-quote exchange; pairs with the buyer's quote.* events).
    PROPOSAL_RECEIVED = "proposal.received"
    PROPOSAL_EVALUATED = "proposal.evaluated"
    PROPOSAL_ACCEPTED = "proposal.accepted"
    PROPOSAL_REJECTED = "proposal.rejected"
    PROPOSAL_COUNTERED = "proposal.countered"

    # Quote lifecycle -- buyer-emitted (the buyer's view of the
    # request-for-quote exchange; pairs with the seller's proposal.* events).
    QUOTE_REQUESTED = "quote.requested"
    QUOTE_RECEIVED = "quote.received"

    # Session lifecycle -- emitted by either agent.
    SESSION_CREATED = "session.created"
    SESSION_RESUMED = "session.resumed"
    SESSION_CLOSED = "session.closed"


#: Legacy event-type strings (from the pre-reconciliation buyer/seller repos)
#: whose canonical value uses a *different* string. Legacy values not listed
#: here are unchanged: the same string is the canonical value.
LEGACY_ALIASES: dict[str, EventType] = {
    # seller ad_seller/events/models.py
    "approval.denied": EventType.APPROVAL_REJECTED,
    # buyer ad_buyer/events/models.py
    "campaign.canceled": EventType.CAMPAIGN_CANCELLED,
    "booking.submitted": EventType.ORDER_SUBMITTED,
}


class Event(BaseModel):
    """The canonical event envelope emitted by both agents.

    Correlation identifiers are all optional; an emitter sets whichever ones
    the event relates to (for example, the seller sets ``proposal_id`` on
    ``proposal.*`` events; the buyer sets ``campaign_id`` on ``campaign.*``
    events; either side sets ``deal_id`` once a deal exists). Anything that
    does not fit a first-class field (including the legacy ``flow_id``,
    ``flow_type``, and ``payload`` fields of the per-repo envelopes) travels
    in ``metadata``.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    occurred_at: datetime = Field(default_factory=utc_now)
    source_agent: Literal["buyer", "seller"]

    # Optional correlation identifiers.
    deal_id: str | None = None
    order_id: str | None = None
    proposal_id: str | None = None
    campaign_id: str | None = None
    session_id: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def _require_timezone_aware_utc(cls, value: datetime) -> datetime:
        """Reject naive datetimes and normalize aware ones to UTC."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("occurred_at must be timezone-aware (UTC)")
        return value.astimezone(UTC)
