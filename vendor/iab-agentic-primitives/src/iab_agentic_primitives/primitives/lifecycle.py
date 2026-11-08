"""Lifecycle wire primitives: Proposal, Negotiation, Deal, Order, Line,
ChangeRequest, Session.

Reconciled from the buyer agent's ``models/deals.py`` /
``models/opendirect.py`` / ``models/state_machine.py`` and the seller
agent's ``models/core.py`` / ``models/quotes.py`` /
``models/negotiation.py`` / ``models/order_state_machine.py`` /
``models/change_request.py`` / ``models/session.py``. See
RECONCILIATION.md at the repo root for the field-level audit trail.

Status vocabularies here are enums ONLY — transition rules and the
canonical state machines are EP-1.4 (``iab_agentic_primitives.state``).
"""

from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import Field, model_validator

from ._util import Money, WireModel, utc_now
from .identity import AccessTier, BuyerIdentity, ConsentContext
from .pricing import (
    DealType,
    LinearTVQuoteDetails,
    MediaType,
    PricingModel,
    PricingType,
    ProductRef,
    QuotePricing,
    QuoteTerms,
)
from .supply_chain import SupplyChain

# ---------------------------------------------------------------------------
# Canonical status vocabularies (ONE each — see RECONCILIATION.md)
# ---------------------------------------------------------------------------


class DealStatus(str, Enum):
    """ONE deal status vocabulary, unioned from the four competing sets.

    Sources: buyer ``DealResponse.status`` (proposed/active/rejected/
    expired/completed), seller ``DealBookingStatus`` (proposed/active/
    expired/cancelled), buyer ``BuyerDealStatus`` (quoted/negotiating/
    accepted/booking/booked/delivering/... + linear TV extensions).

    Recorded aliases (retired values, NOT valid on the wire):
    ``delivering`` -> ``active``; ``booking`` -> ``booked``;
    ``quoted`` -> represented by QuoteStatus, not a deal state;
    ``partially_canceled`` -> ``partially_cancelled``.
    """

    PROPOSED = "proposed"
    NEGOTIATING = "negotiating"
    ACCEPTED = "accepted"
    BOOKED = "booked"
    ACTIVE = "active"
    MAKEGOOD_PENDING = "makegood_pending"  # linear TV
    PARTIALLY_CANCELLED = "partially_cancelled"  # linear TV
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class OrderStatus(str, Enum):
    """ONE order status vocabulary.

    Adopts the seller's unified ``order_state_machine.OrderStatus`` (which
    already merged the seller's workflow and ad-server vocabularies).

    Recorded aliases (retired values, NOT valid on the wire): buyer
    OpenDirect ``PENDING`` -> ``pending_approval``; ``APPROVED``/``REJECTED``
    (uppercase) -> lowercase; seller ``ExecutionOrderStatus.proposed`` ->
    ``submitted``; ``canceled`` -> ``cancelled``. The seller-internal
    ``syncing`` ad-server state is dropped from the wire vocabulary.
    """

    DRAFT = "draft"
    SUBMITTED = "submitted"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    IN_PROGRESS = "in_progress"
    BOOKED = "booked"
    UNBOOKED = "unbooked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class LineStatus(str, Enum):
    """Line booking status. Keeps the OpenDirect (the IAB direct-buying API
    standard) vocabulary and wire casing — the published standard wins.
    """

    DRAFT = "Draft"
    PENDING_RESERVATION = "PendingReservation"
    RESERVED = "Reserved"
    PENDING_BOOKING = "PendingBooking"
    BOOKED = "Booked"
    IN_FLIGHT = "InFlight"
    FINISHED = "Finished"
    STOPPED = "Stopped"
    CANCELLED = "Cancelled"
    EXPIRED = "Expired"


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------


class ProposalStatus(str, Enum):
    """Status of a proposal (seller vocabulary; buyer had no proposal model)."""

    DRAFT = "draft"
    SENT = "sent"
    COUNTERED = "countered"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class GoalType(str, Enum):
    """Types of delivery goals."""

    IMPRESSIONS = "impressions"
    CLICKS = "clicks"
    VIEWABLE_IMPRESSIONS = "viewable_impressions"
    COMPLETIONS = "completions"


class BillableEvent(str, Enum):
    """Events that trigger billing."""

    IMPRESSION = "impression"
    VIEWABLE_IMPRESSION = "viewable_impression"
    CLICK = "click"
    COMPLETION = "completion"


class DeliveryGoal(WireModel):
    """Delivery goal for a proposal line."""

    goal_type: GoalType
    goal_amount: int = Field(ge=0)
    billable_event: BillableEvent


class PricingTerms(WireModel):
    """Pricing terms for a proposal line."""

    pricing_type: PricingType = PricingType.FIXED
    pricing_model: PricingModel | None = None
    price: Money | None = None


class ProposalLine(WireModel):
    """Individual line item within a proposal."""

    proposal_line_id: str = Field(description="Seller-issued proposal line identifier.")
    proposal_id: str
    product_id: str
    deal_type: DealType
    audience_targeting: dict[str, Any] | None = None
    ad_product_targeting: dict[str, Any] | None = None
    content_targeting: dict[str, Any] | None = None
    delivery_goal: DeliveryGoal
    pricing: PricingTerms
    external_ids: dict[str, Any] | None = None


class Proposal(WireModel):
    """A structured buy proposal under negotiation between the pair.

    The seller repo's revision machinery (JSON Patch revisions, hashes)
    stays seller-local; the shared primitive is the current proposal state.
    Multi-turn offer history is the :class:`Negotiation` primitive.

    ID minting: ``proposal_id`` is seller-issued (created via the seller's
    API on buyer request).
    """

    proposal_id: str = Field(description="Seller-issued proposal identifier.")
    proposal_thread_id: str | None = Field(
        default=None,
        description="Stable id across all revisions of this negotiation, if threaded.",
    )
    account_id: str = Field(description="Seller-issued account identifier.")
    status: ProposalStatus = ProposalStatus.DRAFT
    current_revision_number: int = Field(default=1, ge=1)
    start_date: date
    end_date: date
    lines: list[ProposalLine] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None
    ext: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Negotiation (multi-turn offer history container)
# ---------------------------------------------------------------------------


class NegotiationAction(str, Enum):
    """Action taken in a negotiation round."""

    ACCEPT = "accept"
    COUNTER = "counter"
    REJECT = "reject"  # walk-away
    FINAL_OFFER = "final_offer"  # last round before walk-away


class NegotiationStatus(str, Enum):
    """Status of a negotiation (typed; was a raw string in the seller repo)."""

    ACTIVE = "active"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class NegotiationRound(WireModel):
    """A single offer/counter round in a negotiation."""

    round_number: int = Field(ge=1)
    buyer_price: Money = Field(description="What the buyer offered this round.")
    seller_price: Money = Field(
        description="What the seller countered (or accepted at) this round."
    )
    action: NegotiationAction
    concession_pct: float = Field(default=0.0, description="Seller concession this round (0-1).")
    cumulative_concession_pct: float = Field(
        default=0.0, description="Total seller concession so far (0-1)."
    )
    rationale: str = ""
    timestamp: datetime = Field(default_factory=utc_now)


class Negotiation(WireModel):
    """Multi-turn offer history container for a buyer/seller negotiation.

    From the seller's ``NegotiationHistory``, minus everything that must
    NOT cross the wire: the seller's ``floor_price``, ``base_price``,
    strategy, and concession limits are seller-internal guardrails and are
    deliberately absent from the shared schema.

    ID minting: ``negotiation_id`` is seller-issued.
    """

    negotiation_id: str = Field(description="Seller-issued negotiation identifier.")
    proposal_id: str | None = Field(
        default=None, description="Proposal under negotiation, if proposal-led."
    )
    quote_id: str | None = Field(default=None, description="Quote under negotiation, if quote-led.")
    product_id: str | None = None
    package_id: str | None = Field(default=None, description="Set when negotiating on a package.")
    buyer_tier: AccessTier = AccessTier.PUBLIC
    rounds: list[NegotiationRound] = Field(default_factory=list)
    status: NegotiationStatus = NegotiationStatus.ACTIVE
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Deal
# ---------------------------------------------------------------------------


class OpenRTBParams(WireModel):
    """OpenRTB (Open Real-Time Bidding) deal parameters for DSP
    (demand-side platform) activation."""

    id: str = Field(description="Deal id as it appears in the OpenRTB bid stream.")
    bidfloor: Money = Field(
        description="Bid floor (exact micros; FD-11). Adapters translate to the raw "
        "OpenRTB float `bidfloor`/`bidfloorcur` encoding at the DSP edge."
    )
    at: int = Field(default=3, description="Auction type (3 = fixed price).")
    wseat: list[str] = Field(default_factory=list, description="Allowed buyer seats.")
    wadomain: list[str] = Field(default_factory=list, description="Allowed advertiser domains.")


class Deal(WireModel):
    """A confirmed deal booked from a quote (Deals API v1.0 book phase).

    ID minting: ``deal_id`` is seller-issued.
    """

    deal_id: str = Field(description="Seller-issued deal identifier.")
    deal_type: DealType
    status: DealStatus = DealStatus.PROPOSED
    quote_id: str | None = Field(
        default=None, description="Seller-issued id of the quote this deal booked."
    )
    rate_card_id: str | None = Field(
        default=None,
        description="Seller-issued id of the private rate card this deal books "
        "against, when the pair has one (FD-9). Never embedded, only referenced.",
    )
    product: ProductRef
    pricing: QuotePricing
    terms: QuoteTerms
    buyer_tier: AccessTier = AccessTier.PUBLIC
    seller_id: str | None = Field(
        default=None, description="Registry-issued id of the selling agent."
    )
    expires_at: datetime | None = Field(
        default=None, description="Acceptance window for a proposed deal."
    )
    activation_instructions: dict[str, str] = Field(default_factory=dict)
    openrtb_params: OpenRTBParams | None = None
    media_type: MediaType = MediaType.DIGITAL
    linear_tv: LinearTVQuoteDetails | None = Field(
        default=None,
        description="Linear TV details carried over from the booked quote (FD-6).",
    )
    created_at: datetime = Field(default_factory=utc_now)
    consent_context: ConsentContext | None = Field(
        default=None, description="Privacy consent signals riding with the deal (FD-10)."
    )
    supply_chain: SupplyChain | None = Field(
        default=None,
        description="OpenRTB supply chain (schain) for transparency (EP-10.3); "
        "optional so pre-schain deals still validate.",
    )


# ---------------------------------------------------------------------------
# Order & Line (OpenDirect campaign container + booking unit)
# ---------------------------------------------------------------------------


class Order(WireModel):
    """Campaign container (insertion order) holding one or more lines.

    Merges the buyer's OpenDirect ``Order`` with the seller's
    ``ExecutionOrder``. Per flagged decision FD-8, the seller's record is
    authoritative for order/fulfillment state.

    ID minting: ``order_id`` is seller-issued (created via the seller's
    API on buyer request).
    """

    order_id: str = Field(description="Seller-issued order identifier.")
    account_id: str = Field(description="Seller-issued account identifier.")
    proposal_id: str | None = Field(
        default=None, description="Proposal this order materializes, if any."
    )
    deal_id: str | None = Field(default=None, description="Deal this order fulfils, if deal-led.")
    name: str = Field(max_length=200)
    budget: Money = Field(description="Estimated budget (exact micros; FD-11).")
    start_date: date
    end_date: date
    status: OrderStatus = OrderStatus.DRAFT
    external_ids: dict[str, Any] | None = Field(
        default=None, description="Ad-server order references (e.g. GAM order id)."
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None
    consent_context: ConsentContext | None = Field(
        default=None, description="Privacy consent signals riding with the order (FD-10)."
    )
    ext: dict[str, Any] | None = None


class Line(WireModel):
    """Individual product booking within an order (OpenDirect Line).

    The seller maps a line to its internal placement/ad-server entities;
    ``Line`` is the only execution unit on the wire.

    ID minting: ``line_id`` is seller-issued.
    """

    line_id: str = Field(description="Seller-issued line identifier.")
    order_id: str
    product_id: str
    name: str = Field(max_length=200)
    start_date: date
    end_date: date
    pricing_model: PricingModel = PricingModel.CPM
    rate: Money = Field(description="Rate per pricing-model unit (exact micros; FD-11).")
    quantity: int = Field(ge=0, description="Target impressions or units.")
    cost: Money | None = Field(
        default=None, description="Calculated cost (read-only, seller-computed)."
    )
    status: LineStatus = LineStatus.DRAFT
    targeting: dict[str, Any] | None = None
    ext: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# ChangeRequest (post-booking modifications; makegood is a typed subtype — FD-6)
# ---------------------------------------------------------------------------


class ChangeRequestStatus(str, Enum):
    """Lifecycle status of a change request."""

    PENDING = "pending"
    VALIDATING = "validating"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    FAILED = "failed"


class ChangeType(str, Enum):
    """Category of change being requested.

    ``makegood`` implements flagged decision FD-6: makegoods are a typed
    ChangeRequest subtype, not a separate primitive.
    """

    FLIGHT_DATES = "flight_dates"
    IMPRESSIONS = "impressions"
    PRICING = "pricing"
    CREATIVE = "creative"
    TARGETING = "targeting"
    CANCELLATION = "cancellation"
    MAKEGOOD = "makegood"
    OTHER = "other"


class ChangeSeverity(str, Enum):
    """How significant the change is — determines approval requirements."""

    MINOR = "minor"
    MATERIAL = "material"
    CRITICAL = "critical"


class FieldDiff(WireModel):
    """A single field-level change."""

    field: str
    old_value: Any = None
    new_value: Any = None


class MakegoodStatus(str, Enum):
    """Compensation status of a makegood (EP-10.2)."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    SCHEDULED = "scheduled"
    DELIVERED = "delivered"
    REJECTED = "rejected"


class MakegoodDetails(WireModel):
    """Makegood payload for a ChangeRequest of type ``makegood`` (FD-6).

    Sent when delivery falls short of the guaranteed level; the seller
    responds with replacement inventory. Carries the compensation terms:
    what is owed (``shortfall_grps`` for linear TV, ``owed_impressions``
    for digital), the proposed replacement flight, and the makegood
    ``status``. The human-readable reason lives on the enclosing
    :class:`ChangeRequest.reason` (not duplicated here). GRP = gross rating
    point.
    """

    shortfall_grps: float = Field(
        description="GRP shortfall owed that needs to be made up (linear TV)."
    )
    original_daypart: str = Field(description="Daypart where the underdelivery occurred.")
    target_demo: str = Field(description="Target demographic for makegood inventory.")
    owed_impressions: int | None = Field(
        default=None,
        ge=0,
        description="Impressions owed for a digital makegood; None for a pure-GRP makegood.",
    )
    preferred_dayparts: list[str] | None = Field(
        default=None, description="Buyer's preferred dayparts for replacement inventory."
    )
    replacement_flight_start: date | None = Field(
        default=None, description="Proposed start of the replacement flight."
    )
    replacement_flight_end: date | None = Field(
        default=None, description="Proposed end of the replacement flight."
    )
    status: MakegoodStatus = Field(
        default=MakegoodStatus.PROPOSED,
        description="Compensation status of the makegood.",
    )
    notes: str | None = None


class ChangeRequest(WireModel):
    """A request to modify an existing order or deal post-booking.

    ID minting: ``change_request_id`` is seller-issued (the buyer submits
    the request; the seller assigns the identifier and owns its lifecycle).
    """

    change_request_id: str = Field(description="Seller-issued change request identifier.")
    order_id: str | None = Field(
        default=None, description="Order being modified; at least one of order_id/deal_id."
    )
    deal_id: str | None = Field(
        default=None, description="Deal being modified; at least one of order_id/deal_id."
    )
    status: ChangeRequestStatus = ChangeRequestStatus.PENDING
    change_type: ChangeType
    severity: ChangeSeverity = ChangeSeverity.MATERIAL
    requested_by: str = Field(
        default="system", description="Actor id: 'system', 'human:<id>', or 'agent:<id>'."
    )
    requested_at: datetime = Field(default_factory=utc_now)
    reason: str = ""
    diffs: list[FieldDiff] = Field(default_factory=list)
    proposed_values: dict[str, Any] = Field(default_factory=dict)
    makegood: MakegoodDetails | None = Field(
        default=None, description="Required when change_type == 'makegood' (FD-6)."
    )
    validation_errors: list[str] = Field(default_factory=list)
    pricing_impact: dict[str, Any] | None = None
    availability_check: dict[str, Any] | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejection_reason: str | None = None
    applied_at: datetime | None = None
    applied_by: str | None = None

    @model_validator(mode="after")
    def _require_target(self) -> "ChangeRequest":
        if self.order_id is None and self.deal_id is None:
            raise ValueError("ChangeRequest requires at least one of order_id or deal_id")
        return self


# ---------------------------------------------------------------------------
# Session (multi-turn conversation persistence)
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    """Lifecycle status of a session."""

    ACTIVE = "active"
    EXPIRED = "expired"
    CLOSED = "closed"


class SessionMessage(WireModel):
    """A single message in a session conversation."""

    role: str = Field(description='"user" or "assistant".')
    content: str
    timestamp: datetime = Field(default_factory=utc_now)
    message_type: str | None = Field(
        default=None, description='"pricing", "deal", "availability", "general".'
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class Session(WireModel):
    """A persistent multi-turn buyer conversation with a seller.

    The seller repo's internal flow-threading and negotiation-funnel state
    stay seller-local; the shared primitive links the conversation to its
    negotiations and deals by id.

    ID minting: ``session_id`` is seller-issued.
    """

    session_id: str = Field(description="Seller-issued session identifier.")
    status: SessionStatus = SessionStatus.ACTIVE
    buyer_identity: BuyerIdentity = Field(default_factory=BuyerIdentity)
    messages: list[SessionMessage] = Field(default_factory=list)
    active_negotiation_ids: list[str] = Field(default_factory=list)
    active_deal_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    closed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "BillableEvent",
    "ChangeRequest",
    "ChangeRequestStatus",
    "ChangeSeverity",
    "ChangeType",
    "Deal",
    "DealStatus",
    "DeliveryGoal",
    "FieldDiff",
    "GoalType",
    "Line",
    "LineStatus",
    "MakegoodDetails",
    "MakegoodStatus",
    "Negotiation",
    "NegotiationAction",
    "NegotiationRound",
    "NegotiationStatus",
    "OpenRTBParams",
    "Order",
    "OrderStatus",
    "PricingTerms",
    "Proposal",
    "ProposalLine",
    "ProposalStatus",
    "Session",
    "SessionMessage",
    "SessionStatus",
]
