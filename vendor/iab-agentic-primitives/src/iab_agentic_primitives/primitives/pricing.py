"""Pricing wire primitives: DealType, pricing enums, linear TV, RateCard, Quote.

Reconciled from the buyer agent's ``models/deals.py`` /
``models/linear_tv.py`` / ``models/buyer_identity.py`` and the seller
agent's ``models/quotes.py`` / ``models/pricing_type.py`` /
``models/core.py``. See RECONCILIATION.md at the repo root for the
field-level audit trail.
"""

from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._util import Money, WireModel, utc_now
from .identity import AccessTier, ConsentContext

# ---------------------------------------------------------------------------
# Deal type — ONE enum, wire values win
# ---------------------------------------------------------------------------


class DealType(str, Enum):
    """Programmatic deal types. The short wire encoding is canonical.

    - ``PG`` = Programmatic Guaranteed: fixed price, guaranteed impressions
    - ``PD`` = Preferred Deal: fixed price, non-guaranteed first look
    - ``PA`` = Private Auction: auction with floor price, invited buyers

    Mapping from the seller repo's retired long-form encoding
    (``models/core.py``): ``programmaticguaranteed`` -> ``PG``,
    ``preferreddeal`` -> ``PD``, ``privateauction`` -> ``PA``. The
    long-form strings are NOT valid wire values.
    """

    PROGRAMMATIC_GUARANTEED = "PG"
    PREFERRED_DEAL = "PD"
    PRIVATE_AUCTION = "PA"


# ---------------------------------------------------------------------------
# Pricing enums
# ---------------------------------------------------------------------------


class PricingType(str, Enum):
    """How a price signal should be interpreted.

    - ``fixed``: price is set by the seller, use as-is
    - ``floor``: minimum price; negotiation expected above this level
    - ``on_request``: no price available; buyer must negotiate before any
      pricing exists (pricing fields are None — buyers must never fabricate
      a price for on_request inventory)
    """

    FIXED = "fixed"
    FLOOR = "floor"
    ON_REQUEST = "on_request"


class PricingModel(str, Enum):
    """Unit of pricing. Union of the buyer's ``RateType`` and the seller's
    ``PricingModel`` plus the linear TV additions.

    - ``cpm``: cost per mille (thousand impressions)
    - ``cpmv``: cost per thousand viewable impressions
    - ``cpv``: cost per view
    - ``cpc``: cost per click
    - ``cpcv``: cost per completed view
    - ``cpd``: cost per day
    - ``cpp``: cost per (gross rating) point — linear TV
    - ``flat_fee``: flat fee (buyer repo's ``FlatRate`` maps here)
    - ``unit_rate``: per-unit rate
    - ``hybrid``: mixed CPM/CPP pricing — linear TV
    """

    CPM = "cpm"
    CPMV = "cpmv"
    CPV = "cpv"
    CPC = "cpc"
    CPCV = "cpcv"
    CPD = "cpd"
    CPP = "cpp"
    FLAT_FEE = "flat_fee"
    UNIT_RATE = "unit_rate"
    HYBRID = "hybrid"


class MediaType(str, Enum):
    """Media type discriminator carried on quotes and deals.

    Sellers that do not support ``linear_tv`` MUST return a structured
    rejection rather than silently mispricing (flagged decision FD-6);
    the field exists on the shared schema so that rejection can be
    structural.
    """

    DIGITAL = "digital"
    CTV = "ctv"  # CTV = connected television
    LINEAR_TV = "linear_tv"


# ---------------------------------------------------------------------------
# Linear TV parameters (buyer models/linear_tv.py shape — FD-6)
# ---------------------------------------------------------------------------


class LinearTVParams(WireModel):
    """Linear-TV-specific request parameters (buyer-supplied).

    Used when ``media_type == "linear_tv"``. GRP = gross rating point;
    CPP = cost per point; DMA = designated market area.
    """

    target_demo: str = Field(
        description='Target demographic, e.g. "A18-49", "A25-54", "HH" (households).'
    )
    grps_requested: int | None = Field(
        default=None, description="Requested volume in GRPs (gross rating points)."
    )
    dayparts: list[str] | None = Field(
        default=None,
        description='Target dayparts, e.g. "primetime", "daytime", "late_night".',
    )
    networks: list[str] | None = Field(
        default=None, description='Target networks, e.g. ["NBC", "ESPN"].'
    )
    dmas: list[str] | None = Field(
        default=None,
        description="Nielsen DMA (designated market area) codes; None means national.",
    )
    spot_length: int = Field(default=30, description="Spot length in seconds: 15, 30, or 60.")
    target_cpp: Money | None = Field(
        default=None, description="Buyer's desired CPP (cost per point)."
    )
    measurement_currency: str = Field(
        default="nielsen",
        description='Audience measurement provider: "nielsen", "comscore", "videoamp".',
    )
    rotation: str = Field(
        default="ros",
        description='Spot rotation: "ros" (run of schedule), "fixed", "program_specific".',
    )


class CancellationTerms(WireModel):
    """Structured cancellation window for linear TV deals."""

    notice_days: int = Field(description="Days of notice required before cancellation.")
    cancellable_pct: float = Field(
        ge=0.0, le=1.0, description="Portion of the deal that can be cancelled (0.0-1.0)."
    )
    deadline: date | None = Field(default=None, description="Absolute deadline for cancellation.")
    force_majeure: bool = Field(default=True, description="Whether force majeure exceptions apply.")


class LinearTVQuoteDetails(WireModel):
    """Linear-TV-specific quote details (seller-populated).

    Nested under ``Quote.linear_tv`` when ``media_type == "linear_tv"``.
    """

    target_demo: str
    estimated_grps: float = Field(description="Estimated GRPs (gross rating points).")
    estimated_rating: float
    cpp: Money = Field(description="CPP (cost per point) offered by the seller.")
    dayparts: list[str]
    networks: list[str]
    spots_per_week: int
    total_spots: int
    spot_length: int
    measurement_currency: str
    audience_estimate: dict[str, Any] = Field(
        default_factory=dict,
        description='Audience estimates; expected keys "demo", "universe", "impressions_equiv".',
    )
    cancellation_terms: CancellationTerms | None = None
    makegood_policy: str | None = Field(
        default=None,
        description='Makegood policy: "standard" (audience deficiency unit), '
        '"negotiated", or "none".',
    )


# ---------------------------------------------------------------------------
# RateCard (flagged decision FD-9)
# ---------------------------------------------------------------------------


class RateCardStatus(str, Enum):
    """Agreement status of a rate card."""

    PROPOSED = "proposed"
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"


class RateCardEntry(WireModel):
    """One negotiated rate: a product/format mapped to an agreed price."""

    product_id: str | None = Field(
        default=None, description="Seller-issued product the rate applies to."
    )
    package_id: str | None = Field(
        default=None, description="Seller-issued package the rate applies to."
    )
    ad_format: str | None = Field(
        default=None,
        description='OpenRTB (Open Real-Time Bidding) format: "banner", "video", '
        '"native", "audio".',
    )
    pricing_model: PricingModel = PricingModel.CPM
    rate: Money = Field(description="Agreed rate (exact micros; FD-11).")
    notes: str | None = None


class RateCard(WireModel):
    """The private, negotiated rates a specific buyer/seller pair has agreed to.

    Per the ratified flagged decision FD-9: a rate card is a persisted,
    shared-schema object **private to the pair** — it is NEVER public and is
    never disclosed to any other party. Quotes and deals book against it by
    referencing ``rate_card_id``; they do not embed it. The seller's internal
    list/default pricing is deliberately NOT modeled here — that remains
    seller-local configuration.

    ID minting: ``rate_card_id`` is seller-issued when the negotiated
    agreement is recorded.
    """

    rate_card_id: str = Field(description="Seller-issued rate card identifier.")
    buyer_organization_id: str = Field(
        description="Registry-issued id of the buyer party to the agreement."
    )
    seller_organization_id: str = Field(
        description="Registry-issued id of the seller party to the agreement."
    )
    account_id: str | None = Field(
        default=None, description="Seller-issued account the agreement rides on, if any."
    )
    entries: list[RateCardEntry] = Field(
        default_factory=list, description="Negotiated product/format -> rate entries."
    )
    effective_from: date = Field(description="First day the agreed rates apply.")
    effective_to: date | None = Field(
        default=None, description="Last day the agreed rates apply; None = open-ended."
    )
    status: RateCardStatus = RateCardStatus.PROPOSED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None
    notes: str | None = None


# ---------------------------------------------------------------------------
# Quote
# ---------------------------------------------------------------------------


class QuoteStatus(str, Enum):
    """Status of a price quote (identical in both source repos)."""

    AVAILABLE = "available"
    BOOKED = "booked"
    EXPIRED = "expired"
    DECLINED = "declined"


class ProductRef(WireModel):
    """Lightweight product summary embedded in quotes and deals."""

    product_id: str = Field(description="Seller-issued product identifier.")
    name: str
    inventory_type: str | None = None


class QuotePricing(WireModel):
    """Pricing breakdown on a quote or deal.

    ``base_cpm``/``final_cpm`` are optional to support
    ``pricing_type=on_request`` — when the seller has not provided pricing,
    these fields are None. CPM = cost per mille (thousand impressions);
    CPP = cost per point (linear TV).
    """

    pricing_type: PricingType = PricingType.FIXED
    base_cpm: Money | None = None
    tier_discount_pct: float = 0.0
    volume_discount_pct: float = 0.0
    final_cpm: Money | None = None
    pricing_model: PricingModel = PricingModel.CPM
    rationale: str = ""
    base_cpp: Money | None = Field(
        default=None, description="Linear TV base CPP; None for digital/CTV."
    )
    final_cpp: Money | None = Field(
        default=None, description="Linear TV final CPP; None for digital/CTV."
    )


class QuoteTerms(WireModel):
    """Volume, flight, and guarantee terms on a quote or deal."""

    impressions: int | None = Field(default=None, ge=0)
    flight_start: date | None = None
    flight_end: date | None = None
    guaranteed: bool = False
    grps: int | None = Field(
        default=None, description="Linear TV volume in GRPs (gross rating points)."
    )
    guaranteed_grps: int | None = None
    target_demo: str | None = Field(default=None, description="Linear TV target demographic.")


class QuoteAvailability(WireModel):
    """Inventory availability information in a quote."""

    inventory_available: bool = True
    estimated_fill_rate: float | None = None
    competing_demand: str | None = None


class Quote(WireModel):
    """A non-binding price quote from a seller (Deals API v1.0 quote phase).

    Carries ``media_type`` and optional ``linear_tv`` details on the shared
    schema (flagged decision FD-6) so sellers that do not support linear TV
    can reject structurally instead of silently mispricing.

    ID minting: ``quote_id`` is seller-issued.
    """

    quote_id: str = Field(description="Seller-issued quote identifier.")
    status: QuoteStatus = QuoteStatus.AVAILABLE
    deal_type: DealType
    product: ProductRef
    pricing: QuotePricing
    terms: QuoteTerms
    availability: QuoteAvailability | None = None
    buyer_tier: AccessTier = AccessTier.PUBLIC
    rate_card_id: str | None = Field(
        default=None,
        description="Seller-issued id of the private rate card this quote prices "
        "against, when the pair has one (FD-9). The rate card itself is never embedded.",
    )
    expires_at: datetime | None = None
    seller_id: str | None = Field(
        default=None, description="Registry-issued id of the quoting seller agent."
    )
    created_at: datetime = Field(default_factory=utc_now)
    deal_id: str | None = Field(
        default=None, description="Seller-issued deal id, set once the quote is booked."
    )
    media_type: MediaType = MediaType.DIGITAL
    linear_tv: LinearTVQuoteDetails | None = Field(
        default=None, description="Linear TV details; None for digital/CTV."
    )
    consent_context: ConsentContext | None = Field(
        default=None, description="Privacy consent signals riding with the quote (FD-10)."
    )


__all__ = [
    "CancellationTerms",
    "DealType",
    "LinearTVParams",
    "LinearTVQuoteDetails",
    "MediaType",
    "PricingModel",
    "PricingType",
    "ProductRef",
    "Quote",
    "QuoteAvailability",
    "QuotePricing",
    "QuoteStatus",
    "QuoteTerms",
    "RateCard",
    "RateCardEntry",
    "RateCardStatus",
]
