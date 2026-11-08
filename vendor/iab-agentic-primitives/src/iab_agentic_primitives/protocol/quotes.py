"""Quote surface of the Deals API quote->book flow.

- ``POST /api/v1/quotes`` — request a non-binding quote; body is
  :class:`QuoteRequest`, success response is :class:`QuoteResponse`
  (an envelope wrapping the shared
  :class:`~iab_agentic_primitives.primitives.Quote` primitive).
- ``GET /api/v1/quotes/{quote_id}`` — retrieve; response is
  :class:`QuoteResponse`.

Reconciled from the buyer's ``models/deals.QuoteRequest`` and the
seller's inline ``QuoteRequestModel`` (``interfaces/api/main.py``). The
buyer sent ``agent_url``, ``media_type``, ``linear_tv``, and
``audience_plan``; the seller's model silently dropped all four. The
canonical request carries every one of them, plus ``rate_card_id`` (FD-9)
and a required ``idempotency_key`` (FD-12 — see
:mod:`iab_agentic_primitives.protocol._base` for replay semantics).

Linear TV rejection (FD-6): a seller that does not support the requested
``media_type`` (or any other requested capability) MUST reject with the
structured error envelope —
``{"detail": {"error": "unsupported_capability", "unsupported":
[{"capability": "linear_tv"}]}}`` — never silently misprice. See
:mod:`iab_agentic_primitives.protocol.errors`.

Acronyms: FD = flagged decision (remediation plan §7.2 register);
CPM = cost per mille (thousand impressions); TTL = time to live;
A2A = agent-to-agent protocol.
"""

from datetime import date

from pydantic import Field, model_validator

from ..primitives import (
    BuyerIdentity,
    ConsentContext,
    DealType,
    LinearTVParams,
    MediaType,
    Money,
    Quote,
    WireModel,
)
from ._base import IdempotentRequest


class QuoteRequest(IdempotentRequest):
    """Request body for ``POST /api/v1/quotes`` (money-mutating: FD-12).

    ID minting: the seller mints ``quote_id`` in the response; the buyer
    never proposes one.
    """

    product_id: str = Field(description="Seller-issued product to quote.")
    deal_type: DealType = Field(
        description="'PG' (Programmatic Guaranteed), 'PD' (Preferred Deal), "
        "'PA' (Private Auction). Typed — the retired long-form strings are "
        "not valid wire values."
    )
    impressions: int | None = Field(
        default=None, ge=0, description="Requested volume; required for PG."
    )
    flight_start: date | None = None
    flight_end: date | None = None
    target_cpm: Money | None = Field(
        default=None,
        description="Buyer's desired CPM (exact micros; FD-11). Advisory.",
    )
    buyer_identity: BuyerIdentity | None = Field(
        default=None,
        description="Progressively revealed identity for tiered pricing; the "
        "effective tier is capped server-side by registry-verified trust.",
    )
    agent_url: str | None = Field(
        default=None,
        description="A2A endpoint of the requesting buyer agent, for "
        "registry trust verification. The buyer already sent this; the "
        "seller's model dropped it — now part of the contract.",
    )
    rate_card_id: str | None = Field(
        default=None,
        description="Seller-issued id of the pair's private rate card to "
        "price against (FD-9). The rate card itself never crosses the wire.",
    )
    media_type: MediaType = Field(
        default=MediaType.DIGITAL,
        description="Media discriminator (FD-6). Sellers that do not "
        "support the requested type MUST reject structurally.",
    )
    linear_tv: LinearTVParams | None = Field(
        default=None,
        description="Linear TV parameters; required when media_type == "
        "'linear_tv', must be None otherwise.",
    )
    audience_plan: dict | None = Field(
        default=None,
        description="Audience plan slot (open object; the typed model lands "
        "with the audience-plan bead). Sellers pre-flight it against their "
        "capabilities and reject unsupported parts structurally (FD-6).",
    )
    consent_context: ConsentContext | None = Field(
        default=None,
        description="Privacy consent signals riding with the request (FD-10).",
    )

    @model_validator(mode="after")
    def _linear_tv_consistency(self) -> "QuoteRequest":
        if self.media_type == MediaType.LINEAR_TV and self.linear_tv is None:
            raise ValueError("media_type 'linear_tv' requires linear_tv params")
        if self.media_type != MediaType.LINEAR_TV and self.linear_tv is not None:
            raise ValueError("linear_tv params require media_type 'linear_tv'")
        return self


class QuoteResponse(WireModel):
    """Success envelope for the quote endpoints: wraps the Quote primitive.

    The quote carries its own ``media_type``, ``linear_tv`` details,
    ``rate_card_id``, pricing, terms, availability, and ``expires_at``
    (quotes are ephemeral — the seller enforces a TTL and answers a
    ``quote_expired`` error after it elapses).
    """

    quote: Quote


__all__ = ["QuoteRequest", "QuoteResponse"]
