"""Role interfaces the two-agent harness plugs real (or reference) agents into.

The harness proves interoperability by running BOTH sides of a transaction
against the ONE shared contract (:mod:`iab_agentic_primitives.protocol` +
:mod:`iab_agentic_primitives.primitives` + :mod:`iab_agentic_primitives.state`
+ the sandbox AAMP — Agentic Advertising Marketplace Protocol — registry),
instead of each repo mocking its counterparty. The mocks are exactly why the
historical interop breaks (negotiation 422-every-round, dropped ``agent_url``
headers, 405 catalog, makegood 404s, incompatible agent cards) stayed
invisible: a mock never disagrees with you.

Two abstract roles capture the buyer/seller split. Every method takes and
returns the canonical protocol envelopes and primitives — there is NO free
text on any money path (offers, quotes, deals, budgets are all
:class:`~iab_agentic_primitives.primitives.Money`):

- :class:`SellerRole` is a passive service: serve the catalog, price a quote
  (honoring a floor and the registry-capped access tier), handle a
  negotiation message, and book a deal (minting the ``deal_id`` and driving
  the Order/Deal state machines). Money-path methods return either the
  success envelope OR the ONE structured
  :class:`~iab_agentic_primitives.protocol.errors.ErrorEnvelope` — never a
  bare exception, never a silently mispriced result.
- :class:`BuyerRole` is the active driver: given a :class:`CampaignBrief` and
  the set of discovered+trusted seller channels, it requests quotes,
  optionally negotiates, enforces its hard budget ceiling, and books —
  returning a :class:`BuyerOutcome`.

A :class:`SellerChannel` is how a buyer reaches ONE seller over the protocol.
In-process the channel wraps a :class:`SellerRole` directly (no socket); in
production the same interface is an HTTP client. Crucially the channel carries
the buyer's registry-verified access-tier CEILING and injects it into every
seller call, so the seller caps the buyer's self-asserted tier server-side —
trust is never self-asserted (see the Agent primitive and
:data:`iab_agentic_primitives.registry_client.TRUST_TIER_CEILING`).

Acronyms: A2A = agent-to-agent protocol; AAMP = the IAB (Interactive
Advertising Bureau) Tech Lab agent discovery and trust registry; CPM = cost
per mille (per thousand impressions); FD = flagged decision.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from ..primitives import (
    AccessTier,
    BuyerIdentity,
    Deal,
    DealStatus,
    DealType,
    LinearTVParams,
    MediaType,
    Money,
    Negotiation,
    Quote,
)
from ..protocol import (
    AgentCard,
    DealBookingRequest,
    DealBookingResponse,
    ErrorEnvelope,
    NegotiationMessage,
    NegotiationRoundResponse,
    ProductListRequest,
    ProductListResponse,
    QuoteRequest,
    QuoteResponse,
)
from ..state import AuditEntry

# ---------------------------------------------------------------------------
# Access-tier helpers (trust caps the effective tier server-side — FD, not
# self-asserted). The buyer reveals an identity; the seller derives the
# CLAIMED tier from it and caps it at the registry-verified CEILING.
# ---------------------------------------------------------------------------

#: Total order over access tiers, low to high privilege.
TIER_ORDER: dict[AccessTier, int] = {
    AccessTier.PUBLIC: 0,
    AccessTier.SEAT: 1,
    AccessTier.AGENCY: 2,
    AccessTier.ADVERTISER: 3,
}


def tier_from_identity(identity: BuyerIdentity | None) -> AccessTier:
    """The access tier a revealed :class:`BuyerIdentity` CLAIMS (uncapped).

    Progressive revelation: the most specific id present wins. An unrevealed
    (``None``) identity claims only :attr:`AccessTier.PUBLIC`.
    """
    if identity is None:
        return AccessTier.PUBLIC
    if identity.advertiser_id:
        return AccessTier.ADVERTISER
    if identity.agency_id:
        return AccessTier.AGENCY
    if identity.seat_id:
        return AccessTier.SEAT
    return AccessTier.PUBLIC


def cap_tier(claimed: AccessTier, ceiling: AccessTier) -> AccessTier:
    """Cap a claimed tier at the registry-verified ceiling (never above it)."""
    return claimed if TIER_ORDER[claimed] <= TIER_ORDER[ceiling] else ceiling


def cpm_cost(cpm: Money, impressions: int) -> Money:
    """Total cost of ``impressions`` at ``cpm`` (CPM = price per 1000), in exact micros.

    Integer micros math only (FD-11): no float on the money path, so the
    result is deterministic and reproducible across runs and languages.
    """
    return Money(
        amount_micros=cpm.amount_micros * impressions // 1000,
        currency=cpm.currency,
    )


# ---------------------------------------------------------------------------
# Campaign brief — the buyer's input (harness type, not a wire primitive)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignBrief:
    """What a buyer is trying to buy, plus its hard guardrails.

    Not a wire primitive: it is the buyer agent's internal objective. Every
    money field is :class:`~iab_agentic_primitives.primitives.Money` so the
    ceiling checks are exact-micros comparisons, never float.
    """

    campaign_name: str
    deal_type: DealType
    impressions: int
    #: Hard per-mille ceiling: the buyer never books above this CPM.
    max_cpm: Money
    #: Hard total-spend ceiling: the buyer walks rather than exceed this.
    budget: Money
    ad_format: str | None = None
    media_type: MediaType = MediaType.DIGITAL
    #: Linear-TV parameters; REQUIRED when ``media_type`` is ``linear_tv`` (the
    #: envelope validator enforces this), must be ``None`` otherwise.
    linear_tv: LinearTVParams | None = None
    flight_start: date | None = None
    flight_end: date | None = None
    #: Identity the buyer self-asserts; the seller caps the derived tier at
    #: the registry ceiling. ``None`` means the buyer stays public.
    buyer_identity: BuyerIdentity | None = None
    #: Whether the buyer attempts a counter before accepting/booking.
    negotiate: bool = False
    #: The buyer's opening counter CPM when ``negotiate`` is set. ``None``
    #: derives one below the quoted price.
    counter_cpm: Money | None = None
    #: Audience plan frozen with the booking (open object; typed model lands
    #: with the audience-plan bead). Rides through to prove it is not dropped.
    audience_plan: dict | None = None
    #: When set, the buyer replays the booking with the SAME idempotency key
    #: to exercise idempotent double-booking (same key -> one deal).
    idempotent_double_book: bool = False


# ---------------------------------------------------------------------------
# Buyer outcome — the buyer's structured result
# ---------------------------------------------------------------------------


@dataclass
class BuyerOutcome:
    """Structured result of one :meth:`BuyerRole.transact` run.

    Captures the buyer's own view; the scenario runner augments it with the
    seller-side status and the reconciliation verdict.
    """

    seller_id: str | None = None
    quote: Quote | None = None
    negotiation: Negotiation | None = None
    deal: Deal | None = None
    booked: bool = False
    walked_away: bool = False
    walk_reason: str | None = None
    #: The buyer's independently-tracked deal status (reconciled vs seller).
    buyer_deal_status: DealStatus | None = None
    #: The idempotency key the booking used (so a replay can reuse it).
    idempotency_key: str | None = None
    #: Result of replaying the booking with the same key (idempotent probe).
    replay_deal: Deal | None = None


# ---------------------------------------------------------------------------
# SellerChannel — how a buyer reaches ONE seller over the protocol
# ---------------------------------------------------------------------------


class SellerChannel(ABC):
    """A buyer's protocol connection to one discovered, trusted seller.

    In-process this wraps a :class:`SellerRole` (see the scenario runner); in
    production it is an HTTP client to the seller's A2A endpoint. Either way
    the buyer speaks only the canonical envelopes. The channel owns the
    buyer's registry-capped tier ceiling and injects it into seller calls, so
    the buyer can never dial its own privilege up past what the registry
    granted.
    """

    @property
    @abstractmethod
    def seller_card(self) -> AgentCard:
        """The discovered seller's registry card (its A2A endpoint, deal types)."""

    @abstractmethod
    def list_products(self, request: ProductListRequest) -> ProductListResponse:
        """``GET /products`` — the seller's catalog (read-only, no free-text search)."""

    @abstractmethod
    def request_quote(self, request: QuoteRequest) -> QuoteResponse | ErrorEnvelope:
        """``POST /api/v1/quotes`` — price a quote or reject structurally (FD-6)."""

    @abstractmethod
    def negotiate(self, message: NegotiationMessage) -> NegotiationRoundResponse | ErrorEnvelope:
        """``POST /api/v1/negotiations/messages`` — one negotiation round each way."""

    @abstractmethod
    def book(self, request: DealBookingRequest) -> DealBookingResponse | ErrorEnvelope:
        """``POST /api/v1/deals`` — commit the quote into a seller-minted Deal."""


# ---------------------------------------------------------------------------
# The two roles
# ---------------------------------------------------------------------------


class SellerRole(ABC):
    """A seller agent: serve inventory, price, negotiate, and book — over the contract.

    Every money-path method returns EITHER the canonical success envelope OR
    the ONE :class:`~iab_agentic_primitives.protocol.errors.ErrorEnvelope`.
    The ``registry_tier_ceiling`` argument is the buyer's registry-verified
    access-tier cap; the seller derives the buyer's claimed tier from the
    request identity and caps it at this ceiling (never trusting the buyer's
    self-assertion).
    """

    @abstractmethod
    def agent_card(self) -> AgentCard:
        """The seller's Agent Card, as registered for discovery."""

    @abstractmethod
    def list_products(self, request: ProductListRequest) -> ProductListResponse:
        """Serve the catalog for ``GET /products`` (client-side filtering; no 405 search)."""

    @abstractmethod
    def price_quote(
        self, request: QuoteRequest, *, registry_tier_ceiling: AccessTier
    ) -> QuoteResponse | ErrorEnvelope:
        """Price a quote honoring the product floor and the (capped) tier discount."""

    @abstractmethod
    def handle_negotiation(
        self, message: NegotiationMessage, *, registry_tier_ceiling: AccessTier
    ) -> NegotiationRoundResponse | ErrorEnvelope:
        """Advance a negotiation by one round; MUST terminate (never loop 'active')."""

    @abstractmethod
    def book_deal(
        self, request: DealBookingRequest, *, registry_tier_ceiling: AccessTier
    ) -> DealBookingResponse | ErrorEnvelope:
        """Book a Deal from a quote: mint ``deal_id``, drive the Order/Deal machines."""

    # -- harness introspection (not a wire surface) -----------------------

    def state_transitions(self, deal_id: str) -> list[AuditEntry]:
        """Order/Deal lifecycle transitions the seller drove for ``deal_id``.

        A harness hook, not a protocol endpoint: the scenario runner reads it
        to record the state-machine timeline. Real agents override it to
        return the relevant slice of their audit log; the default is empty.
        """
        return []

    def deal_status(self, deal_id: str) -> DealStatus | None:
        """The seller's independently-tracked status for ``deal_id`` (for reconciliation)."""
        return None


class BuyerRole(ABC):
    """A buyer agent: given a brief and discovered sellers, transact over the contract.

    The scenario runner performs the registry legs (register cards, discover
    sellers, verify the buyer's trust) and hands the buyer ready
    :class:`SellerChannel` objects with the tier ceiling already baked in.
    The buyer's job is the agent business logic: pick inventory, quote,
    optionally negotiate, enforce its hard budget ceiling, and book.
    """

    @abstractmethod
    def agent_card(self) -> AgentCard:
        """The buyer's Agent Card, as registered for discovery/trust."""

    @abstractmethod
    def transact(self, brief: CampaignBrief, sellers: Sequence[SellerChannel]) -> BuyerOutcome:
        """Run the brief against the discovered sellers; return the outcome."""


__all__ = [
    "TIER_ORDER",
    "BuyerOutcome",
    "BuyerRole",
    "CampaignBrief",
    "SellerChannel",
    "SellerRole",
    "cap_tier",
    "cpm_cost",
    "tier_from_identity",
]
