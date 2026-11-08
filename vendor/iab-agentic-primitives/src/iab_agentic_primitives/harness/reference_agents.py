"""Deterministic, LLM-free reference buyer and seller for the harness.

These are the KNOWN-GOOD agents. They implement :class:`SellerRole` /
:class:`BuyerRole` with fixed, reproducible logic (no language model, no
clock- or random-dependent branching on the money path), so the rig (EP-11)
and the cross-repo interop tests have a fixed point to swap real agents
against: a real seller is correct if it interoperates with
:class:`ReferenceBuyer` exactly as :class:`ReferenceSeller` does, and vice
versa.

:class:`ReferenceSeller`
    A fixed catalog of :class:`~iab_agentic_primitives.primitives.Product`,
    a deterministic pricing engine that applies a tier discount but never
    prices below the product's private floor, a simple concession rule for
    negotiation that is guaranteed to TERMINATE (bounded rounds; never loops
    'active'), idempotent booking (same ``idempotency_key`` -> one deal), a
    seller-minted ``deal_id``, and it drives the canonical Order and Deal
    state machines from :mod:`iab_agentic_primitives.state`. Linear TV is
    rejected STRUCTURALLY (FD-6 ``unsupported_capability``), never silently
    mispriced.

:class:`ReferenceBuyer`
    Picks the cheapest quoted product within its negotiation band (at/below
    ``max_cpm`` books directly; above the ceiling but within
    ``negotiation_band_per_mille`` is negotiable, not discarded), can send a
    counter and accept within budget, and enforces TWO hard guardrails before
    booking: it never books above ``max_cpm`` (an above-ceiling quote books
    only if negotiation brings the agreed price down to the ceiling) and never
    exceeds ``budget`` (walks away cleanly — no exception — rather than
    overspend).

Acronyms: CPM = cost per mille; FD = flagged decision; A2A = agent-to-agent
protocol; PG = Programmatic Guaranteed.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..primitives import (
    AccessTier,
    AgentProvider,
    AgentType,
    CommercialTerms,
    Deal,
    DealStatus,
    DealType,
    MediaType,
    Money,
    Negotiation,
    NegotiationAction,
    NegotiationRound,
    NegotiationStatus,
    OrderStatus,
    Product,
    ProductRef,
    Quote,
    QuotePricing,
    QuoteStatus,
    QuoteTerms,
)
from ..protocol import (
    AgentCard,
    DealBookingRequest,
    DealBookingResponse,
    ErrorCode,
    ErrorDetail,
    ErrorEnvelope,
    NegotiationMessage,
    NegotiationRoundResponse,
    ProductListRequest,
    ProductListResponse,
    QuoteRequest,
    QuoteResponse,
    UnsupportedItem,
)
from ..state import DEAL_LIFECYCLE, ORDER_LIFECYCLE, AuditEntry
from .roles import (
    BuyerOutcome,
    BuyerRole,
    CampaignBrief,
    SellerChannel,
    SellerRole,
    cap_tier,
    cpm_cost,
    tier_from_identity,
)

#: Tier discount as integer per-mille off list (deterministic; no float math).
_TIER_DISCOUNT_PER_MILLE: dict[AccessTier, int] = {
    AccessTier.PUBLIC: 0,
    AccessTier.SEAT: 50,  # 5%
    AccessTier.AGENCY: 100,  # 10%
    AccessTier.ADVERTISER: 150,  # 15%
}

#: Media types the reference seller supports. Linear TV is deliberately NOT
#: here: it is rejected structurally (FD-6), never silently mispriced.
_SUPPORTED_MEDIA: frozenset[MediaType] = frozenset({MediaType.DIGITAL, MediaType.CTV})

#: Bounded negotiation: the seller walks after this many rounds rather than
#: looping 'active' forever (the historical infinite-negotiation failure).
MAX_SELLER_ROUNDS = 6

#: Default buyer negotiation band, in per-mille of ``max_cpm`` (integer math;
#: FD-11 no float on the money path). 1250 = quotes up to 25% above the
#: buyer's ceiling are NEGOTIABLE rather than discarded; 1000 restores the
#: strict legacy filter (above-ceiling quotes skipped outright).
DEFAULT_NEGOTIATION_BAND_PER_MILLE = 1250


def _err(
    code: ErrorCode, message: str, unsupported: list[UnsupportedItem] | None = None
) -> ErrorEnvelope:
    return ErrorEnvelope(
        detail=ErrorDetail(error=code, message=message, unsupported=unsupported or [])
    )


class _QuoteState:
    """Seller-internal record of an issued quote (never crosses the wire)."""

    __slots__ = ("quote", "floor_micros", "product_id", "effective_tier")

    def __init__(self, quote, floor_micros: int, product_id: str, effective_tier: AccessTier):
        self.quote = quote
        self.floor_micros = floor_micros
        self.product_id = product_id
        self.effective_tier = effective_tier


class _NegState:
    """Seller-internal negotiation record (guardrails stay off the wire)."""

    __slots__ = (
        "negotiation_id",
        "quote_id",
        "seller_price",
        "floor_micros",
        "rounds",
        "status",
        "last_buyer_price",
        "start_price",
    )

    def __init__(self, negotiation_id: str, quote_id: str, seller_price: int, floor_micros: int):
        self.negotiation_id = negotiation_id
        self.quote_id = quote_id
        self.seller_price = seller_price
        self.start_price = seller_price
        self.floor_micros = floor_micros
        self.rounds: list[NegotiationRound] = []
        self.status = NegotiationStatus.ACTIVE
        self.last_buyer_price = seller_price


def _default_catalog(org_id: str) -> list[tuple[Product, int]]:
    """A small fixed catalog: ``(product, floor_micros)`` pairs.

    ``base_price`` is the public list CPM; ``floor_micros`` is the seller's
    private floor (never disclosed, never priced below).
    """
    return [
        (
            Product(
                product_id="ref-prod-display",
                seller_organization_id=org_id,
                name="Run-of-Site Display",
                base_price=Money.from_decimal_str("10.00"),
                ad_formats=["banner"],
                available_impressions=50_000_000,
                commercial_terms=CommercialTerms(
                    supported_deal_types=[
                        DealType.PROGRAMMATIC_GUARANTEED,
                        DealType.PREFERRED_DEAL,
                    ]
                ),
            ),
            Money.from_decimal_str("7.00").amount_micros,
        ),
        (
            Product(
                product_id="ref-prod-video",
                seller_organization_id=org_id,
                name="Premium Video Pre-Roll",
                base_price=Money.from_decimal_str("30.00"),
                ad_formats=["video"],
                available_impressions=10_000_000,
                commercial_terms=CommercialTerms(
                    supported_deal_types=[
                        DealType.PROGRAMMATIC_GUARANTEED,
                        DealType.PRIVATE_AUCTION,
                    ]
                ),
            ),
            Money.from_decimal_str("24.00").amount_micros,
        ),
    ]


class ReferenceSeller(SellerRole):
    """Deterministic seller: fixed catalog, floor-honoring pricing, terminating negotiation."""

    def __init__(
        self,
        agent_id: str = "ref-seller",
        name: str = "Reference Seller",
        *,
        organization_id: str = "org-ref-seller",
        catalog: list[tuple[Product, int]] | None = None,
        supports_pa: bool = True,
    ) -> None:
        self._agent_id = agent_id
        self._name = name
        self._org_id = organization_id
        self._catalog: list[tuple[Product, int]] = catalog or _default_catalog(organization_id)
        self._floors: dict[str, int] = {p.product_id: floor for p, floor in self._catalog}
        self._products: dict[str, Product] = {p.product_id: p for p, _ in self._catalog}
        self._quotes: dict[str, _QuoteState] = {}
        self._negotiations: dict[str, _NegState] = {}
        self._neg_by_quote: dict[str, str] = {}
        self._neg_replay: dict[str, NegotiationRoundResponse] = {}
        self._deals: dict[str, Deal] = {}
        self._deals_by_key: dict[str, str] = {}
        self._deal_status: dict[str, DealStatus] = {}
        self._transitions: dict[str, list[AuditEntry]] = {}
        self._n = 0

    # -- ids ---------------------------------------------------------------

    def _mint(self, kind: str) -> str:
        self._n += 1
        return f"{self._agent_id}-{kind}-{self._n}"

    # -- role: discovery ---------------------------------------------------

    def agent_card(self) -> AgentCard:
        deal_types = ["PG", "PD"]
        return AgentCard(
            agent_id=self._agent_id,
            name=self._name,
            description="Deterministic reference seller for the interop harness.",
            url=f"https://{self._agent_id}.example/a2a",
            agent_type=AgentType.SELLER,
            provider=AgentProvider(name="Reference"),
            organization_id=self._org_id,
            supported_deal_types=deal_types,
        )

    # -- role: catalog -----------------------------------------------------

    def list_products(self, request: ProductListRequest) -> ProductListResponse:
        products = [p for p, _ in self._catalog]
        window = products[request.offset : request.offset + request.limit]
        return ProductListResponse(
            products=window,
            total_count=len(products),
            limit=request.limit,
            offset=request.offset,
        )

    # -- role: pricing -----------------------------------------------------

    def price_quote(
        self, request: QuoteRequest, *, registry_tier_ceiling: AccessTier
    ) -> QuoteResponse | ErrorEnvelope:
        product = self._products.get(request.product_id)
        if product is None:
            return _err(ErrorCode.NOT_FOUND, f"unknown product {request.product_id!r}")
        if request.media_type not in _SUPPORTED_MEDIA:
            return _err(
                ErrorCode.UNSUPPORTED_CAPABILITY,
                f"media_type {request.media_type.value!r} not supported",
                [UnsupportedItem(capability=request.media_type.value)],
            )
        terms = product.commercial_terms
        if (
            terms
            and terms.supported_deal_types
            and request.deal_type not in terms.supported_deal_types
        ):
            return _err(
                ErrorCode.UNSUPPORTED_CAPABILITY,
                f"deal_type {request.deal_type.value!r} not supported for this product",
                [UnsupportedItem(capability=f"deal_type:{request.deal_type.value}")],
            )
        if request.deal_type is DealType.PROGRAMMATIC_GUARANTEED and request.impressions is None:
            return _err(ErrorCode.VALIDATION, "PG quote requires impressions")

        claimed = tier_from_identity(request.buyer_identity)
        effective = cap_tier(claimed, registry_tier_ceiling)
        base_micros = product.base_price.amount_micros
        off = _TIER_DISCOUNT_PER_MILLE[effective]
        discounted = base_micros * (1000 - off) // 1000
        floor = self._floors[product.product_id]
        final_micros = max(floor, discounted)
        currency = product.base_price.currency

        quote = Quote(
            quote_id=self._mint("quote"),
            status=QuoteStatus.AVAILABLE,
            deal_type=request.deal_type,
            product=ProductRef(product_id=product.product_id, name=product.name),
            pricing=QuotePricing(
                base_cpm=Money(amount_micros=base_micros, currency=currency),
                tier_discount_pct=off / 10.0,
                final_cpm=Money(amount_micros=final_micros, currency=currency),
                rationale=f"tier {effective.value} discount, floor-honored",
            ),
            terms=QuoteTerms(
                impressions=request.impressions,
                flight_start=request.flight_start,
                flight_end=request.flight_end,
                guaranteed=request.deal_type is DealType.PROGRAMMATIC_GUARANTEED,
            ),
            buyer_tier=effective,
            seller_id=self._agent_id,
            media_type=request.media_type,
        )
        self._quotes[quote.quote_id] = _QuoteState(quote, floor, product.product_id, effective)
        return QuoteResponse(quote=quote)

    # -- role: negotiation -------------------------------------------------

    def handle_negotiation(
        self, message: NegotiationMessage, *, registry_tier_ceiling: AccessTier
    ) -> NegotiationRoundResponse | ErrorEnvelope:
        cached = self._neg_replay.get(message.idempotency_key)
        if cached is not None:
            return cached
        neg = self._resolve_negotiation(message)
        if isinstance(neg, ErrorEnvelope):
            return neg
        if neg.status is not NegotiationStatus.ACTIVE:
            return _err(
                ErrorCode.NEGOTIATION_CLOSED, f"negotiation {neg.negotiation_id} is terminal"
            )

        response = self._advance(neg, message)
        self._neg_replay[message.idempotency_key] = response
        return response

    def _resolve_negotiation(self, message: NegotiationMessage) -> _NegState | ErrorEnvelope:
        if message.negotiation_id is not None:
            neg = self._negotiations.get(message.negotiation_id)
            if neg is None:
                return _err(ErrorCode.NOT_FOUND, f"unknown negotiation {message.negotiation_id!r}")
            return neg
        if message.quote_id is None:
            return _err(ErrorCode.VALIDATION, "opening negotiation requires quote_id")
        existing = self._neg_by_quote.get(message.quote_id)
        if existing is not None:
            return self._negotiations[existing]
        qstate = self._quotes.get(message.quote_id)
        if qstate is None:
            return _err(ErrorCode.NOT_FOUND, f"unknown quote {message.quote_id!r}")
        neg_id = self._mint("neg")
        neg = _NegState(
            neg_id,
            message.quote_id,
            qstate.quote.pricing.final_cpm.amount_micros,
            qstate.floor_micros,
        )
        self._negotiations[neg_id] = neg
        self._neg_by_quote[message.quote_id] = neg_id
        return neg

    def _advance(self, neg: _NegState, message: NegotiationMessage) -> NegotiationRoundResponse:
        round_number = len(neg.rounds) + 1
        currency = "USD"
        if message.buyer_price is not None:
            currency = message.buyer_price.currency
            neg.last_buyer_price = message.buyer_price.amount_micros

        if message.action is NegotiationAction.ACCEPT:
            neg.status = NegotiationStatus.ACCEPTED
            return self._record_round(
                neg,
                round_number,
                neg.last_buyer_price,
                neg.seller_price,
                NegotiationAction.ACCEPT,
                currency,
            )
        if message.action is NegotiationAction.REJECT:
            neg.status = NegotiationStatus.REJECTED
            return self._record_round(
                neg,
                round_number,
                neg.last_buyer_price,
                neg.seller_price,
                NegotiationAction.REJECT,
                currency,
            )

        # counter / final_offer: buyer_price is required by the envelope
        bp = message.buyer_price.amount_micros
        if bp >= neg.seller_price:
            neg.status = NegotiationStatus.ACCEPTED
            return self._record_round(neg, round_number, bp, bp, NegotiationAction.ACCEPT, currency)
        if round_number >= MAX_SELLER_ROUNDS:
            if bp >= neg.floor_micros:
                # Terminal round with the buyer's standing price at/above the
                # private floor: taking the profitable offer beats walking.
                # (Without this, the midpoint concession — which approaches a
                # holding buyer's price from above but never reaches it —
                # would walk away from money above the floor.)
                neg.status = NegotiationStatus.ACCEPTED
                neg.seller_price = bp
                return self._record_round(
                    neg, round_number, bp, bp, NegotiationAction.ACCEPT, currency
                )
            neg.status = NegotiationStatus.REJECTED
            return self._record_round(
                neg, round_number, bp, neg.seller_price, NegotiationAction.REJECT, currency
            )
        if bp >= neg.floor_micros:
            new_price = max(neg.floor_micros, (neg.seller_price + bp) // 2)
            if new_price <= bp:
                neg.status = NegotiationStatus.ACCEPTED
                return self._record_round(
                    neg, round_number, bp, bp, NegotiationAction.ACCEPT, currency
                )
            neg.seller_price = new_price
            action = (
                NegotiationAction.FINAL_OFFER
                if round_number >= MAX_SELLER_ROUNDS - 1
                else NegotiationAction.COUNTER
            )
            return self._record_round(neg, round_number, bp, new_price, action, currency)
        # buyer below floor
        if neg.seller_price <= neg.floor_micros:
            neg.status = NegotiationStatus.REJECTED
            return self._record_round(
                neg, round_number, bp, neg.seller_price, NegotiationAction.REJECT, currency
            )
        neg.seller_price = neg.floor_micros
        return self._record_round(
            neg, round_number, bp, neg.floor_micros, NegotiationAction.FINAL_OFFER, currency
        )

    def _record_round(
        self,
        neg: _NegState,
        round_number: int,
        buyer_micros: int,
        seller_micros: int,
        action: NegotiationAction,
        currency: str,
    ) -> NegotiationRoundResponse:
        concession = (neg.start_price - seller_micros) / neg.start_price if neg.start_price else 0.0
        rnd = NegotiationRound(
            round_number=round_number,
            buyer_price=Money(amount_micros=buyer_micros, currency=currency),
            seller_price=Money(amount_micros=seller_micros, currency=currency),
            action=action,
            concession_pct=round(concession, 4),
            cumulative_concession_pct=round(concession, 4),
        )
        neg.rounds.append(rnd)
        if neg.status is not NegotiationStatus.ACTIVE:
            remaining = 0
        else:
            remaining = max(0, MAX_SELLER_ROUNDS - round_number)
        return NegotiationRoundResponse(
            negotiation_id=neg.negotiation_id,
            status=neg.status,
            round=rnd,
            rounds_remaining=remaining,
        )

    # -- role: booking -----------------------------------------------------

    def book_deal(
        self, request: DealBookingRequest, *, registry_tier_ceiling: AccessTier
    ) -> DealBookingResponse | ErrorEnvelope:
        existing_id = self._deals_by_key.get(request.idempotency_key)
        if existing_id is not None:
            deal = self._deals[existing_id]
            return DealBookingResponse(deal=deal, audience_plan_snapshot=request.audience_plan)
        qstate = self._quotes.get(request.quote_id)
        if qstate is None:
            return _err(ErrorCode.NOT_FOUND, f"unknown quote {request.quote_id!r}")

        claimed = tier_from_identity(request.buyer_identity)
        effective = cap_tier(claimed, registry_tier_ceiling)
        deal_id = self._mint("deal")
        transitions = self._drive_machines(deal_id)
        quote = qstate.quote
        pricing = quote.pricing
        neg_id = self._neg_by_quote.get(request.quote_id)
        if neg_id is not None:
            neg = self._negotiations[neg_id]
            if neg.status is NegotiationStatus.ACCEPTED and neg.rounds:
                # An ACCEPTED negotiation reprices the booking: the deal is
                # struck at the agreed price (the final round's seller price
                # — the seller's own record is authoritative), not the
                # pre-negotiation quote price.
                agreed = neg.rounds[-1].seller_price
                pricing = pricing.model_copy(
                    update={
                        "final_cpm": agreed,
                        "rationale": f"{pricing.rationale}; negotiated to agreed price",
                    }
                )
        deal = Deal(
            deal_id=deal_id,
            deal_type=quote.deal_type,
            status=DealStatus.BOOKED,
            quote_id=quote.quote_id,
            product=quote.product,
            pricing=pricing,
            terms=quote.terms,
            buyer_tier=effective,
            seller_id=self._agent_id,
            media_type=quote.media_type,
        )
        self._deals[deal_id] = deal
        self._deals_by_key[request.idempotency_key] = deal_id
        self._deal_status[deal_id] = DealStatus.BOOKED
        self._transitions[deal_id] = transitions
        return DealBookingResponse(deal=deal, audience_plan_snapshot=request.audience_plan)

    def _drive_machines(self, deal_id: str) -> list[AuditEntry]:
        entries: list[AuditEntry] = []
        # Deal machine: proposed -> accepted -> booked.
        deal_path = [
            (DealStatus.PROPOSED, DealStatus.ACCEPTED),
            (DealStatus.ACCEPTED, DealStatus.BOOKED),
        ]
        for frm, to in deal_path:
            entries.append(DEAL_LIFECYCLE.entry(frm, to, actor=f"agent:{self._agent_id}"))
        # Order machine: draft -> submitted -> approved -> in_progress -> booked.
        order_path = [
            (OrderStatus.DRAFT, OrderStatus.SUBMITTED),
            (OrderStatus.SUBMITTED, OrderStatus.APPROVED),
            (OrderStatus.APPROVED, OrderStatus.IN_PROGRESS),
            (OrderStatus.IN_PROGRESS, OrderStatus.BOOKED),
        ]
        for frm, to in order_path:
            entries.append(ORDER_LIFECYCLE.entry(frm, to, actor=f"agent:{self._agent_id}"))
        return entries

    # -- harness introspection --------------------------------------------

    def state_transitions(self, deal_id: str) -> list[AuditEntry]:
        return list(self._transitions.get(deal_id, []))

    def deal_status(self, deal_id: str) -> DealStatus | None:
        return self._deal_status.get(deal_id)

    def negotiation_history(self, negotiation_id: str) -> Negotiation | None:
        neg = self._negotiations.get(negotiation_id)
        if neg is None:
            return None
        return Negotiation(
            negotiation_id=neg.negotiation_id,
            quote_id=neg.quote_id,
            rounds=list(neg.rounds),
            status=neg.status,
        )


class ReferenceBuyer(BuyerRole):
    """Deterministic buyer: cheapest quote within the negotiation band, hard ceilings.

    Quote selection and the two guardrail invariants:

    - a quote at/below ``max_cpm`` books directly (negotiation only if the
      brief asks for it) — unchanged legacy behavior;
    - a quote ABOVE ``max_cpm`` but within the negotiation band
      (``final_cpm <= max_cpm * negotiation_band_per_mille / 1000``) is
      negotiable: the buyer MUST negotiate it down to its ceiling to book.
      Deterministic policy: open at ``max_cpm`` (the true ceiling), never bid
      above it, accept the seller's counter iff it is <= ``max_cpm``, and walk
      once the seller's bounded rounds are exhausted;
    - a quote beyond the band is filtered outright, exactly like the legacy
      above-ceiling filter.

    The buyer NEVER books above ``max_cpm`` and NEVER exceeds ``budget`` (both
    checked at the EFFECTIVE price — the negotiated price when a negotiation
    was accepted, the quoted price otherwise).
    """

    #: Buyer walks after this many rounds; the seller's cap (6) fires first.
    MAX_BUYER_ROUNDS = 8

    def __init__(
        self,
        agent_id: str = "ref-buyer",
        name: str = "Reference Buyer",
        *,
        organization_id: str = "org-ref-buyer",
        negotiation_band_per_mille: int = DEFAULT_NEGOTIATION_BAND_PER_MILLE,
    ) -> None:
        if negotiation_band_per_mille < 1000:
            raise ValueError(
                "negotiation_band_per_mille must be >= 1000 (1000 = strict "
                f"max_cpm filter); got {negotiation_band_per_mille}"
            )
        self._agent_id = agent_id
        self._name = name
        self._org_id = organization_id
        self._band_per_mille = negotiation_band_per_mille

    def agent_card(self) -> AgentCard:
        return AgentCard(
            agent_id=self._agent_id,
            name=self._name,
            description="Deterministic reference buyer for the interop harness.",
            url=f"https://{self._agent_id}.example/a2a",
            agent_type=AgentType.BUYER,
            provider=AgentProvider(name="Reference"),
            organization_id=self._org_id,
            supported_deal_types=["PG", "PD"],
        )

    # -- driver ------------------------------------------------------------

    def transact(self, brief: CampaignBrief, sellers: Sequence[SellerChannel]) -> BuyerOutcome:
        best = self._discover_cheapest(brief, sellers)
        if best is None:
            return BuyerOutcome(walked_away=True, walk_reason="no affordable quote under max_cpm")
        channel, quote = best
        seller_id = channel.seller_card.agent_id
        outcome = BuyerOutcome(seller_id=seller_id, quote=quote)

        # An above-ceiling (in-band) quote is only bookable if negotiation
        # brings it down to the ceiling, so negotiation is REQUIRED for it —
        # the brief's ``negotiate`` flag only governs voluntary negotiation
        # on quotes already at/below the ceiling.
        must_negotiate = quote.pricing.final_cpm.amount_micros > brief.max_cpm.amount_micros
        effective_cpm = quote.pricing.final_cpm
        if brief.negotiate or must_negotiate:
            negotiation, agreed = self._negotiate(
                brief, channel, quote, hold_at_ceiling=must_negotiate
            )
            outcome.negotiation = negotiation
            if not agreed:
                outcome.walked_away = True
                outcome.walk_reason = "negotiation did not reach agreement"
                return outcome
            if negotiation.rounds:
                # The agreed price is the final round's seller price (the
                # seller's numbering and record are authoritative).
                effective_cpm = negotiation.rounds[-1].seller_price

        # Ceiling guarantee (guardrail invariant): NEVER book above max_cpm.
        if effective_cpm.amount_micros > brief.max_cpm.amount_micros:
            outcome.walked_away = True
            outcome.walk_reason = (
                f"cpm ceiling exceeded: effective {effective_cpm.amount_micros} "
                f"> max_cpm {brief.max_cpm.amount_micros}"
            )
            return outcome

        # Hard budget ceiling at the EFFECTIVE (post-negotiation) price: the
        # buyer walks rather than overspend.
        cost = cpm_cost(effective_cpm, brief.impressions)
        if cost.amount_micros > brief.budget.amount_micros:
            outcome.walked_away = True
            outcome.walk_reason = f"budget ceiling exceeded: cost {cost.amount_micros} > budget {brief.budget.amount_micros}"
            return outcome

        return self._book(brief, channel, quote, outcome)

    def _discover_cheapest(
        self, brief: CampaignBrief, sellers: Sequence[SellerChannel]
    ) -> tuple[SellerChannel, object] | None:
        candidates: list[tuple[int, SellerChannel, object]] = []
        for channel in sellers:
            catalog = channel.list_products(ProductListRequest())
            product = self._pick_product(brief, catalog.products)
            if product is None:
                continue
            request = self._quote_request(brief, channel, product.product_id)
            response = channel.request_quote(request)
            if isinstance(response, ErrorEnvelope):
                continue  # structural rejection (e.g. linear_tv unsupported) — try the next seller
            quote = response.quote
            final = quote.pricing.final_cpm
            if final is None:
                continue
            # Within the negotiation band: at/below max_cpm books directly;
            # above max_cpm but in-band is negotiable; beyond the band is
            # filtered outright. Integer per-mille math (FD-11, no float).
            band_limit = brief.max_cpm.amount_micros * self._band_per_mille // 1000
            if final.amount_micros <= band_limit:
                candidates.append((final.amount_micros, channel, quote))
        if not candidates:
            return None
        # Cheapest wins; any in-band above-ceiling quote is by definition
        # more expensive than every at/below-ceiling one, so at/below-ceiling
        # quotes are always preferred when available.
        candidates.sort(key=lambda row: row[0])
        _, channel, quote = candidates[0]
        return channel, quote

    def _pick_product(self, brief: CampaignBrief, products) -> Product | None:
        suitable: list[Product] = []
        for product in products:
            if brief.ad_format and brief.ad_format not in product.ad_formats:
                continue
            terms = product.commercial_terms
            if (
                terms
                and terms.supported_deal_types
                and brief.deal_type not in terms.supported_deal_types
            ):
                continue
            if product.base_price is None:
                continue
            suitable.append(product)
        if not suitable:
            return None
        return min(suitable, key=lambda p: p.base_price.amount_micros)

    def _quote_request(
        self, brief: CampaignBrief, channel: SellerChannel, product_id: str
    ) -> QuoteRequest:
        return QuoteRequest(
            idempotency_key=f"quote-{self._agent_id}-{channel.seller_card.agent_id}-{product_id}",
            product_id=product_id,
            deal_type=brief.deal_type,
            impressions=brief.impressions,
            flight_start=brief.flight_start,
            flight_end=brief.flight_end,
            buyer_identity=brief.buyer_identity,
            agent_url=self.agent_card().url,
            media_type=brief.media_type,
            linear_tv=brief.linear_tv if brief.media_type is MediaType.LINEAR_TV else None,
            audience_plan=brief.audience_plan,
        )

    def _negotiate(
        self,
        brief: CampaignBrief,
        channel: SellerChannel,
        quote,
        *,
        hold_at_ceiling: bool = False,
    ) -> tuple[Negotiation, bool]:
        currency = quote.pricing.final_cpm.currency
        ceiling = brief.max_cpm.amount_micros
        if hold_at_ceiling:
            # Above-ceiling quote: open at the TRUE ceiling (clamping any
            # configured counter down to it) — the buyer never bids above
            # max_cpm, so the ceiling guarantee holds by construction.
            opening = (
                min(brief.counter_cpm.amount_micros, ceiling)
                if brief.counter_cpm is not None
                else ceiling
            )
        else:
            opening = (
                brief.counter_cpm.amount_micros
                if brief.counter_cpm is not None
                else quote.pricing.final_cpm.amount_micros * 85 // 100
            )
        bp = opening
        rounds: list[NegotiationRound] = []
        negotiation_id: str | None = None
        status = NegotiationStatus.ACTIVE
        message = NegotiationMessage(
            idempotency_key=f"neg-{self._agent_id}-{quote.quote_id}-1",
            action=NegotiationAction.COUNTER,
            quote_id=quote.quote_id,
            buyer_price=Money(amount_micros=bp, currency=currency),
            buyer_identity=brief.buyer_identity,
        )
        for i in range(2, self.MAX_BUYER_ROUNDS + 2):
            response = channel.negotiate(message)
            if isinstance(response, ErrorEnvelope):
                status = NegotiationStatus.REJECTED
                break
            negotiation_id = response.negotiation_id
            rounds.append(response.round)
            status = response.status
            if status is NegotiationStatus.ACCEPTED:
                break
            if status in (NegotiationStatus.REJECTED, NegotiationStatus.EXPIRED):
                break
            seller_price = response.round.seller_price.amount_micros
            if seller_price <= ceiling:
                message = NegotiationMessage(
                    idempotency_key=f"neg-{self._agent_id}-{quote.quote_id}-{i}",
                    action=NegotiationAction.ACCEPT,
                    negotiation_id=negotiation_id,
                    buyer_identity=brief.buyer_identity,
                )
                continue
            new_bp = min(ceiling, (bp + seller_price) // 2)
            if new_bp <= bp:
                if hold_at_ceiling:
                    # The buyer cannot bid higher (it is at its ceiling):
                    # HOLD the standing price and let the seller spend its
                    # remaining bounded rounds conceding toward it. The
                    # seller's round cap guarantees termination; the buyer's
                    # own round cap is the backstop.
                    message = NegotiationMessage(
                        idempotency_key=f"neg-{self._agent_id}-{quote.quote_id}-{i}",
                        action=NegotiationAction.COUNTER,
                        negotiation_id=negotiation_id,
                        buyer_price=Money(amount_micros=bp, currency=currency),
                        buyer_identity=brief.buyer_identity,
                    )
                    continue
                message = NegotiationMessage(
                    idempotency_key=f"neg-{self._agent_id}-{quote.quote_id}-{i}",
                    action=NegotiationAction.REJECT,
                    negotiation_id=negotiation_id,
                    buyer_identity=brief.buyer_identity,
                )
                channel.negotiate(message)
                status = NegotiationStatus.REJECTED
                break
            bp = new_bp
            message = NegotiationMessage(
                idempotency_key=f"neg-{self._agent_id}-{quote.quote_id}-{i}",
                action=NegotiationAction.COUNTER,
                negotiation_id=negotiation_id,
                buyer_price=Money(amount_micros=bp, currency=currency),
                buyer_identity=brief.buyer_identity,
            )
        if status is NegotiationStatus.ACTIVE and negotiation_id is not None:
            # Buyer rounds exhausted while the seller is still countering:
            # close the negotiation honestly (a recorded walk-away round)
            # instead of abandoning it 'active'.
            channel.negotiate(
                NegotiationMessage(
                    idempotency_key=f"neg-{self._agent_id}-{quote.quote_id}-close",
                    action=NegotiationAction.REJECT,
                    negotiation_id=negotiation_id,
                    buyer_identity=brief.buyer_identity,
                )
            )
            status = NegotiationStatus.REJECTED
        negotiation = Negotiation(
            negotiation_id=negotiation_id or "unopened",
            quote_id=quote.quote_id,
            rounds=rounds,
            status=status,
        )
        return negotiation, status is NegotiationStatus.ACCEPTED

    def _book(
        self, brief: CampaignBrief, channel: SellerChannel, quote, outcome: BuyerOutcome
    ) -> BuyerOutcome:
        key = f"book-{self._agent_id}-{quote.quote_id}"
        request = DealBookingRequest(
            idempotency_key=key,
            quote_id=quote.quote_id,
            buyer_identity=brief.buyer_identity,
            audience_plan=brief.audience_plan,
        )
        response = channel.book(request)
        if isinstance(response, ErrorEnvelope):
            outcome.walked_away = True
            outcome.walk_reason = f"booking rejected: {response.detail.error.value}"
            return outcome
        outcome.deal = response.deal
        outcome.booked = True
        outcome.buyer_deal_status = DealStatus.BOOKED
        outcome.idempotency_key = key
        if brief.idempotent_double_book:
            replay = channel.book(request)
            if not isinstance(replay, ErrorEnvelope):
                outcome.replay_deal = replay.deal
        return outcome


__all__ = [
    "DEFAULT_NEGOTIATION_BAND_PER_MILLE",
    "MAX_SELLER_ROUNDS",
    "ReferenceBuyer",
    "ReferenceSeller",
]
