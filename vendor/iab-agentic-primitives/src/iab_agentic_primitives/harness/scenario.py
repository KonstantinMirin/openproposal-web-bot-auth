"""In-process scenario runner: N buyers x M sellers through the real registry.

Wires whole transactions end-to-end with NO network sockets. Buyer<->seller
calls are direct in-process invocations through the :class:`SellerChannel`
interface (the same interface an HTTP client would satisfy in production), and
the discovery/trust leg runs against the REAL sandbox AAMP registry app via
``httpx.ASGITransport`` — so agent-card registration, discovery filtering, and
the registry-verified trust ceiling are all exercised for real, not mocked.

The runner:

1. Stands up the sandbox registry (:func:`create_app` over an in-memory store)
   and an in-process :class:`RegistryClient` (ASGITransport, no socket).
2. Registers every buyer and seller Agent Card, then sets each participant's
   trust status (which caps the tier a buyer can be granted, and hides blocked
   sellers from discovery).
3. For each buyer: discovers trusted sellers, verifies the buyer's own trust
   ceiling, builds recording :class:`SellerChannel` objects (ceiling baked in),
   and runs :meth:`BuyerRole.transact`.
4. Reconciles the buyer-side and seller-side deal status (FD-8) and returns a
   structured :class:`TransactionResult` per buyer: the full protocol
   timeline, the final Deal, the state-machine transitions the seller drove,
   and any :class:`DisagreementReport`.

The registry legs need the ``client`` + ``sandbox`` extras (httpx + fastapi);
they are imported lazily so ``import ...harness`` stays dependency-free.

Acronyms: ASGI = Asynchronous Server Gateway Interface; FD = flagged decision;
AAMP = the IAB Tech Lab agent discovery and trust registry.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from ..primitives import (
    AccessTier,
    AgentType,
    Deal,
    DealStatus,
    Negotiation,
    Quote,
    TrustStatus,
    WireModel,
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
from ..state import (
    AuditEntry,
    DisagreementReport,
    ReconciliationResult,
    reconcile_deal,
)
from .roles import BuyerOutcome, BuyerRole, CampaignBrief, SellerChannel, SellerRole

# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------


@dataclass
class SellerParticipant:
    """A seller in a scenario, plus the trust status the registry should grant it."""

    seller: SellerRole
    trust_status: TrustStatus = TrustStatus.APPROVED


@dataclass
class BuyerParticipant:
    """A buyer in a scenario: its brief and its registry-granted trust status.

    ``trust_status`` sets the buyer's tier CEILING via the canonical
    :data:`iab_agentic_primitives.registry_client.TRUST_TIER_CEILING`; the
    brief's ``buyer_identity`` is what the buyer SELF-ASSERTS. The seller caps
    the self-assertion at the ceiling — that gap is the trust-tier test.
    """

    buyer: BuyerRole
    brief: CampaignBrief
    trust_status: TrustStatus = TrustStatus.APPROVED


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass
class Exchange:
    """One request/response pair on a protocol surface, for the timeline."""

    surface: str  # "catalog" | "quote" | "negotiation" | "booking"
    request: WireModel
    response: WireModel  # a success envelope OR an ErrorEnvelope

    @property
    def rejected(self) -> bool:
        return isinstance(self.response, ErrorEnvelope)


@dataclass
class TransactionResult:
    """Everything one buyer's transaction produced, for assertions and reports."""

    buyer_id: str
    seller_id: str | None
    brief: CampaignBrief
    tier_ceiling: AccessTier
    timeline: list[Exchange]
    quote: Quote | None = None
    negotiation: Negotiation | None = None
    deal: Deal | None = None
    booked: bool = False
    walked_away: bool = False
    walk_reason: str | None = None
    buyer_deal_status: DealStatus | None = None
    seller_deal_status: DealStatus | None = None
    state_transitions: list[AuditEntry] = field(default_factory=list)
    reconciliation: ReconciliationResult | None = None
    replay_deal: Deal | None = None
    idempotency_key: str | None = None

    @property
    def disagreement(self) -> DisagreementReport | None:
        return self.reconciliation.disagreement if self.reconciliation else None

    def exchanges(self, surface: str) -> list[Exchange]:
        return [ex for ex in self.timeline if ex.surface == surface]


@dataclass
class ScenarioResult:
    """The outcome of a whole scenario: one :class:`TransactionResult` per buyer."""

    transactions: list[TransactionResult]

    def for_buyer(self, buyer_id: str) -> TransactionResult:
        for tx in self.transactions:
            if tx.buyer_id == buyer_id:
                return tx
        raise KeyError(buyer_id)


# ---------------------------------------------------------------------------
# In-process channel (records the timeline)
# ---------------------------------------------------------------------------


class InProcessSellerChannel(SellerChannel):
    """Direct in-process channel to one seller, recording every exchange.

    Holds the buyer's registry-verified tier ceiling and injects it into each
    seller call, so the seller caps the buyer's self-asserted tier — trust is
    enforced server-side, never taken on the buyer's word.
    """

    def __init__(
        self,
        seller: SellerRole,
        card: AgentCard,
        ceiling: AccessTier,
        timeline: list[Exchange],
    ) -> None:
        self._seller = seller
        self._card = card
        self._ceiling = ceiling
        self._timeline = timeline

    @property
    def seller_card(self) -> AgentCard:
        return self._card

    def list_products(self, request: ProductListRequest) -> ProductListResponse:
        response = self._seller.list_products(request)
        self._timeline.append(Exchange("catalog", request, response))
        return response

    def request_quote(self, request: QuoteRequest) -> QuoteResponse | ErrorEnvelope:
        response = self._seller.price_quote(request, registry_tier_ceiling=self._ceiling)
        self._timeline.append(Exchange("quote", request, response))
        return response

    def negotiate(self, message: NegotiationMessage) -> NegotiationRoundResponse | ErrorEnvelope:
        response = self._seller.handle_negotiation(message, registry_tier_ceiling=self._ceiling)
        self._timeline.append(Exchange("negotiation", message, response))
        return response

    def book(self, request: DealBookingRequest) -> DealBookingResponse | ErrorEnvelope:
        response = self._seller.book_deal(request, registry_tier_ceiling=self._ceiling)
        self._timeline.append(Exchange("booking", request, response))
        return response


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def run_scenario(
    buyers: list[BuyerParticipant],
    sellers: list[SellerParticipant],
) -> ScenarioResult:
    """Run every buyer against every discovered, trusted seller. Async (registry I/O).

    Transactions execute independently and do not share per-buyer state, so
    two buyers hitting the same seller cannot cross-contaminate (deals and
    negotiations are keyed by seller-minted id and by idempotency key).
    """
    import httpx  # lazy: the 'client' extra

    from ..registry_client import RegistryClient  # lazy: registry client (httpx)
    from ..sandbox_registry import AgentStore, create_app  # lazy: the 'sandbox' extra

    store = AgentStore()
    app = create_app(store)
    transport = httpx.ASGITransport(app=app)

    seller_by_id: dict[str, SellerRole] = {}

    async with RegistryClient(base_url="http://sandbox", transport=transport) as client:
        # Register + set trust for every participant.
        for participant in sellers:
            card = participant.seller.agent_card()
            await client.register(card)
            await client.set_trust(card.agent_id, participant.trust_status)
            seller_by_id[card.agent_id] = participant.seller
        for participant in buyers:
            card = participant.buyer.agent_card()
            await client.register(card)
            await client.set_trust(card.agent_id, participant.trust_status)

        transactions: list[TransactionResult] = []
        for participant in buyers:
            transactions.append(await _run_one(client, participant, seller_by_id))

    return ScenarioResult(transactions=transactions)


async def _run_one(
    client: Any,
    participant: BuyerParticipant,
    seller_by_id: dict[str, SellerRole],
) -> TransactionResult:
    buyer_card = participant.buyer.agent_card()
    # Discover trusted sellers and this buyer's own tier ceiling.
    seller_cards = await client.discover(AgentType.SELLER)
    verification = await client.verify_trust(buyer_card.agent_id)
    ceiling = verification.max_access_tier

    timeline: list[Exchange] = []
    channels = [
        InProcessSellerChannel(seller_by_id[card.agent_id], card, ceiling, timeline)
        for card in seller_cards
        if card.agent_id in seller_by_id
    ]

    outcome: BuyerOutcome = participant.buyer.transact(participant.brief, channels)
    return _build_result(participant, buyer_card, ceiling, timeline, outcome, seller_by_id)


def _build_result(
    participant: BuyerParticipant,
    buyer_card: AgentCard,
    ceiling: AccessTier,
    timeline: list[Exchange],
    outcome: BuyerOutcome,
    seller_by_id: dict[str, SellerRole],
) -> TransactionResult:
    result = TransactionResult(
        buyer_id=buyer_card.agent_id,
        seller_id=outcome.seller_id,
        brief=participant.brief,
        tier_ceiling=ceiling,
        timeline=timeline,
        quote=outcome.quote,
        negotiation=outcome.negotiation,
        deal=outcome.deal,
        booked=outcome.booked,
        walked_away=outcome.walked_away,
        walk_reason=outcome.walk_reason,
        buyer_deal_status=outcome.buyer_deal_status,
        replay_deal=outcome.replay_deal,
        idempotency_key=outcome.idempotency_key,
    )
    if outcome.deal is not None and outcome.seller_id in seller_by_id:
        seller = seller_by_id[outcome.seller_id]
        result.state_transitions = seller.state_transitions(outcome.deal.deal_id)
        seller_status = seller.deal_status(outcome.deal.deal_id)
        result.seller_deal_status = seller_status
        if outcome.buyer_deal_status is not None and seller_status is not None:
            result.reconciliation = reconcile_deal(
                deal_id=outcome.deal.deal_id,
                buyer_status=outcome.buyer_deal_status,
                seller_status=seller_status,
            )
    return result


def run_scenario_sync(
    buyers: list[BuyerParticipant],
    sellers: list[SellerParticipant],
) -> ScenarioResult:
    """Synchronous convenience wrapper over :func:`run_scenario`."""
    return asyncio.run(run_scenario(buyers, sellers))


__all__ = [
    "BuyerParticipant",
    "Exchange",
    "InProcessSellerChannel",
    "ScenarioResult",
    "SellerParticipant",
    "TransactionResult",
    "run_scenario",
    "run_scenario_sync",
]
