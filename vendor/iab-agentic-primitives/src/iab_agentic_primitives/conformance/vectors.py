"""Golden-vector definitions and the fixture generator (EP-6.1).

Every wire primitive, protocol envelope, and event gets 2-4 realistic
golden vectors, built HERE as validated model instances and written to
``spec/fixtures/<area>/<Target>.golden.json`` by :func:`write_fixtures`
(``python -m iab_agentic_primitives.conformance --regenerate``). The
checked-in fixture files are the normative artifacts — non-Python
implementations replay them without importing this package — and a drift
test fails if they ever diverge from these builders.

Vector modes (see :mod:`iab_agentic_primitives.conformance.runner`):

- ``valid`` — must parse, and re-serializing must byte-match the vector's
  ``data`` under canonical JSON (JavaScript Object Notation).
- ``must_ignore`` — carries unknown fields and ``x_``-prefixed extension
  fields (flagged decision FD-13): must parse, and re-serializing must
  byte-match ``expected`` (the data minus the extras — proof the extras
  were ignored, not stored or echoed).
- ``invalid`` — must FAIL validation with an error containing
  ``expected_error``. This is how FD-11 (float-typed money is rejected)
  is asserted as an executable check.

Determinism: every timestamp and identifier is pinned — regeneration is
byte-stable, so ``--regenerate`` never produces noise diffs.

Acronyms: FD = flagged decision; PG/PD/PA = Programmatic Guaranteed /
Preferred Deal / Private Auction; GRP = gross rating point; CPM/CPP =
cost per mille / cost per point; GPP = Global Privacy Platform;
TCF = Transparency & Consent Framework.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..events import Event, EventType
from ..primitives import (
    AccessTier,
    Account,
    ActorKind,
    Agent,
    AgentProvider,
    AgentSkill,
    Assignment,
    BuyerIdentity,
    CancellationTerms,
    ChangeRequest,
    ChangeRequestStatus,
    ChangeSeverity,
    ChangeType,
    CommercialTerms,
    ConsentContext,
    Creative,
    CreativeApproval,
    CreativeAsset,
    CreativeManifest,
    Deal,
    DealStatus,
    DealType,
    DecisionActor,
    DecisionInputRef,
    DecisionRationale,
    DecisionRecord,
    DecisionType,
    DeliveryGoal,
    DeliveryType,
    DiligenceStatus,
    FieldDiff,
    Line,
    LinearTVParams,
    LinearTVQuoteDetails,
    LineStatus,
    MakegoodDetails,
    MakegoodStatus,
    MediaKit,
    MediaType,
    Money,
    Negotiation,
    NegotiationAction,
    NegotiationRound,
    NegotiationStatus,
    OpenRTBParams,
    Order,
    OrderStatus,
    Organization,
    OrganizationRole,
    Package,
    PackageLayer,
    PackagePlacement,
    PackageStatus,
    PricingModel,
    PricingTerms,
    PricingType,
    Product,
    ProductRef,
    Proposal,
    ProposalLine,
    ProposalStatus,
    Quote,
    QuoteAvailability,
    QuotePricing,
    QuoteStatus,
    QuoteTerms,
    RateCard,
    RateCardEntry,
    RateCardStatus,
    ReviewStatus,
    RotationMode,
    SellersJsonEntry,
    SellerType,
    Session,
    SessionMessage,
    SessionStatus,
    SupplyChain,
    SupplyChainNode,
    TrustStatus,
)
from ..protocol import (
    A2AMessage,
    A2APart,
    A2AResult,
    AgentDiscoveryRequest,
    AgentTrustVerification,
    Avails,
    AvailsCollection,
    AvailsRequest,
    AvailsResponse,
    AvailsStatus,
    AvailsStatusReason,
    AvailsStatusValue,
    ProductAvailsSearch,
    ProductTargeting,
    TargetingDimension,
    TargetingUnit,
    ChangeRequestCreate,
    ChangeRequestResponse,
    DealBookingRequest,
    DealBookingResponse,
    ErrorCode,
    ErrorDetail,
    ErrorEnvelope,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    MessageSendParams,
    NegotiationMessage,
    NegotiationRoundResponse,
    ProductListRequest,
    ProductListResponse,
    QuoteRequest,
    QuoteResponse,
    UnsupportedItem,
)

_GENERATED_NOTE = (
    "GENERATED golden vectors -- regenerate with "
    "`uv run python -m iab_agentic_primitives.conformance --regenerate`; "
    "a drift test fails if this file diverges from "
    "iab_agentic_primitives.conformance.vectors."
)


def _doc(area: str, target: str, vectors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "$comment": _GENERATED_NOTE,
        "area": area,
        "target": target,
        "vectors": vectors,
    }


# Pinned timestamps -- regeneration must be byte-stable.
T0 = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 7, 2, 9, 30, 0, tzinfo=UTC)
T_EXPIRES = datetime(2026, 7, 15, 0, 0, 0, tzinfo=UTC)

#: Largest integer exactly representable as an IEEE 754 double (2**53 - 1).
#: The interop boundary for JSON consumers that parse numbers as doubles.
MAX_SAFE_MICROS = 9_007_199_254_740_991

#: FD-13 extras: one reserved x_ extension field and one unknown field a
#: newer counterparty might send. Conformant parsers must ignore both.
_EXTRAS: dict[str, Any] = {
    "x_vendor_ext": {"partner": "example-dsp", "trace": "abc-123"},
    "field_from_a_newer_spec_version": "must-be-ignored",
}


def _dump(instance: BaseModel) -> dict[str, Any]:
    """Canonical wire form of a model instance (camelCase where aliased)."""
    return instance.model_dump(mode="json", by_alias=True)


def _valid(name: str, description: str, instance: BaseModel) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "mode": "valid",
        "data": _dump(instance),
    }


def _must_ignore(name: str, description: str, instance: BaseModel) -> dict[str, Any]:
    base = _dump(instance)
    return {
        "name": name,
        "description": description,
        "mode": "must_ignore",
        "data": {**base, **_EXTRAS},
        "expected": base,
    }


def _invalid(
    name: str, description: str, data: dict[str, Any], expected_error: str
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "mode": "invalid",
        "data": data,
        "expected_error": expected_error,
    }


# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------


def _consent() -> ConsentContext:
    return ConsentContext(
        applicable_regimes=["GDPR", "CCPA"],
        gpp_string="DBABMA~CPXxRfAPXxRfAAfKABENB",
        gpp_section_ids=[2, 6],
        tcf_string="CPXxRfAPXxRfAAfKABENB",
        gdpr_applies=True,
        us_privacy="1YNN",
        diligence_status=DiligenceStatus.PASSED,
        verified_at=T0,
    )


def _supply_chain() -> SupplyChain:
    return SupplyChain(
        complete=1,
        ver="1.0",
        nodes=[
            SupplyChainNode(
                asi="exchange.example.com",
                sid="seller-001",
                hp=1,
                rid="req-abc",
                name="PremiumPub",
                domain="premiumpub.example.com",
            )
        ],
    )


def _product_ref() -> ProductRef:
    return ProductRef(
        product_id="prod-001",
        name="Premium Homepage Takeover",
        inventory_type="display",
    )


def _linear_tv_details() -> LinearTVQuoteDetails:
    return LinearTVQuoteDetails(
        target_demo="A18-49",
        estimated_grps=120.0,
        estimated_rating=2.4,
        cpp=Money.from_decimal_str("450.00"),
        dayparts=["primetime"],
        networks=["NBC", "ESPN"],
        spots_per_week=12,
        total_spots=48,
        spot_length=30,
        measurement_currency="nielsen",
        audience_estimate={"demo": "A18-49", "universe": 128_000_000},
        cancellation_terms=CancellationTerms(
            notice_days=14, cancellable_pct=0.5, deadline=date(2026, 9, 15)
        ),
        makegood_policy="standard",
    )


def _quote_pg_digital() -> Quote:
    return Quote(
        quote_id="q-pg-001",
        deal_type=DealType.PROGRAMMATIC_GUARANTEED,
        product=_product_ref(),
        pricing=QuotePricing(
            base_cpm=Money.from_decimal_str("25.00"),
            tier_discount_pct=10.0,
            final_cpm=Money.from_decimal_str("22.50"),
            rationale="advertiser tier discount",
        ),
        terms=QuoteTerms(
            impressions=1_000_000,
            flight_start=date(2026, 8, 1),
            flight_end=date(2026, 8, 31),
            guaranteed=True,
        ),
        availability=QuoteAvailability(inventory_available=True, estimated_fill_rate=0.95),
        buyer_tier=AccessTier.ADVERTISER,
        rate_card_id="rc-001",
        expires_at=T_EXPIRES,
        seller_id="agent-seller-1",
        created_at=T0,
        consent_context=_consent(),
    )


def _quote_linear_tv() -> Quote:
    return Quote(
        quote_id="q-ltv-002",
        deal_type=DealType.PROGRAMMATIC_GUARANTEED,
        product=ProductRef(product_id="prod-ltv-9", name="Primetime National Spots"),
        pricing=QuotePricing(
            pricing_model=PricingModel.CPP,
            base_cpp=Money.from_decimal_str("475.00"),
            final_cpp=Money.from_decimal_str("450.00"),
            rationale="upfront volume commitment",
        ),
        terms=QuoteTerms(
            flight_start=date(2026, 9, 1),
            flight_end=date(2026, 9, 28),
            guaranteed=True,
            grps=120,
            guaranteed_grps=110,
            target_demo="A18-49",
        ),
        buyer_tier=AccessTier.AGENCY,
        expires_at=T_EXPIRES,
        seller_id="agent-seller-1",
        created_at=T0,
        media_type=MediaType.LINEAR_TV,
        linear_tv=_linear_tv_details(),
    )


def _deal_pg_booked() -> Deal:
    return Deal(
        deal_id="deal-001",
        deal_type=DealType.PROGRAMMATIC_GUARANTEED,
        status=DealStatus.BOOKED,
        quote_id="q-pg-001",
        rate_card_id="rc-001",
        product=_product_ref(),
        pricing=QuotePricing(
            base_cpm=Money.from_decimal_str("25.00"),
            final_cpm=Money.from_decimal_str("22.50"),
        ),
        terms=QuoteTerms(
            impressions=1_000_000,
            flight_start=date(2026, 8, 1),
            flight_end=date(2026, 8, 31),
            guaranteed=True,
        ),
        buyer_tier=AccessTier.ADVERTISER,
        seller_id="agent-seller-1",
        activation_instructions={"dsp": "send deal id via OpenRTB"},
        openrtb_params=OpenRTBParams(
            id="deal-001",
            bidfloor=Money.from_decimal_str("22.50"),
            wseat=["seat-42"],
            wadomain=["example.com"],
        ),
        created_at=T0,
        consent_context=_consent(),
        supply_chain=_supply_chain(),
    )


def _makegood_details() -> MakegoodDetails:
    return MakegoodDetails(
        shortfall_grps=8.5,
        original_daypart="primetime",
        target_demo="A18-49",
        owed_impressions=250_000,
        preferred_dayparts=["primetime", "late_night"],
        replacement_flight_start=date(2026, 10, 1),
        replacement_flight_end=date(2026, 10, 14),
        status=MakegoodStatus.PROPOSED,
        notes="Week 2 audience under-delivery",
    )


def _change_request_makegood() -> ChangeRequest:
    return ChangeRequest(
        change_request_id="cr-001",
        deal_id="deal-ltv-002",
        change_type=ChangeType.MAKEGOOD,
        severity=ChangeSeverity.MATERIAL,
        requested_by="agent:agent-buyer-1",
        requested_at=T1,
        reason="GRP shortfall in week 2",
        makegood=_makegood_details(),
    )


def _idem(n: int) -> str:
    """A pinned, obviously-fake UUID-shaped idempotency key."""
    return f"00000000-0000-4000-8000-{n:012d}"


# ---------------------------------------------------------------------------
# Primitives (22 targets)
# ---------------------------------------------------------------------------


def primitive_fixture_docs() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {}

    docs["Organization"] = _doc(
        "primitives",
        "Organization",
        [
            _valid(
                "buyer_org",
                "Registered buying organization",
                Organization(
                    organization_id="org-buyer-1",
                    name="Acme Media Buying",
                    role=OrganizationRole.BUYER,
                ),
            ),
            _valid(
                "seller_org_with_ext",
                "Selling organization with contacts and an extension slot",
                Organization(
                    organization_id="org-seller-1",
                    name="PremiumPub",
                    role=OrganizationRole.SELLER,
                    address="1 Publisher Way, New York, NY",
                    contacts=[{"name": "Ad Ops", "email": "adops@example.com"}],
                    ext={"crm_id": "crm-778"},
                ),
            ),
        ],
    )

    docs["Account"] = _doc(
        "primitives",
        "Account",
        [
            _valid(
                "active_pair",
                "Active buyer/seller commercial relationship",
                Account(
                    account_id="acct-001",
                    buyer_organization_id="org-buyer-1",
                    seller_organization_id="org-seller-1",
                    advertiser_id="adv-cola",
                    name="Acme x PremiumPub",
                ),
            ),
            _valid(
                "suspended_minimal",
                "Suspended account with only required fields",
                Account(
                    account_id="acct-002",
                    buyer_organization_id="org-buyer-2",
                    seller_organization_id="org-seller-1",
                    status="suspended",
                ),
            ),
        ],
    )

    seller_agent = Agent(
        agent_id="agent-seller-1",
        name="PremiumPub Seller Agent",
        description="Seller agent for PremiumPub inventory",
        url="https://seller.example.com/a2a",
        agent_type="seller",
        provider=AgentProvider(name="PremiumPub", url="https://premiumpub.example.com"),
        skills=[
            AgentSkill(
                id="quote",
                name="Quoting",
                description="Price quotes for PG/PD/PA deals",
                tags=["deals"],
            )
        ],
        organization_id="org-seller-1",
        inventory_types=["display", "video", "ctv"],
        supported_deal_types=["PG", "PD", "PA"],
        trust_status=TrustStatus.APPROVED,
    )
    docs["Agent"] = _doc(
        "primitives",
        "Agent",
        [
            _valid("seller_card", "Registry-approved seller agent card", seller_agent),
            _valid(
                "buyer_card_minimal",
                "Self-served buyer card: trust_status stays 'unknown' until "
                "a registry lookup upgrades it",
                Agent(
                    agent_id="agent-buyer-1",
                    name="Acme Buyer Agent",
                    description="Buyer agent for Acme campaigns",
                    url="https://buyer.example.com/a2a",
                    provider=AgentProvider(name="Acme Media Buying"),
                ),
            ),
            _must_ignore(
                "card_with_unknown_fields",
                "FD-13: unknown + x_ fields on an agent card are ignored",
                seller_agent,
            ),
        ],
    )

    product = Product(
        product_id="prod-001",
        seller_organization_id="org-seller-1",
        name="Premium Homepage Takeover",
        description="Above-the-fold homepage display",
        base_price=Money.from_decimal_str("25.00"),
        ad_formats=["banner", "video"],
        audience_targeting={"segment_ids": ["1001"]},
        available_impressions=5_000_000,
        commercial_terms=CommercialTerms(
            supported_deal_types=[DealType.PROGRAMMATIC_GUARANTEED, DealType.PREFERRED_DEAL],
            supported_pricing_models=[PricingModel.CPM],
            minimum_deal_value=Money.from_decimal_str("5000"),
            guarantee_allowed=True,
        ),
    )
    docs["Product"] = _doc(
        "primitives",
        "Product",
        [
            _valid("guaranteed_display", "Fixed-price guaranteed display product", product),
            _valid(
                "on_request_video",
                "pricing_type=on_request: no price fields are fabricated",
                Product(
                    product_id="prod-002",
                    seller_organization_id="org-seller-1",
                    name="CTV Prime Video",
                    pricing_type=PricingType.ON_REQUEST,
                    pricing_model=PricingModel.CPCV,
                    delivery_type=DeliveryType.PMP,
                    ad_formats=["video"],
                ),
            ),
            _must_ignore(
                "product_with_unknown_fields",
                "FD-13: unknown + x_ fields on a product are ignored",
                product,
            ),
        ],
    )

    package = Package(
        package_id="pkg-001",
        name="Sports Premium",
        description="Cross-screen sports package",
        status=PackageStatus.ACTIVE,
        placements=[
            PackagePlacement(
                product_id="prod-001",
                product_name="Premium Homepage Takeover",
                ad_formats=["banner"],
                device_types=[2, 3],
                weight=0.7,
            )
        ],
        cat=["IAB19"],
        geo_targets=["US", "US-NY"],
        base_price=Money.from_decimal_str("32.00"),
        tags=["sports", "premium"],
        is_featured=True,
        created_at=T0,
    )
    docs["Package"] = _doc(
        "primitives",
        "Package",
        [
            _valid("curated_sports", "Curated, active cross-screen package", package),
            _valid(
                "dynamic_ctv_minimal",
                "Agent-assembled dynamic package, draft, no list price",
                Package(
                    package_id="pkg-002",
                    name="Dynamic CTV Reach",
                    layer=PackageLayer.DYNAMIC,
                    device_types=[3],
                    ad_formats=["video"],
                    pricing_type=PricingType.FLOOR,
                    created_at=T1,
                ),
            ),
        ],
    )

    docs["MediaKit"] = _doc(
        "primitives",
        "MediaKit",
        [
            _valid(
                "kit_with_packages",
                "Discoverable media kit with one active package",
                MediaKit(
                    media_kit_id="mk-001",
                    seller_organization_id="org-seller-1",
                    name="PremiumPub 2026 Media Kit",
                    description="All discoverable PremiumPub packages",
                    packages=[package],
                    contact="adops@example.com",
                    created_at=T0,
                ),
            ),
            _valid(
                "empty_kit",
                "Media kit with no packages yet",
                MediaKit(
                    media_kit_id="mk-002",
                    seller_organization_id="org-seller-2",
                    name="Fresh Seller Kit",
                    created_at=T1,
                ),
            ),
        ],
    )

    docs["RateCard"] = _doc(
        "primitives",
        "RateCard",
        [
            _valid(
                "active_pair_card",
                "Active private rate card between one buyer/seller pair (FD-9)",
                RateCard(
                    rate_card_id="rc-001",
                    buyer_organization_id="org-buyer-1",
                    seller_organization_id="org-seller-1",
                    account_id="acct-001",
                    entries=[
                        RateCardEntry(
                            product_id="prod-001",
                            rate=Money.from_decimal_str("21.00"),
                            notes="2026 upfront rate",
                        ),
                        RateCardEntry(
                            ad_format="video",
                            pricing_model=PricingModel.CPCV,
                            rate=Money.from_decimal_str("0.12"),
                        ),
                    ],
                    effective_from=date(2026, 7, 1),
                    effective_to=date(2026, 12, 31),
                    status=RateCardStatus.ACTIVE,
                    created_at=T0,
                ),
            ),
            _valid(
                "proposed_minimal",
                "Proposed card, open-ended effective window",
                RateCard(
                    rate_card_id="rc-002",
                    buyer_organization_id="org-buyer-2",
                    seller_organization_id="org-seller-1",
                    effective_from=date(2026, 8, 1),
                    created_at=T1,
                ),
            ),
        ],
    )

    docs["Quote"] = _doc(
        "primitives",
        "Quote",
        [
            _valid("pg_digital_guaranteed", "Happy-path PG digital quote", _quote_pg_digital()),
            _valid(
                "linear_tv_primetime",
                "FD-6 linear TV quote: CPP pricing, GRP terms, structured linear_tv details",
                _quote_linear_tv(),
            ),
            _valid(
                "pd_on_request_declined",
                "PD quote with on_request pricing (no fabricated prices) in "
                "a terminal declined status",
                Quote(
                    quote_id="q-pd-003",
                    status=QuoteStatus.DECLINED,
                    deal_type=DealType.PREFERRED_DEAL,
                    product=ProductRef(product_id="prod-002", name="CTV Prime Video"),
                    pricing=QuotePricing(
                        pricing_type=PricingType.ON_REQUEST,
                        pricing_model=PricingModel.CPCV,
                        rationale="pricing on request; buyer declined to negotiate",
                    ),
                    terms=QuoteTerms(),
                    created_at=T1,
                ),
            ),
            _valid(
                "pa_money_boundary",
                "FD-11 boundary values: 1 micro floor and the 2**53-1 "
                "largest-safe-integer micros ceiling",
                Quote(
                    quote_id="q-pa-004",
                    deal_type=DealType.PRIVATE_AUCTION,
                    product=_product_ref(),
                    pricing=QuotePricing(
                        pricing_type=PricingType.FLOOR,
                        base_cpm=Money(amount_micros=1),
                        final_cpm=Money(amount_micros=MAX_SAFE_MICROS),
                        rationale="boundary-value vector",
                    ),
                    terms=QuoteTerms(impressions=0),
                    created_at=T1,
                ),
            ),
            _must_ignore(
                "quote_with_unknown_fields",
                "FD-13: unknown + x_ fields on a quote are ignored",
                _quote_pg_digital(),
            ),
            _invalid(
                "float_money_rejected",
                "FD-11: float-typed money (22.5 micros) must be rejected",
                _with_float_cpm(_dump(_quote_pg_digital())),
                "Input should be a valid integer",
            ),
        ],
    )

    docs["Proposal"] = _doc(
        "primitives",
        "Proposal",
        [
            _valid(
                "sent_with_lines",
                "Sent proposal with one PD line",
                Proposal(
                    proposal_id="prop-001",
                    account_id="acct-001",
                    status=ProposalStatus.SENT,
                    start_date=date(2026, 8, 1),
                    end_date=date(2026, 8, 31),
                    lines=[
                        ProposalLine(
                            proposal_line_id="pl-001",
                            proposal_id="prop-001",
                            product_id="prod-001",
                            deal_type=DealType.PREFERRED_DEAL,
                            delivery_goal=DeliveryGoal(
                                goal_type="impressions",
                                goal_amount=1_000_000,
                                billable_event="impression",
                            ),
                            pricing=PricingTerms(
                                pricing_model=PricingModel.CPM,
                                price=Money.from_decimal_str("22.50"),
                            ),
                        )
                    ],
                    created_at=T0,
                ),
            ),
            _valid(
                "countered_revision_3",
                "Threaded proposal on its third revision",
                Proposal(
                    proposal_id="prop-002",
                    proposal_thread_id="thread-77",
                    account_id="acct-001",
                    status=ProposalStatus.COUNTERED,
                    current_revision_number=3,
                    start_date=date(2026, 9, 1),
                    end_date=date(2026, 9, 30),
                    created_at=T0,
                    updated_at=T1,
                ),
            ),
        ],
    )

    docs["Negotiation"] = _doc(
        "primitives",
        "Negotiation",
        [
            _valid(
                "active_round_1",
                "Quote-led negotiation after the first counter",
                Negotiation(
                    negotiation_id="neg-001",
                    quote_id="q-pg-001",
                    product_id="prod-001",
                    buyer_tier=AccessTier.ADVERTISER,
                    rounds=[
                        NegotiationRound(
                            round_number=1,
                            buyer_price=Money.from_decimal_str("20.00"),
                            seller_price=Money.from_decimal_str("23.00"),
                            action=NegotiationAction.COUNTER,
                            concession_pct=0.04,
                            cumulative_concession_pct=0.04,
                            rationale="meeting the buyer partway",
                            timestamp=T0,
                        )
                    ],
                    started_at=T0,
                ),
            ),
            _valid(
                "accepted_terminal",
                "Terminal accepted negotiation with full round history",
                Negotiation(
                    negotiation_id="neg-002",
                    proposal_id="prop-001",
                    package_id="pkg-001",
                    buyer_tier=AccessTier.AGENCY,
                    rounds=[
                        NegotiationRound(
                            round_number=1,
                            buyer_price=Money.from_decimal_str("28.00"),
                            seller_price=Money.from_decimal_str("31.00"),
                            action=NegotiationAction.COUNTER,
                            timestamp=T0,
                        ),
                        NegotiationRound(
                            round_number=2,
                            buyer_price=Money.from_decimal_str("30.00"),
                            seller_price=Money.from_decimal_str("30.00"),
                            action=NegotiationAction.ACCEPT,
                            concession_pct=0.032,
                            cumulative_concession_pct=0.032,
                            timestamp=T1,
                        ),
                    ],
                    status=NegotiationStatus.ACCEPTED,
                    started_at=T0,
                    completed_at=T1,
                ),
            ),
        ],
    )

    docs["Deal"] = _doc(
        "primitives",
        "Deal",
        [
            _valid(
                "pg_booked_openrtb",
                "Booked PG deal with OpenRTB activation params",
                _deal_pg_booked(),
            ),
            _valid(
                "linear_tv_makegood_pending",
                "FD-6 linear TV deal in makegood_pending after GRP shortfall",
                Deal(
                    deal_id="deal-ltv-002",
                    deal_type=DealType.PROGRAMMATIC_GUARANTEED,
                    status=DealStatus.MAKEGOOD_PENDING,
                    quote_id="q-ltv-002",
                    product=ProductRef(product_id="prod-ltv-9", name="Primetime National Spots"),
                    pricing=QuotePricing(
                        pricing_model=PricingModel.CPP,
                        base_cpp=Money.from_decimal_str("475.00"),
                        final_cpp=Money.from_decimal_str("450.00"),
                    ),
                    terms=QuoteTerms(
                        guaranteed=True, grps=120, guaranteed_grps=110, target_demo="A18-49"
                    ),
                    buyer_tier=AccessTier.AGENCY,
                    seller_id="agent-seller-1",
                    media_type=MediaType.LINEAR_TV,
                    linear_tv=_linear_tv_details(),
                    created_at=T0,
                ),
            ),
            _valid(
                "cancelled_terminal",
                "Terminal cancelled deal",
                Deal(
                    deal_id="deal-003",
                    deal_type=DealType.PREFERRED_DEAL,
                    status=DealStatus.CANCELLED,
                    product=_product_ref(),
                    pricing=QuotePricing(base_cpm=Money.from_decimal_str("18.00")),
                    terms=QuoteTerms(),
                    created_at=T1,
                ),
            ),
            _must_ignore(
                "deal_with_unknown_fields",
                "FD-13: unknown + x_ fields on a deal are ignored",
                _deal_pg_booked(),
            ),
            _invalid(
                "float_bidfloor_rejected",
                "FD-11: an integral float bid floor (22500000.0) is still a "
                "float and must be rejected",
                _with_float_bidfloor(_dump(_deal_pg_booked())),
                "Input should be a valid integer",
            ),
        ],
    )

    order = Order(
        order_id="ord-001",
        account_id="acct-001",
        deal_id="deal-001",
        name="Q3 Awareness Push",
        budget=Money.from_decimal_str("50000"),
        start_date=date(2026, 8, 1),
        end_date=date(2026, 8, 31),
        status=OrderStatus.SUBMITTED,
        external_ids={"gam_order_id": "gam-556677"},
        created_at=T0,
        consent_context=_consent(),
    )
    docs["Order"] = _doc(
        "primitives",
        "Order",
        [
            _valid("submitted_with_consent", "Submitted insertion order", order),
            _valid(
                "completed_terminal",
                "Terminal completed order",
                Order(
                    order_id="ord-002",
                    account_id="acct-001",
                    name="Spring Retargeting",
                    budget=Money.from_decimal_str("12000"),
                    start_date=date(2026, 3, 1),
                    end_date=date(2026, 3, 31),
                    status=OrderStatus.COMPLETED,
                    created_at=T0,
                    updated_at=T1,
                ),
            ),
            _invalid(
                "float_budget_rejected",
                "FD-11: float-typed budget must be rejected",
                _with_float_money(_dump(order), ["budget"]),
                "Input should be a valid integer",
            ),
        ],
    )

    line = Line(
        line_id="line-001",
        order_id="ord-001",
        product_id="prod-001",
        name="Homepage Takeover Aug",
        start_date=date(2026, 8, 1),
        end_date=date(2026, 8, 31),
        rate=Money.from_decimal_str("22.50"),
        quantity=1_000_000,
        cost=Money.from_decimal_str("22500"),
        status=LineStatus.BOOKED,
        targeting={"geo": ["US-NY"]},
    )
    docs["Line"] = _doc(
        "primitives",
        "Line",
        [
            _valid(
                "booked_line",
                "Booked line (OpenDirect wire casing: 'Booked')",
                line,
            ),
            _valid(
                "finished_terminal",
                "Terminal finished line",
                Line(
                    line_id="line-002",
                    order_id="ord-002",
                    product_id="prod-002",
                    name="CTV Prime March",
                    start_date=date(2026, 3, 1),
                    end_date=date(2026, 3, 31),
                    pricing_model=PricingModel.CPCV,
                    rate=Money.from_decimal_str("0.12"),
                    quantity=400_000,
                    status=LineStatus.FINISHED,
                ),
            ),
            _invalid(
                "float_rate_rejected",
                "FD-11: float-typed line rate must be rejected",
                _with_float_money(_dump(line), ["rate"]),
                "Input should be a valid integer",
            ),
        ],
    )

    docs["ChangeRequest"] = _doc(
        "primitives",
        "ChangeRequest",
        [
            _valid(
                "makegood_pending",
                "FD-6 makegood as a typed ChangeRequest subtype",
                _change_request_makegood(),
            ),
            _valid(
                "cancellation_applied",
                "Terminal applied cancellation with field diffs",
                ChangeRequest(
                    change_request_id="cr-002",
                    order_id="ord-001",
                    status=ChangeRequestStatus.APPLIED,
                    change_type=ChangeType.CANCELLATION,
                    severity=ChangeSeverity.CRITICAL,
                    requested_by="human:ops-42",
                    requested_at=T0,
                    reason="Campaign paused by advertiser",
                    diffs=[FieldDiff(field="status", old_value="booked", new_value="cancelled")],
                    proposed_values={
                        "cancel_pct": 1.0,
                        "reason": "advertiser pause",
                        "effective_date": "2026-08-15",
                    },
                    approved_by="human:manager-7",
                    approved_at=T1,
                    applied_at=T1,
                    applied_by="system",
                ),
            ),
            _invalid(
                "missing_target_rejected",
                "A change request must reference an order or a deal",
                {
                    "change_request_id": "cr-bad",
                    "change_type": "pricing",
                    "requested_at": "2026-07-01T12:00:00Z",
                },
                "requires at least one of order_id or deal_id",
            ),
        ],
    )

    docs["Session"] = _doc(
        "primitives",
        "Session",
        [
            _valid(
                "active_conversation",
                "Active session with revealed buyer identity",
                Session(
                    session_id="sess-001",
                    buyer_identity=BuyerIdentity(seat_id="ttd-seat-123", agency_id="omnicom-456"),
                    messages=[
                        SessionMessage(
                            role="user",
                            content="What CTV inventory do you have?",
                            timestamp=T0,
                            message_type="availability",
                        )
                    ],
                    active_negotiation_ids=["neg-001"],
                    active_deal_ids=["deal-001"],
                    created_at=T0,
                    updated_at=T0,
                    expires_at=T_EXPIRES,
                ),
            ),
            _valid(
                "closed_terminal",
                "Terminal closed session",
                Session(
                    session_id="sess-002",
                    status=SessionStatus.CLOSED,
                    created_at=T0,
                    updated_at=T1,
                    closed_at=T1,
                ),
            ),
        ],
    )

    docs["Creative"] = _doc(
        "primitives",
        "Creative",
        [
            _valid(
                "video_approved",
                "Approved video creative with a full manifest",
                Creative(
                    creative_id="crv-001",
                    account_id="acct-001",
                    name="Summer Video 30s",
                    language="en",
                    click_url="https://example.com/summer",
                    creative_manifest=CreativeManifest(
                        assets=[
                            CreativeAsset(
                                asset_id="a-1",
                                asset_url="https://cdn.example.com/summer.mp4",
                                mime_type="video/mp4",
                                width=1920,
                                height=1080,
                                role="main",
                            )
                        ],
                        landing_page_urls=["https://example.com/summer"],
                        declared_advertiser_domains=["example.com"],
                        duration_ms=30_000,
                        file_size_bytes=4_500_000,
                    ),
                    review_status=ReviewStatus.APPROVED,
                ),
            ),
            _valid(
                "placeholder_pending",
                "Metadata-only placeholder awaiting seller review",
                Creative(
                    creative_id="crv-002",
                    name="Q4 Placeholder",
                    is_placeholder=True,
                    placeholder_type="pending_asset",
                ),
            ),
        ],
    )

    docs["Assignment"] = _doc(
        "primitives",
        "Assignment",
        [
            _valid(
                "weighted_rotation",
                "Weighted creative-to-line binding with share of voice",
                Assignment(
                    assignment_id="asg-001",
                    creative_id="crv-001",
                    line_id="line-001",
                    rotation_mode=RotationMode.WEIGHTED,
                    sov=0.6,
                    effective_start_date=date(2026, 8, 1),
                    effective_end_date=date(2026, 8, 31),
                ),
            ),
            _valid(
                "even_minimal",
                "Even rotation with only required fields",
                Assignment(
                    assignment_id="asg-002",
                    creative_id="crv-002",
                    line_id="line-002",
                ),
            ),
        ],
    )

    docs["ConsentContext"] = _doc(
        "primitives",
        "ConsentContext",
        [
            _valid(
                "gdpr_gpp_passed",
                "GDPR-scope consent with GPP + TCF strings and passed diligence",
                _consent(),
            ),
            _valid(
                "us_privacy_only",
                "US-only consent: us_privacy string, GDPR not applicable",
                ConsentContext(
                    applicable_regimes=["CCPA"],
                    us_privacy="1YNN",
                    gdpr_applies=False,
                    diligence_status=DiligenceStatus.PASSED,
                    verified_at=T0,
                ),
            ),
            _valid(
                "unknown_minimal",
                "Empty consent context: unknown diligence, no signals",
                ConsentContext(),
            ),
        ],
    )

    docs["CreativeApproval"] = _doc(
        "primitives",
        "CreativeApproval",
        [
            _valid(
                "human_approved",
                "Seller human reviewer approves a creative",
                CreativeApproval(
                    approval_id="capp-001",
                    creative_id="crv-001",
                    status=ReviewStatus.APPROVED,
                    reviewer="human:ops-42",
                    reason="Meets brand-safety and format requirements",
                    occurred_at=T0,
                ),
            ),
            _valid(
                "auto_rejected",
                "Automated review rejects a creative with a reason",
                CreativeApproval(
                    approval_id="capp-002",
                    creative_id="crv-002",
                    status=ReviewStatus.REJECTED,
                    reviewer="system",
                    reason="Declared advertiser domain is on the block list",
                    occurred_at=T1,
                ),
            ),
        ],
    )

    docs["SupplyChain"] = _doc(
        "primitives",
        "SupplyChain",
        [
            _valid(
                "complete_single_hop",
                "Complete schain with one disclosed node (OpenRTB field names)",
                _supply_chain(),
            ),
            _valid(
                "incomplete_two_hops",
                "Incomplete schain across a reseller hop",
                SupplyChain(
                    complete=0,
                    nodes=[
                        SupplyChainNode(
                            asi="ssp.example.com",
                            sid="pub-77",
                            hp=1,
                            name="Origin SSP",
                            domain="ssp.example.com",
                        ),
                        SupplyChainNode(
                            asi="reseller.example.com",
                            sid="rsl-9",
                            hp=0,
                        ),
                    ],
                ),
            ),
            _must_ignore(
                "schain_with_unknown_fields",
                "FD-13: unknown + x_ fields on a supply chain are ignored",
                _supply_chain(),
            ),
        ],
    )

    docs["SellersJsonEntry"] = _doc(
        "primitives",
        "SellersJsonEntry",
        [
            _valid(
                "publisher_entry",
                "Publisher sellers.json entry (owns the inventory)",
                SellersJsonEntry(
                    seller_id="seller-001",
                    name="PremiumPub",
                    domain="premiumpub.example.com",
                    seller_type=SellerType.PUBLISHER,
                ),
            ),
            _valid(
                "confidential_intermediary",
                "Confidential intermediary: name/domain withheld",
                SellersJsonEntry(
                    seller_id="seller-002",
                    seller_type=SellerType.INTERMEDIARY,
                    is_confidential=True,
                    comment="Confidential per contract",
                ),
            ),
        ],
    )

    decision = DecisionRecord(
        decision_id="dr-001",
        subject_type="deal",
        subject_id="deal-001",
        decision_type=DecisionType.BOOKING,
        actor=DecisionActor(
            agent_id="agent-seller-1",
            kind=ActorKind.MACHINE,
            on_behalf_of="org-seller-1",
        ),
        inputs=[
            DecisionInputRef(
                kind="counterparty_message",
                ref="msg-001",
                digest="sha256:2c26b46b68ffc68ff99b453c1d304134",
                description="Buyer booking request",
            ),
            DecisionInputRef(
                kind="model_output",
                digest="sha256:fcde2b2edba56bf408601fb721fe9b5c",
                description="Pricing model recommendation",
            ),
        ],
        rationale=DecisionRationale(
            summary="Booked at the advertiser-tier rate card price",
            factors=["advertiser_tier", "rate_card_match", "inventory_available"],
            policy_refs=["policy:auto-book-approved-tier"],
        ),
        money_effect=Money.from_decimal_str("22500"),
        occurred_at=T0,
        correlation_id="corr-001",
        session_id="sess-001",
    )
    docs["DecisionRecord"] = _doc(
        "primitives",
        "DecisionRecord",
        [
            _valid(
                "booking_decision",
                "Durable record of why a booking committed money (EP-10.1)",
                decision,
            ),
            _valid(
                "concession_minimal",
                "Negotiation-concession decision by a human, no money effect yet",
                DecisionRecord(
                    decision_id="dr-002",
                    subject_type="negotiation",
                    subject_id="neg-001",
                    decision_type=DecisionType.NEGOTIATION_CONCESSION,
                    actor=DecisionActor(agent_id="human:trader-7", kind=ActorKind.HUMAN),
                    rationale=DecisionRationale(
                        summary="Conceded 3% to close within the buyer's ceiling"
                    ),
                    occurred_at=T1,
                    negotiation_id="neg-001",
                ),
            ),
            _must_ignore(
                "decision_with_unknown_fields",
                "FD-13: unknown + x_ fields on a decision record are ignored",
                decision,
            ),
            _invalid(
                "float_money_effect_rejected",
                "FD-11: float-typed money_effect must be rejected",
                _with_float_money(_dump(decision), ["money_effect"]),
                "Input should be a valid integer",
            ),
        ],
    )

    return docs


def _with_float_cpm(data: dict[str, Any]) -> dict[str, Any]:
    """Corrupt a quote-shaped payload with fractional-float money (FD-11)."""
    data = json.loads(json.dumps(data))
    data["pricing"]["base_cpm"]["amount_micros"] = 22500000.5
    return data


def _with_float_bidfloor(data: dict[str, Any]) -> dict[str, Any]:
    """Corrupt a deal-shaped payload with integral-float money (FD-11)."""
    data = json.loads(json.dumps(data))
    data["openrtb_params"]["bidfloor"]["amount_micros"] = 22500000.0
    return data


def _with_float_money(data: dict[str, Any], path: list[str]) -> dict[str, Any]:
    """Corrupt ``data[...path]["amount_micros"]`` into a float (FD-11)."""
    data = json.loads(json.dumps(data))
    node = data
    for key in path:
        node = node[key]
    node["amount_micros"] = float(node["amount_micros"]) + 0.5
    return data


# ---------------------------------------------------------------------------
# Protocol (15 targets)
# ---------------------------------------------------------------------------


def _quote_request_pg() -> QuoteRequest:
    return QuoteRequest(
        idempotency_key=_idem(1),
        product_id="prod-001",
        deal_type=DealType.PROGRAMMATIC_GUARANTEED,
        impressions=1_000_000,
        flight_start=date(2026, 8, 1),
        flight_end=date(2026, 8, 31),
        target_cpm=Money.from_decimal_str("22.00"),
        buyer_identity=BuyerIdentity(
            seat_id="ttd-seat-123",
            agency_id="omnicom-456",
            advertiser_id="adv-cola",
            advertiser_name="Cola Co",
        ),
        agent_url="https://buyer.example.com/a2a",
        rate_card_id="rc-001",
        consent_context=_consent(),
    )


def protocol_fixture_docs() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {}

    docs["ProductListRequest"] = _doc(
        "protocol",
        "ProductListRequest",
        [
            _valid(
                "default_page",
                "Default pagination for GET /products",
                ProductListRequest(),
            ),
            _valid(
                "second_page_max",
                "Maximum page size at an offset",
                ProductListRequest(limit=500, offset=500),
            ),
        ],
    )

    product = Product(
        product_id="prod-001",
        seller_organization_id="org-seller-1",
        name="Premium Homepage Takeover",
        base_price=Money.from_decimal_str("25.00"),
        ad_formats=["banner", "video"],
        available_impressions=5_000_000,
    )
    docs["ProductListResponse"] = _doc(
        "protocol",
        "ProductListResponse",
        [
            _valid(
                "one_product",
                "Catalog page with a single product",
                ProductListResponse(products=[product], total_count=1, limit=50, offset=0),
            ),
            _valid(
                "empty_catalog",
                "Empty catalog page",
                ProductListResponse(products=[], total_count=0, limit=50, offset=0),
            ),
        ],
    )

    docs["AvailsRequest"] = _doc(
        "protocol",
        "AvailsRequest",
        [
            _valid(
                "impressions_and_targeting",
                "Avails check with requested volume, budget, and targeting",
                AvailsRequest(
                    product_id="prod-001",
                    start_date=datetime(2026, 8, 1, tzinfo=UTC),
                    end_date=datetime(2026, 8, 31, 23, 59, 59, tzinfo=UTC),
                    requested_impressions=500_000,
                    budget=6000.0,
                    targeting={"geo": ["US"], "device": ["mobile"]},
                ),
            ),
            _valid(
                "minimal_dates_only",
                "Minimal check: seller falls back to product minimums",
                AvailsRequest(
                    product_id="prod-001",
                    start_date=datetime(2026, 9, 1, tzinfo=UTC),
                    end_date=datetime(2026, 9, 30, tzinfo=UTC),
                ),
            ),
            _invalid(
                "end_before_start",
                "Flight end must be strictly after the start",
                {
                    "productid": "prod-001",
                    "startdate": "2026-08-31T00:00:00Z",
                    "enddate": "2026-08-01T00:00:00Z",
                },
                "enddate must be after startdate",
            ),
        ],
    )

    docs["AvailsResponse"] = _doc(
        "protocol",
        "AvailsResponse",
        [
            _valid(
                "pg_capable_guaranteed",
                "PG-capable product: guaranteedImpressions present (policy 3)",
                AvailsResponse(
                    product_id="prod-001",
                    available_impressions=750_000,
                    guaranteed_impressions=500_000,
                    estimated_cpm=12.0,
                    total_cost=9000.0,
                    available_targeting=["device", "geo"],
                ),
            ),
            _valid(
                "uncapped_non_pg",
                "Uncapped non-PG product reports requested-as-available; "
                "no forecast source, so deliveryConfidence has no value "
                "(policies 1 and 2)",
                AvailsResponse(
                    product_id="prod-002",
                    available_impressions=250_000,
                    estimated_cpm=8.5,
                    total_cost=2125.0,
                ),
            ),
            _must_ignore(
                "forward_compat_extras",
                "FD-13: unknown and x_ extension fields are ignored",
                AvailsResponse(
                    product_id="prod-001",
                    available_impressions=100_000,
                    estimated_cpm=10.0,
                    total_cost=1000.0,
                ),
            ),
            _invalid(
                "missing_available_impressions",
                "availableImpressions is REQUIRED (policy 1)",
                {
                    "productid": "prod-001",
                    "estimatedCpm": 12.0,
                    "totalCost": 9000.0,
                },
                "availableImpressions",
            ),
        ],
    )

    # ------------------------------------------------------------------
    # OpenDirect 2.1 spec dialect (normative attribute tables): the
    # converged request/response shapes served alongside the legacy
    # simplified profile.
    # ------------------------------------------------------------------

    _avails_flight = dict(
        start_date=datetime(2026, 8, 1, tzinfo=UTC),
        end_date=datetime(2026, 8, 31, 23, 59, 59, tzinfo=UTC),
    )

    def _spec_inventory_pt(available: int) -> ProductTargeting:
        return ProductTargeting(
            name=TargetingDimension.INVENTORY,
            type=TargetingUnit.AUDIENCE,
            datasource="iab-agentic-primitives",
            target="impressions",
            target_values=[str(available)],
            selectable=False,
            count=available,
        )

    def _spec_avails(
        product_id: str,
        available: int,
        status: AvailsStatusValue,
        reason: AvailsStatusReason | None,
    ) -> Avails:
        return Avails(
            product_id=product_id,
            account_id="acct-42",
            availability=available,
            avails_status=AvailsStatus(
                status=status,
                reason=reason,
                product_targeting=[_spec_inventory_pt(available)],
            ),
            currency="USD",
            price=12.0,
            **_avails_flight,
        )

    docs["ProductAvailsSearch"] = _doc(
        "protocol",
        "ProductAvailsSearch",
        [
            _valid(
                "spec_minimal_multi_product",
                "Strictly spec-shaped multi-product search: the five "
                "spec-required attributes plus currency",
                ProductAvailsSearch(
                    product_ids=["prod-001", "prod-002"],
                    account_id="acct-42",
                    advertiser_brand_id="brand-7",
                    currency="USD",
                    **_avails_flight,
                ),
            ),
            _valid(
                "bridged_from_simplified",
                "AvailsRequest.to_spec output: volume/budget as minted "
                "Investment producttargeting, legacy dict targeting as "
                "the AdCOM Segment array",
                AvailsRequest(
                    product_id="prod-001",
                    requested_impressions=500_000,
                    budget=6000.0,
                    targeting={"geo": ["US"], "device": ["mobile"]},
                    **_avails_flight,
                ).to_spec(account_id="acct-42", advertiser_brand_id="brand-7"),
            ),
            _must_ignore(
                "forward_compat_extras",
                "FD-13: unknown and x_ extension fields are ignored",
                ProductAvailsSearch(
                    product_ids=["prod-001"],
                    account_id="acct-42",
                    advertiser_brand_id="brand-7",
                    **_avails_flight,
                ),
            ),
            _invalid(
                "missing_accountid",
                "accountid is spec-required on ProductAvailsSearch",
                {
                    "productids": ["prod-001"],
                    "advertiserbrandid": "brand-7",
                    "startdate": "2026-08-01T00:00:00Z",
                    "enddate": "2026-08-31T23:59:59Z",
                },
                "accountid",
            ),
            _invalid(
                "empty_productids",
                "productids must name at least one product",
                {
                    "productids": [],
                    "accountid": "acct-42",
                    "advertiserbrandid": "brand-7",
                    "startdate": "2026-08-01T00:00:00Z",
                    "enddate": "2026-08-31T23:59:59Z",
                },
                "productids",
            ),
        ],
    )

    docs["Avails"] = _doc(
        "protocol",
        "Avails",
        [
            _valid(
                "fully_available",
                "Full requested volume available: availsstatus Available, no reason",
                _spec_avails("prod-001", 500_000, AvailsStatusValue.AVAILABLE, None),
            ),
            _valid(
                "partially_available_booked",
                "Capacity caps availability below the requested volume: "
                "Partially Available with spec reason Booked",
                _spec_avails(
                    "prod-002",
                    400_000,
                    AvailsStatusValue.PARTIALLY_AVAILABLE,
                    AvailsStatusReason.BOOKED,
                ),
            ),
            _valid(
                "minimal_required_only",
                "Only the spec-required attributes (productid, accountid, "
                "price, startdate, enddate)",
                Avails(
                    product_id="prod-003",
                    account_id="acct-42",
                    price=8.5,
                    **_avails_flight,
                ),
            ),
            _invalid(
                "missing_price",
                "price is spec-required on Avails",
                {
                    "productid": "prod-001",
                    "accountid": "acct-42",
                    "startdate": "2026-08-01T00:00:00Z",
                    "enddate": "2026-08-31T23:59:59Z",
                },
                "price",
            ),
        ],
    )

    docs["AvailsCollection"] = _doc(
        "protocol",
        "AvailsCollection",
        [
            _valid(
                "one_record_per_requested_product",
                "Collection Objects envelope: the array property is named "
                "'avails', one record per product in the request",
                AvailsCollection(
                    avails=[
                        _spec_avails(
                            "prod-001",
                            500_000,
                            AvailsStatusValue.AVAILABLE,
                            None,
                        ),
                        _spec_avails(
                            "prod-002",
                            0,
                            AvailsStatusValue.UNAVAILABLE,
                            AvailsStatusReason.BOOKED,
                        ),
                    ]
                ),
            ),
            _valid(
                "empty_collection",
                "No matching availability: the avails array is empty, never absent",
                AvailsCollection(avails=[]),
            ),
            _must_ignore(
                "forward_compat_extras",
                "FD-13 + spec: 'the collection object may include "
                "additional publisher-defined properties'",
                AvailsCollection(
                    avails=[
                        Avails(
                            product_id="prod-001",
                            account_id="acct-42",
                            price=12.0,
                            **_avails_flight,
                        )
                    ]
                ),
            ),
            _invalid(
                "missing_avails_array",
                "The envelope must contain the 'avails' array property",
                {},
                "avails",
            ),
        ],
    )

    docs["QuoteRequest"] = _doc(
        "protocol",
        "QuoteRequest",
        [
            _valid(
                "pg_with_idempotency_key",
                "FD-12 money-mutating request with its required key",
                _quote_request_pg(),
            ),
            _valid(
                "linear_tv_request",
                "FD-6 linear TV quote request with LinearTVParams",
                QuoteRequest(
                    idempotency_key=_idem(2),
                    product_id="prod-ltv-9",
                    deal_type=DealType.PROGRAMMATIC_GUARANTEED,
                    flight_start=date(2026, 9, 1),
                    flight_end=date(2026, 9, 28),
                    media_type=MediaType.LINEAR_TV,
                    linear_tv=LinearTVParams(
                        target_demo="A18-49",
                        grps_requested=120,
                        dayparts=["primetime"],
                        networks=["NBC", "ESPN"],
                        spot_length=30,
                        target_cpp=Money.from_decimal_str("450.00"),
                    ),
                ),
            ),
            _must_ignore(
                "request_with_unknown_fields",
                "FD-13: unknown + x_ fields on a quote request are ignored",
                _quote_request_pg(),
            ),
            _invalid(
                "missing_idempotency_key",
                "FD-12: a money-mutating request without idempotency_key must be rejected",
                {"product_id": "prod-001", "deal_type": "PG", "impressions": 1000000},
                "idempotency_key",
            ),
            _invalid(
                "float_target_cpm_rejected",
                "FD-11: float-typed target CPM must be rejected",
                {
                    "idempotency_key": _idem(3),
                    "product_id": "prod-001",
                    "deal_type": "PG",
                    "target_cpm": {"amount_micros": 22.5, "currency": "USD"},
                },
                "Input should be a valid integer",
            ),
            _invalid(
                "linear_tv_missing_params",
                "FD-6: media_type linear_tv without linear_tv params must be rejected",
                {
                    "idempotency_key": _idem(4),
                    "product_id": "prod-ltv-9",
                    "deal_type": "PG",
                    "media_type": "linear_tv",
                },
                "requires linear_tv params",
            ),
        ],
    )

    docs["QuoteResponse"] = _doc(
        "protocol",
        "QuoteResponse",
        [
            _valid(
                "digital_quote",
                "Envelope wrapping a PG digital quote",
                QuoteResponse(quote=_quote_pg_digital()),
            ),
            _valid(
                "linear_tv_quote",
                "Envelope wrapping the FD-6 linear TV quote",
                QuoteResponse(quote=_quote_linear_tv()),
            ),
            _must_ignore(
                "response_with_unknown_fields",
                "FD-13: unknown + x_ fields on a quote response are ignored",
                QuoteResponse(quote=_quote_pg_digital()),
            ),
        ],
    )

    booking = DealBookingRequest(
        idempotency_key=_idem(5),
        quote_id="q-pg-001",
        buyer_identity=BuyerIdentity(seat_id="ttd-seat-123", advertiser_id="adv-cola"),
        notes="Book at quoted terms",
        consent_context=_consent(),
    )
    docs["DealBookingRequest"] = _doc(
        "protocol",
        "DealBookingRequest",
        [
            _valid("book_quoted_deal", "Commit-point booking of a quote", booking),
            _valid(
                "booking_with_audience_plan",
                "Booking that freezes an audience plan snapshot",
                DealBookingRequest(
                    idempotency_key=_idem(6),
                    quote_id="q-pg-001",
                    audience_plan={
                        "plan_id": "ap-9",
                        "segments": [{"id": "1001", "role": "reach"}],
                    },
                ),
            ),
            _must_ignore(
                "booking_with_unknown_fields",
                "FD-13: unknown + x_ fields on a booking request are ignored",
                booking,
            ),
        ],
    )

    docs["DealBookingResponse"] = _doc(
        "protocol",
        "DealBookingResponse",
        [
            _valid(
                "booked_deal",
                "Envelope wrapping the booked deal",
                DealBookingResponse(deal=_deal_pg_booked()),
            ),
            _valid(
                "booked_with_audience_snapshot",
                "Booked deal with the frozen audience-plan snapshot",
                DealBookingResponse(
                    deal=_deal_pg_booked(),
                    audience_plan_snapshot={
                        "plan_id": "ap-9",
                        "segments": [{"id": "1001", "role": "reach"}],
                    },
                    audience_match_summary={"reach": "full"},
                ),
            ),
        ],
    )

    docs["ChangeRequestCreate"] = _doc(
        "protocol",
        "ChangeRequestCreate",
        [
            _valid(
                "makegood_create",
                "FD-6 makegood submitted as a typed change request",
                ChangeRequestCreate(
                    idempotency_key=_idem(7),
                    deal_id="deal-ltv-002",
                    change_type=ChangeType.MAKEGOOD,
                    severity=ChangeSeverity.MATERIAL,
                    reason="GRP shortfall in week 2",
                    makegood=_makegood_details(),
                ),
            ),
            _valid(
                "cancellation_create",
                "Cancellation as a typed change request (retired per-deal cancel route)",
                ChangeRequestCreate(
                    idempotency_key=_idem(8),
                    order_id="ord-001",
                    change_type=ChangeType.CANCELLATION,
                    severity=ChangeSeverity.CRITICAL,
                    reason="Advertiser pause",
                    proposed_values={
                        "cancel_pct": 1.0,
                        "reason": "advertiser pause",
                        "effective_date": "2026-08-15",
                    },
                ),
            ),
            _invalid(
                "makegood_missing_details",
                "change_type makegood without a makegood payload must be rejected",
                {
                    "idempotency_key": _idem(9),
                    "deal_id": "deal-ltv-002",
                    "change_type": "makegood",
                },
                "requires makegood details",
            ),
        ],
    )

    docs["ChangeRequestResponse"] = _doc(
        "protocol",
        "ChangeRequestResponse",
        [
            _valid(
                "makegood_pending_response",
                "Envelope wrapping the pending makegood change request",
                ChangeRequestResponse(change_request=_change_request_makegood()),
            ),
            _valid(
                "cancellation_approved_response",
                "Envelope wrapping an approved cancellation",
                ChangeRequestResponse(
                    change_request=ChangeRequest(
                        change_request_id="cr-002",
                        order_id="ord-001",
                        status=ChangeRequestStatus.APPROVED,
                        change_type=ChangeType.CANCELLATION,
                        severity=ChangeSeverity.CRITICAL,
                        requested_by="human:ops-42",
                        requested_at=T0,
                        reason="Campaign paused by advertiser",
                        proposed_values={"cancel_pct": 1.0},
                        approved_by="human:manager-7",
                        approved_at=T1,
                    )
                ),
            ),
        ],
    )

    open_counter = NegotiationMessage(
        idempotency_key=_idem(10),
        action=NegotiationAction.COUNTER,
        quote_id="q-pg-001",
        buyer_price=Money.from_decimal_str("20.00"),
        buyer_identity=BuyerIdentity(seat_id="ttd-seat-123"),
        rationale="Opening offer below quoted CPM",
    )
    docs["NegotiationMessage"] = _doc(
        "protocol",
        "NegotiationMessage",
        [
            _valid(
                "opening_counter",
                "Opening offer: counter with no negotiation_id (seller mints)",
                open_counter,
            ),
            _valid(
                "accept_terminal",
                "Terminal accept of the seller's last price",
                NegotiationMessage(
                    idempotency_key=_idem(11),
                    action=NegotiationAction.ACCEPT,
                    negotiation_id="neg-001",
                    round_number=2,
                    buyer_price=Money.from_decimal_str("22.00"),
                ),
            ),
            _valid(
                "reject_walk_away",
                "Terminal walk-away: reject carries no price",
                NegotiationMessage(
                    idempotency_key=_idem(12),
                    action=NegotiationAction.REJECT,
                    negotiation_id="neg-001",
                    round_number=2,
                    rationale="Above budget ceiling",
                ),
            ),
            _must_ignore(
                "message_with_unknown_fields",
                "FD-13: unknown + x_ fields on a negotiation message are ignored",
                open_counter,
            ),
            _invalid(
                "reject_with_price",
                "reject must not carry buyer_price",
                {
                    "idempotency_key": _idem(13),
                    "action": "reject",
                    "negotiation_id": "neg-001",
                    "buyer_price": {"amount_micros": 20000000, "currency": "USD"},
                },
                "must not carry buyer_price",
            ),
            _invalid(
                "float_buyer_price_rejected",
                "FD-11: float-typed buyer price must be rejected",
                {
                    "idempotency_key": _idem(14),
                    "action": "counter",
                    "negotiation_id": "neg-001",
                    "buyer_price": {"amount_micros": 20000000.0, "currency": "USD"},
                },
                "Input should be a valid integer",
            ),
        ],
    )

    docs["NegotiationRoundResponse"] = _doc(
        "protocol",
        "NegotiationRoundResponse",
        [
            _valid(
                "counter_active",
                "Seller counters; negotiation stays active",
                NegotiationRoundResponse(
                    negotiation_id="neg-001",
                    status=NegotiationStatus.ACTIVE,
                    round=NegotiationRound(
                        round_number=1,
                        buyer_price=Money.from_decimal_str("20.00"),
                        seller_price=Money.from_decimal_str("23.00"),
                        action=NegotiationAction.COUNTER,
                        concession_pct=0.04,
                        cumulative_concession_pct=0.04,
                        rationale="meeting the buyer partway",
                        timestamp=T0,
                    ),
                    rounds_remaining=2,
                ),
            ),
            _valid(
                "accepted_terminal",
                "Seller accepts; negotiation reaches a terminal status",
                NegotiationRoundResponse(
                    negotiation_id="neg-001",
                    status=NegotiationStatus.ACCEPTED,
                    round=NegotiationRound(
                        round_number=2,
                        buyer_price=Money.from_decimal_str("22.00"),
                        seller_price=Money.from_decimal_str("22.00"),
                        action=NegotiationAction.ACCEPT,
                        cumulative_concession_pct=0.12,
                        timestamp=T1,
                    ),
                ),
            ),
        ],
    )

    rpc_request = JsonRpcRequest(
        id="req-001",
        params=MessageSendParams(
            message=A2AMessage(
                message_id="msg-001",
                parts=[A2APart(kind="text", text="What CTV inventory do you have?")],
            ),
            context_id="ctx-001",
        ),
    )
    docs["JsonRpcRequest"] = _doc(
        "protocol",
        "JsonRpcRequest",
        [
            _valid(
                "message_send_text",
                "A2A message/send with a text part (camelCase wire aliases)",
                rpc_request,
            ),
            _valid(
                "message_send_data",
                "A2A message/send carrying a structured data part",
                JsonRpcRequest(
                    id="req-002",
                    params=MessageSendParams(
                        message=A2AMessage(
                            message_id="msg-002",
                            parts=[
                                A2APart(
                                    kind="data",
                                    data={"quote_request": {"product_id": "prod-001"}},
                                )
                            ],
                        )
                    ),
                ),
            ),
            _must_ignore(
                "request_with_unknown_fields",
                "FD-13: unknown + x_ fields on the JSON-RPC envelope are ignored",
                rpc_request,
            ),
        ],
    )

    docs["JsonRpcResponse"] = _doc(
        "protocol",
        "JsonRpcResponse",
        [
            _valid(
                "result_response",
                "Successful message/send result",
                JsonRpcResponse(
                    id="req-001",
                    result=A2AResult(
                        task_id="task-001",
                        context_id="ctx-001",
                        parts=[A2APart(kind="text", text="We have 3 CTV packages.")],
                    ),
                ),
            ),
            _valid(
                "method_not_found_error",
                "-32601 for the retired seller 'call' dialect",
                JsonRpcResponse(
                    id="req-003",
                    error=JsonRpcError(
                        code=-32601,
                        message="Method not found: 'call' (use 'message/send')",
                    ),
                ),
            ),
            _invalid(
                "result_and_error_rejected",
                "Exactly one of result/error is required",
                {
                    "jsonrpc": "2.0",
                    "id": "req-004",
                    "result": {"taskId": "t", "contextId": "c", "role": "agent", "parts": []},
                    "error": {"code": -32601, "message": "nope"},
                },
                "exactly one of result/error",
            ),
        ],
    )

    docs["AgentDiscoveryRequest"] = _doc(
        "protocol",
        "AgentDiscoveryRequest",
        [
            _valid(
                "discover_seller",
                "Fetch and register a seller agent card by base URL",
                AgentDiscoveryRequest(agent_url="https://seller.example.com"),
            ),
            _valid(
                "discover_buyer",
                "Fetch and register a buyer agent card by base URL",
                AgentDiscoveryRequest(agent_url="https://buyer.example.com"),
            ),
        ],
    )

    docs["AgentTrustVerification"] = _doc(
        "protocol",
        "AgentTrustVerification",
        [
            _valid(
                "approved_by_registry",
                "Registry-verified approved agent",
                AgentTrustVerification(
                    agent_url="https://seller.example.com",
                    agent_id="agent-seller-1",
                    trust_status=TrustStatus.APPROVED,
                    registry_id="iab_aamp",
                    verified_at=T0,
                ),
            ),
            _valid(
                "unknown_unregistered",
                "Unregistered agent: trust stays unknown",
                AgentTrustVerification(agent_url="https://stranger.example.com"),
            ),
        ],
    )

    fd6_rejection = ErrorEnvelope(
        detail=ErrorDetail(
            error=ErrorCode.UNSUPPORTED_CAPABILITY,
            message="This seller does not transact linear TV inventory",
            unsupported=[
                UnsupportedItem(
                    capability="linear_tv",
                    path="$.media_type",
                    reason="linear_tv is not a supported media_type",
                )
            ],
        )
    )
    docs["ErrorEnvelope"] = _doc(
        "protocol",
        "ErrorEnvelope",
        [
            _valid(
                "fd6_linear_tv_rejection",
                "FD-6 structured rejection: unsupported_capability with the "
                "specific unsupported item",
                fd6_rejection,
            ),
            _valid(
                "validation_error",
                "Schema/business validation failure",
                ErrorEnvelope(
                    detail=ErrorDetail(
                        error=ErrorCode.VALIDATION,
                        message="impressions is required for PG deals",
                    )
                ),
            ),
            _valid(
                "idempotency_conflict",
                "FD-12: reused idempotency key with a different body",
                ErrorEnvelope(
                    detail=ErrorDetail(
                        error=ErrorCode.IDEMPOTENCY_CONFLICT,
                        message="idempotency_key was already used with a different request body",
                    )
                ),
            ),
            _must_ignore(
                "error_with_unknown_fields",
                "FD-13: unknown + x_ fields on the error envelope are ignored",
                fd6_rejection,
            ),
        ],
    )

    return docs


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def events_fixture_docs() -> dict[str, dict[str, Any]]:
    deal_booked = Event(
        event_id="evt-001",
        event_type=EventType.DEAL_BOOKED,
        occurred_at=T0,
        source_agent="buyer",
        deal_id="deal-001",
        order_id="ord-001",
        metadata={"final_cpm_micros": 22500000},
    )
    return {
        "Event": _doc(
            "events",
            "Event",
            [
                _valid("deal_booked", "Buyer-emitted booking event", deal_booked),
                _valid(
                    "negotiation_round",
                    "Seller-emitted negotiation round event",
                    Event(
                        event_id="evt-002",
                        event_type=EventType.NEGOTIATION_ROUND,
                        occurred_at=T1,
                        source_agent="seller",
                        proposal_id="prop-001",
                        session_id="sess-001",
                        metadata={"round_number": 1},
                    ),
                ),
                _must_ignore(
                    "event_with_unknown_fields",
                    "FD-13: unknown + x_ fields on an event are ignored",
                    deal_booked,
                ),
                _invalid(
                    "naive_timestamp_rejected",
                    "occurred_at must be timezone-aware UTC",
                    {
                        "event_id": "evt-bad",
                        "event_type": "deal.booked",
                        "occurred_at": "2026-07-01T12:00:00",
                        "source_agent": "buyer",
                    },
                    "timezone-aware",
                ),
            ],
        )
    }


# ---------------------------------------------------------------------------
# State transition sequences
# ---------------------------------------------------------------------------


def _seq(
    name: str,
    description: str,
    states: list[str],
    *,
    expect: str = "legal",
    fails_at: int | None = None,
) -> dict[str, Any]:
    seq: dict[str, Any] = {
        "name": name,
        "description": description,
        "expect": expect,
        "states": states,
    }
    if fails_at is not None:
        seq["fails_at"] = fails_at
    return seq


def state_fixture_docs() -> dict[str, dict[str, Any]]:
    return {
        "DealLifecycle": {
            "$comment": _GENERATED_NOTE,
            "area": "state",
            "machine": "deal",
            "spec_export": "spec/jsonschema/state/DealLifecycle.json",
            "sequences": [
                _seq(
                    "happy_path",
                    "Propose -> negotiate -> accept -> book -> deliver -> complete",
                    [
                        "proposed",
                        "negotiating",
                        "accepted",
                        "booked",
                        "active",
                        "completed",
                    ],
                ),
                _seq(
                    "makegood_cycle",
                    "Linear TV under-delivery: makegood_pending loops back to "
                    "active (rework edge), then completes",
                    [
                        "proposed",
                        "accepted",
                        "booked",
                        "active",
                        "makegood_pending",
                        "active",
                        "completed",
                    ],
                ),
                _seq(
                    "negotiation_rework_walkaway",
                    "Counter-offer re-propose loop, then a terminal walk-away",
                    ["proposed", "negotiating", "proposed", "negotiating", "rejected"],
                ),
                _seq(
                    "partial_cancellation",
                    "Booked units partially cancelled, remainder cancelled",
                    ["proposed", "accepted", "booked", "partially_cancelled", "cancelled"],
                ),
                _seq(
                    "terminal_completed_reopened",
                    "Terminal states have no outgoing transitions",
                    ["active", "completed", "active"],
                    expect="illegal",
                    fails_at=1,
                ),
                _seq(
                    "skip_acceptance",
                    "A proposed deal cannot book without acceptance",
                    ["proposed", "booked"],
                    expect="illegal",
                    fails_at=0,
                ),
                _seq(
                    "booked_back_to_negotiating",
                    "Booking is a commit point; no path back to negotiation",
                    ["accepted", "booked", "negotiating"],
                    expect="illegal",
                    fails_at=1,
                ),
            ],
        },
        "OrderLifecycle": {
            "$comment": _GENERATED_NOTE,
            "area": "state",
            "machine": "order",
            "spec_export": "spec/jsonschema/state/OrderLifecycle.json",
            "sequences": [
                _seq(
                    "human_approval_path",
                    "Draft -> submit -> human gate -> execute -> book -> complete",
                    [
                        "draft",
                        "submitted",
                        "pending_approval",
                        "approved",
                        "in_progress",
                        "booked",
                        "completed",
                    ],
                ),
                _seq(
                    "auto_approval_path",
                    "No human gate: submitted auto-approves",
                    ["draft", "submitted", "approved", "in_progress", "booked", "completed"],
                ),
                _seq(
                    "rejection_recovery",
                    "Rejected orders recover to draft (rework edge), then cancel",
                    ["draft", "submitted", "pending_approval", "rejected", "draft", "cancelled"],
                ),
                _seq(
                    "unbooked_recovery",
                    "Ad-server unbooking recovers to draft for resubmission",
                    ["in_progress", "booked", "unbooked", "draft", "submitted"],
                ),
                _seq(
                    "terminal_completed_reopened",
                    "completed is terminal; no path back to draft",
                    ["booked", "completed", "draft"],
                    expect="illegal",
                    fails_at=1,
                ),
                _seq(
                    "skip_execution",
                    "A draft order cannot book directly",
                    ["draft", "booked"],
                    expect="illegal",
                    fails_at=0,
                ),
            ],
        },
        "ChangeRequestLifecycle": {
            "$comment": _GENERATED_NOTE,
            "area": "state",
            "machine": "change_request",
            "spec_export": "spec/jsonschema/state/ChangeRequestLifecycle.json",
            "sequences": [
                _seq(
                    "minor_auto_approved",
                    "Minor severity: validating auto-approves, then applies",
                    ["pending", "validating", "approved", "applied"],
                ),
                _seq(
                    "material_human_rejected",
                    "Material severity routes to human review; reviewer rejects",
                    ["pending", "validating", "pending_approval", "rejected"],
                ),
                _seq(
                    "approved_apply_failed",
                    "Applying an approved change can fail (added edge)",
                    ["pending", "validating", "pending_approval", "approved", "failed"],
                ),
                _seq(
                    "terminal_applied_reopened",
                    "applied is terminal; no path back to pending",
                    ["pending", "validating", "approved", "applied", "pending"],
                    expect="illegal",
                    fails_at=3,
                ),
                _seq(
                    "skip_validation",
                    "A pending change request cannot approve without validating",
                    ["pending", "approved"],
                    expect="illegal",
                    fails_at=0,
                ),
            ],
        },
    }


# ---------------------------------------------------------------------------
# Document assembly + writer
# ---------------------------------------------------------------------------


def fixture_documents() -> dict[str, dict[str, Any]]:
    """Every fixture document, keyed by path relative to ``spec/fixtures/``."""
    docs: dict[str, dict[str, Any]] = {}
    for target, doc in primitive_fixture_docs().items():
        docs[f"primitives/{target}.golden.json"] = doc
    for target, doc in protocol_fixture_docs().items():
        docs[f"protocol/{target}.golden.json"] = doc
    for target, doc in events_fixture_docs().items():
        docs[f"events/{target}.golden.json"] = doc
    for stem, doc in state_fixture_docs().items():
        docs[f"state/{stem}.golden.json"] = doc
    return docs


def render_fixture(doc: dict[str, Any]) -> str:
    """Stable, diff-friendly rendering for checked-in fixture files."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_fixtures(fixtures_dir: Path) -> list[Path]:
    """Write every fixture document under ``fixtures_dir``; return the paths."""
    written: list[Path] = []
    for rel_path, doc in fixture_documents().items():
        path = fixtures_dir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_fixture(doc))
        written.append(path)
    return written


__all__ = [
    "MAX_SAFE_MICROS",
    "events_fixture_docs",
    "fixture_documents",
    "primitive_fixture_docs",
    "protocol_fixture_docs",
    "render_fixture",
    "state_fixture_docs",
    "write_fixtures",
]
