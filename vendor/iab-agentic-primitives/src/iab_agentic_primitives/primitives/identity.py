"""Identity wire primitives: Organization, Account, Agent, buyer identity, consent.

Reconciled from the buyer agent's ``models/opendirect.py`` /
``models/buyer_identity.py`` and the seller agent's ``models/core.py`` /
``models/agent_registry.py`` / ``models/buyer_identity.py``. See
RECONCILIATION.md at the repo root for the field-level audit trail.

Canonical wire encoding: snake_case field names, no camelCase or
squashed-lowercase aliases.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._util import WireModel

# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------


class OrganizationRole(str, Enum):
    """Role of an organization in the advertising ecosystem.

    - ``buyer``: purchases advertising, selects products, provides creatives
    - ``seller``: owns/controls inventory, approves creatives, executes delivery
    - ``agent``: negotiates on behalf of a buyer or seller
    - ``curator``: packages inventory (does not own or execute)
    - ``platform``: execution/infrastructure provider
    """

    BUYER = "buyer"
    SELLER = "seller"
    AGENT = "agent"
    CURATOR = "curator"
    PLATFORM = "platform"


class OrganizationStatus(str, Enum):
    """Status of an organization."""

    ACTIVE = "active"
    SUSPENDED = "suspended"


class Organization(WireModel):
    """Legal/commercial entity participating in the ecosystem.

    ID minting: ``organization_id`` is issued by the organization's system
    of record when it registers with the AAMP registry (the IAB Tech Lab
    agent discovery and trust registry; IAB = Interactive Advertising
    Bureau). Both agents treat it as an opaque identifier.
    """

    organization_id: str = Field(description="Registry-issued organization identifier.")
    name: str = Field(max_length=128)
    role: OrganizationRole
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    address: str | None = None
    contacts: list[dict[str, Any]] | None = None
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


class AccountStatus(str, Enum):
    """Status of a buyer-seller account relationship."""

    ACTIVE = "active"
    SUSPENDED = "suspended"


class Account(WireModel):
    """Commercial relationship between a specific buyer and seller organization.

    ID minting: ``account_id`` is seller-issued (the seller's system of
    record manages the commercial relationship, consistent with OpenDirect,
    the IAB direct-buying API standard, where the publisher API mints
    resource identifiers).
    """

    account_id: str = Field(description="Seller-issued account identifier.")
    buyer_organization_id: str = Field(description="Registry-issued id of the buying organization.")
    seller_organization_id: str = Field(
        description="Registry-issued id of the selling organization."
    )
    advertiser_id: str | None = Field(
        default=None,
        description="Optional advertiser this account transacts for (buyer-supplied).",
    )
    name: str | None = Field(default=None, max_length=128)
    status: AccountStatus = AccountStatus.ACTIVE
    ext: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Buyer identity + access tiers
# ---------------------------------------------------------------------------


class AccessTier(str, Enum):
    """Access tier for tiered pricing, derived from revealed buyer identity.

    - ``public``: no identity — price ranges only
    - ``seat``: authenticated DSP (demand-side platform) seat
    - ``agency``: agency identity revealed
    - ``advertiser``: advertiser identity revealed (best rates)
    """

    PUBLIC = "public"
    SEAT = "seat"
    AGENCY = "agency"
    ADVERTISER = "advertiser"


class BuyerIdentity(WireModel):
    """Buyer identity revealed progressively to unlock better pricing.

    Superset of the buyer repo's ``BuyerIdentity`` and the seller repo's
    ``BuyerIdentity``/``QuoteBuyerIdentity``; every field is optional so a
    partially revealed identity is always representable. The tier derived
    from these fields is capped server-side by the registry-verified trust
    status of the calling agent — it is never self-asserted.
    """

    seat_id: str | None = Field(default=None, description="DSP seat identifier.")
    seat_name: str | None = Field(default=None, description="DSP platform display name.")
    dsp_platform: str | None = Field(
        default=None, description="DSP platform slug (e.g. 'ttd', 'dv360')."
    )
    agency_id: str | None = None
    agency_name: str | None = None
    agency_holding_company: str | None = None
    advertiser_id: str | None = None
    advertiser_name: str | None = None
    advertiser_industry: str | None = None
    campaign_id: str | None = Field(
        default=None, description="Optional campaign scope for campaign-specific deals."
    )
    campaign_name: str | None = None


# ---------------------------------------------------------------------------
# Agent (A2A agent card + registry identity)
# ---------------------------------------------------------------------------


class AgentType(str, Enum):
    """Type of agent in the registry."""

    BUYER = "buyer"
    SELLER = "seller"
    TOOL_PROVIDER = "tool_provider"
    DATA_PROVIDER = "data_provider"
    OTHER = "other"


class TrustStatus(str, Enum):
    """Registry-verified trust status of an agent.

    Determines the maximum :class:`AccessTier` an agent can claim. Per the
    remediation plan's registry-native corollary, trust is verified against
    the AAMP registry (the IAB Tech Lab agent discovery and trust registry),
    never self-asserted.
    """

    UNKNOWN = "unknown"
    REGISTERED = "registered"
    APPROVED = "approved"
    PREFERRED = "preferred"
    BLOCKED = "blocked"


class AgentSkill(WireModel):
    """A declared capability of an agent."""

    id: str
    name: str
    description: str
    tags: list[str] = Field(default_factory=list)


class AgentProvider(WireModel):
    """Organization operating the agent."""

    name: str
    url: str | None = None
    description: str | None = None


class AgentAuthentication(WireModel):
    """Authentication requirements for interacting with an agent."""

    schemes: list[str] = Field(default_factory=lambda: ["api_key"])
    credentials_url: str | None = None


class AgentCapabilities(WireModel):
    """Protocol and feature capabilities of an agent."""

    protocols: list[str] = Field(default_factory=lambda: ["a2a"])
    streaming: bool = False
    push_notifications: bool = False


class Agent(WireModel):
    """An advertising agent: A2A (agent-to-agent protocol) card plus registry identity.

    Unifies the seller repo's ``AgentCard`` and ``RegisteredAgent`` (the
    buyer repo shipped an incompatible card schema; this model is the single
    replacement for both).

    ID minting: ``agent_id`` is issued by the AAMP registry (the IAB Tech
    Lab agent discovery and trust registry) when the agent registers.
    """

    agent_id: str = Field(description="Registry-issued agent identifier.")
    name: str
    description: str
    url: str = Field(description="A2A service endpoint.")
    version: str = "1.0.0"
    agent_type: AgentType = AgentType.BUYER
    provider: AgentProvider
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    skills: list[AgentSkill] = Field(default_factory=list)
    authentication: AgentAuthentication = Field(default_factory=AgentAuthentication)
    organization_id: str | None = Field(
        default=None, description="Registry-issued id of the operating organization."
    )
    inventory_types: list[str] = Field(default_factory=list)
    supported_deal_types: list[str] = Field(
        default_factory=list,
        description=(
            "DealType wire values the agent supports: 'PG' (Programmatic "
            "Guaranteed), 'PD' (Preferred Deal), 'PA' (Private Auction)."
        ),
    )
    trust_status: TrustStatus = Field(
        default=TrustStatus.UNKNOWN,
        description=(
            "Registry-verified trust status. Caps the effective AccessTier; "
            "never self-asserted by the agent."
        ),
    )
    audience_capabilities: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Audience capability discovery block. Kept as an open object "
            "here; the typed model lands with the audience-plan bead."
        ),
    )
    contact: str | None = None
    tos_url: str | None = Field(default=None, description="Terms-of-service URL.")


# ---------------------------------------------------------------------------
# ConsentContext (FD-10 placeholder — minimal fields, full build-out later)
# ---------------------------------------------------------------------------


class DiligenceStatus(str, Enum):
    """Status of counterparty privacy diligence (IAB Diligence Platform)."""

    UNKNOWN = "unknown"
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"


class ConsentContext(WireModel):
    """Privacy consent signals that travel with a deal (flagged decision FD-10).

    Full build-out (EP-10.4) of the EP-1.2 placeholder: the three
    interoperable consent-string carriers — GPP (Global Privacy Platform)
    with its applicable section ids, TCF (Transparency & Consent Framework)
    with the ``gdpr_applies`` gate, and the US Privacy (``us_privacy``)
    string — plus the SGP (SafeGuard Privacy / IAB Diligence Platform)
    ``diligence_status``. Field names from the EP-1.2 placeholder are kept
    unchanged for backward compatibility; the build-out is purely additive.
    It travels with the Deal, Quote, and Order. Strings are carried opaque:
    no decoding/vendor-list validation is claimed (see the conformance
    standards registry).
    """

    applicable_regimes: list[str] = Field(
        default_factory=list,
        description="Privacy regime identifiers in scope (e.g. 'GDPR', 'CCPA').",
    )
    gpp_string: str | None = Field(
        default=None, description="GPP (Global Privacy Platform) consent string."
    )
    gpp_section_ids: list[int] = Field(
        default_factory=list, description="GPP section ids present in the string."
    )
    tcf_string: str | None = Field(
        default=None,
        description="TCF (Transparency & Consent Framework) TC string, when GDPR applies.",
    )
    gdpr_applies: bool | None = Field(
        default=None,
        description="Whether GDPR (EU General Data Protection Regulation) applies to this "
        "context; None when undetermined. Gates interpretation of the TCF string.",
    )
    us_privacy: str | None = Field(
        default=None,
        description="US Privacy (CCPA) string, e.g. '1YNN'; superseded by GPP where present.",
    )
    diligence_status: DiligenceStatus = Field(
        default=DiligenceStatus.UNKNOWN,
        description="Counterparty diligence status (SGP = SafeGuard Privacy / "
        "IAB Diligence Platform).",
    )
    verified_at: datetime | None = Field(
        default=None,
        description="Timezone-aware timestamp of the last diligence verification, if any.",
    )


__all__ = [
    "Account",
    "AccountStatus",
    "AccessTier",
    "Agent",
    "AgentAuthentication",
    "AgentCapabilities",
    "AgentProvider",
    "AgentSkill",
    "AgentType",
    "BuyerIdentity",
    "ConsentContext",
    "DiligenceStatus",
    "Organization",
    "OrganizationRole",
    "OrganizationStatus",
    "TrustStatus",
]
