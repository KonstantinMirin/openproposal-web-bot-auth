"""The ONE Agent Card discovery surface.

``GET /.well-known/agent.json`` serves the shared
:class:`~iab_agentic_primitives.primitives.Agent` primitive — exported
here as :data:`AgentCard` for protocol-level naming. The primitive is
imported, never redefined: there is exactly one card schema.

Reconciliation of the two incompatible card schemas:

- The seller's ``models/agent_registry.AgentCard`` (name/description/url/
  provider/typed ``AgentCapabilities`` object/``skills``/authentication/
  inventory_types/supported_deal_types) is the structural base — its
  ``capabilities`` was already a TYPED object (protocols/streaming/
  push_notifications), which the canonical card keeps.
- The buyer's ``registry/models.AgentCard`` modeled ``capabilities`` as a
  free list of named capability entries; those map to the card's
  ``skills`` list (:class:`~iab_agentic_primitives.primitives.AgentSkill`),
  not to the typed ``capabilities`` object.
- AAMP trust fields are kept ON the card record: ``trust_status``
  (:class:`~iab_agentic_primitives.primitives.TrustStatus`) is the
  registry-verified status — never self-asserted; a self-served card
  carries ``trust_status="unknown"`` and only a registry lookup
  (:class:`AgentTrustVerification`) upgrades it. The buyer's ``TrustLevel``
  value ``verified`` maps to ``approved``; the seller's vocabulary
  (unknown/registered/approved/preferred/blocked) is canonical.
- ``supported_deal_types`` uses the canonical DealType wire values
  ('PG'/'PD'/'PA'); the seller's lowercase ``pg``/``pmp``/
  ``preferred_deal``/``private_auction`` strings are retired.

AAMP = the IAB (Interactive Advertising Bureau) Tech Lab agent discovery
and trust registry. A2A = Agent-to-Agent protocol.
"""

from datetime import datetime

from pydantic import Field

from ..primitives import Agent, TrustStatus, WireModel

#: The canonical Agent Card IS the shared Agent primitive (one schema).
AgentCard = Agent


class AgentDiscoveryRequest(WireModel):
    """Request body for ``POST /registry/agents/discover``: fetch and
    register a counterparty's card by its base URL."""

    agent_url: str = Field(
        description="Base URL of the agent; its card is fetched from "
        "{agent_url}/.well-known/agent.json."
    )


class AgentTrustVerification(WireModel):
    """Registry-verified trust result for an agent (replaces the buyer's
    ``AgentTrustInfo``).

    ``is_registered`` is retired — it is derivable as
    ``trust_status != "unknown"``. Trust caps the effective access tier
    server-side; it is never self-asserted (see the Agent primitive).
    """

    agent_url: str
    agent_id: str | None = Field(
        default=None, description="Registry-issued agent id, when registered."
    )
    trust_status: TrustStatus = TrustStatus.UNKNOWN
    registry_id: str | None = Field(
        default=None,
        description='Registry that answered, e.g. "iab_aamp".',
    )
    verified_at: datetime | None = Field(
        default=None, description="Timezone-aware timestamp of the verification."
    )


__all__ = ["AgentCard", "AgentDiscoveryRequest", "AgentTrustVerification"]
