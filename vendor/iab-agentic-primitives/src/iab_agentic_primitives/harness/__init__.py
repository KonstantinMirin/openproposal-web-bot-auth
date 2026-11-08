"""In-process two-agent interop test harness (a shared DEV tool).

The buyer and seller repos each test their agent against a MOCK of the
counterparty. That is precisely why the cross-repo interop breaks stayed
invisible: a mock always agrees with you. This harness runs BOTH agents
against the ONE shared contract — the protocol envelopes
(:mod:`iab_agentic_primitives.protocol`), the primitives
(:mod:`iab_agentic_primitives.primitives`), the canonical state machines
(:mod:`iab_agentic_primitives.state`), and the real sandbox AAMP registry
(:mod:`iab_agentic_primitives.sandbox_registry`) — so a disagreement between
the two sides becomes a loud test failure instead of a silent production
incident.

What it gives you:

- :mod:`.roles` — the :class:`BuyerRole` / :class:`SellerRole` / :class:`SellerChannel`
  interfaces (canonical envelopes in and out; no free text on the money path)
  plus the :class:`CampaignBrief` input and tier helpers.
- :mod:`.reference_agents` — deterministic, LLM-free :class:`ReferenceBuyer`
  and :class:`ReferenceSeller`: the known-good agents to swap real agents
  against.
- :mod:`.scenario` — the in-process runner (:func:`run_scenario` /
  :func:`run_scenario_sync`) that wires N buyers x M sellers through the real
  registry and returns a structured :class:`TransactionResult`.
- :mod:`.assertions` — reusable interop assertions both agent repos' CI call.

The runner's registry legs use the ``client`` + ``sandbox`` extras (httpx +
fastapi); importing this package never requires them. See HARNESS.md for how
the rig (EP-11) and the two agent repos consume it.

AAMP = the IAB (Interactive Advertising Bureau) Tech Lab agent discovery and
trust registry; A2A = agent-to-agent protocol; CPM = cost per mille.
"""

from .assertions import (
    assert_auth_tier_enforced,
    assert_booking_has_seller_deal_id,
    assert_idempotent_booking,
    assert_negotiation_terminates,
    assert_no_field_dropped,
    assert_quote_roundtrips,
    assert_state_consistent,
    assert_structural_rejection,
)
from .reference_agents import (
    DEFAULT_NEGOTIATION_BAND_PER_MILLE,
    MAX_SELLER_ROUNDS,
    ReferenceBuyer,
    ReferenceSeller,
)
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
from .scenario import (
    BuyerParticipant,
    Exchange,
    InProcessSellerChannel,
    ScenarioResult,
    SellerParticipant,
    TransactionResult,
    run_scenario,
    run_scenario_sync,
)

__all__ = [
    "DEFAULT_NEGOTIATION_BAND_PER_MILLE",
    "MAX_SELLER_ROUNDS",
    "BuyerOutcome",
    "BuyerParticipant",
    "BuyerRole",
    "CampaignBrief",
    "Exchange",
    "InProcessSellerChannel",
    "ReferenceBuyer",
    "ReferenceSeller",
    "ScenarioResult",
    "SellerChannel",
    "SellerParticipant",
    "SellerRole",
    "TransactionResult",
    "assert_auth_tier_enforced",
    "assert_booking_has_seller_deal_id",
    "assert_idempotent_booking",
    "assert_negotiation_terminates",
    "assert_no_field_dropped",
    "assert_quote_roundtrips",
    "assert_state_consistent",
    "assert_structural_rejection",
    "cap_tier",
    "cpm_cost",
    "run_scenario",
    "run_scenario_sync",
    "tier_from_identity",
]
