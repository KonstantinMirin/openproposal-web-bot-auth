"""In-memory agent store for the local sandbox AAMP registry.

No database: records live in a dict, with optional JSON-file persistence
(``AAMP_SANDBOX_PERSIST_PATH`` or ``persist_path=``). The persistence
file uses the same shape as the seed file, so a persisted store can be
reused directly as seed data.

Seed / persistence JSON shape::

    {
      "agents": [
        {
          "card": { ...AgentCard... },
          "trust_status": "approved",        // optional; default "registered"
          "max_access_tier": "agency"        // optional; default = ceiling for status
        }
      ]
    }
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import Field

from ..primitives import AccessTier, AgentType, TrustStatus, WireModel, utc_now
from ..protocol import AgentCard
from ..registry_client import TRUST_TIER_CEILING, TrustVerification


class DuplicateAgentError(Exception):
    """Raised when registering an agent_id that is already registered."""

    def __init__(self, agent_id: str):
        super().__init__(f"agent {agent_id!r} is already registered")
        self.agent_id = agent_id


class UnknownAgentError(Exception):
    """Raised when an agent_id is not in the registry."""

    def __init__(self, agent_id: str):
        super().__init__(f"agent {agent_id!r} is not registered")
        self.agent_id = agent_id


class AgentRecord(WireModel):
    """One stored registration: the card plus its admin-set tier ceiling.

    ``card.trust_status`` is the authoritative registry-verified status;
    ``max_access_tier`` is the tier ceiling derived from it (or lowered
    explicitly by an admin).
    """

    card: AgentCard
    max_access_tier: AccessTier = AccessTier.PUBLIC


class SeedEntry(WireModel):
    """One agent in a seed file: a card plus optional trust overrides."""

    card: AgentCard
    trust_status: TrustStatus | None = None
    max_access_tier: AccessTier | None = None


class SeedFile(WireModel):
    """Top-level seed / persistence file shape."""

    agents: list[SeedEntry] = Field(default_factory=list)


class AgentStore:
    """In-memory registry store with optional JSON persistence.

    If ``persist_path`` (or env ``AAMP_SANDBOX_PERSIST_PATH``) is set, the
    store loads it at startup when the file exists and rewrites it after
    every mutation.
    """

    ENV_PERSIST_PATH = "AAMP_SANDBOX_PERSIST_PATH"

    def __init__(self, persist_path: str | Path | None = None):
        if persist_path is None:
            persist_path = os.environ.get(self.ENV_PERSIST_PATH) or None
        self._persist_path = Path(persist_path) if persist_path else None
        self._records: dict[str, AgentRecord] = {}
        if self._persist_path is not None and self._persist_path.exists():
            self.load_seed(self._persist_path)

    # -- registry operations ------------------------------------------------

    def register(self, card: AgentCard) -> AgentCard:
        """Store a card. The registry never trusts a self-asserted status:
        a fresh registration is always ``registered`` with the matching
        tier ceiling."""
        if card.agent_id in self._records:
            raise DuplicateAgentError(card.agent_id)
        stored = card.model_copy(update={"trust_status": TrustStatus.REGISTERED})
        self._records[card.agent_id] = AgentRecord(
            card=stored, max_access_tier=TRUST_TIER_CEILING[TrustStatus.REGISTERED]
        )
        self._persist()
        return stored

    def list_cards(self, agent_type: AgentType | None = None) -> list[AgentCard]:
        """Discovery listing. Blocked agents are excluded (they remain
        fetchable by id and answer trust checks as blocked)."""
        cards = [
            record.card
            for record in self._records.values()
            if record.card.trust_status is not TrustStatus.BLOCKED
        ]
        if agent_type is not None:
            cards = [card for card in cards if card.agent_type is agent_type]
        return cards

    def get(self, agent_id: str) -> AgentRecord:
        record = self._records.get(agent_id)
        if record is None:
            raise UnknownAgentError(agent_id)
        return record

    def set_trust(
        self,
        agent_id: str,
        trust_status: TrustStatus,
        max_access_tier: AccessTier | None = None,
    ) -> AgentRecord:
        """Admin: set an agent's trust status and (optionally) an explicit
        tier ceiling; omitted, the canonical ceiling for the status applies."""
        record = self.get(agent_id)
        updated = AgentRecord(
            card=record.card.model_copy(update={"trust_status": trust_status}),
            max_access_tier=(
                max_access_tier if max_access_tier is not None else TRUST_TIER_CEILING[trust_status]
            ),
        )
        self._records[agent_id] = updated
        self._persist()
        return updated

    def verification(self, agent_id: str, registry_id: str) -> TrustVerification:
        """Build the wire TrustVerification for an agent."""
        record = self.get(agent_id)
        return TrustVerification(
            agent_url=record.card.url,
            agent_id=agent_id,
            trust_status=record.card.trust_status,
            registry_id=registry_id,
            verified_at=utc_now(),
            max_access_tier=record.max_access_tier,
        )

    # -- seed data + persistence ---------------------------------------------

    def load_seed(self, path: str | Path) -> int:
        """Load agents from a seed JSON file; returns the number loaded.

        Seed entries default to ``registered`` (an agent present in the
        registry is at least registered) unless the entry or its card says
        otherwise; the tier ceiling defaults to the status's canonical one.
        """
        seed = SeedFile.model_validate(json.loads(Path(path).read_text()))
        for entry in seed.agents:
            status = entry.trust_status
            if status is None:
                status = entry.card.trust_status
                if status is TrustStatus.UNKNOWN:
                    status = TrustStatus.REGISTERED
            tier = (
                entry.max_access_tier
                if entry.max_access_tier is not None
                else TRUST_TIER_CEILING[status]
            )
            self._records[entry.card.agent_id] = AgentRecord(
                card=entry.card.model_copy(update={"trust_status": status}),
                max_access_tier=tier,
            )
        self._persist()
        return len(seed.agents)

    def snapshot(self) -> SeedFile:
        """Current store contents in seed-file shape."""
        return SeedFile(
            agents=[
                SeedEntry(
                    card=record.card,
                    trust_status=record.card.trust_status,
                    max_access_tier=record.max_access_tier,
                )
                for record in self._records.values()
            ]
        )

    def _persist(self) -> None:
        if self._persist_path is None:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        self._persist_path.write_text(self.snapshot().model_dump_json(indent=2))


__all__ = [
    "AgentRecord",
    "AgentStore",
    "DuplicateAgentError",
    "SeedEntry",
    "SeedFile",
    "UnknownAgentError",
]
