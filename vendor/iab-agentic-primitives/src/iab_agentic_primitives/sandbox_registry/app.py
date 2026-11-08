"""LEGACY EP-5.3 AAMP trust-tier sandbox (``/agents`` surface).

NOT the real registry and NOT the ``LOCAL`` backend target. This app
implements the EP-5.3 access-tier trust model (register a card, set a trust
status, read a tier ceiling) that the REAL agent-registry does not have. It
is retained ONLY for the EP-7.1 in-process interop harness, which is built
on those trust-tier semantics. For the real ``/api/agents`` API use the
docker-compose runner (SANDBOX_REGISTRY.md) or the test double in
:mod:`.real_double`.

Run it::

    uvicorn --factory iab_agentic_primitives.sandbox_registry.app:create_app --port 8020

Environment:

- ``AAMP_SANDBOX_SEED_PATH`` — optional seed JSON loaded at startup
- ``AAMP_SANDBOX_PERSIST_PATH`` — optional JSON file the store persists to

Endpoints (all typed against the shared protocol/primitives models, all
errors in the canonical :class:`ErrorEnvelope` shape):

- ``POST /agents`` — register an AgentCard (409 on duplicate id)
- ``GET /agents?agent_type=seller|buyer`` — discovery listing
- ``GET /agents/{agent_id}`` — card fetch
- ``GET /agents/{agent_id}/trust`` — TrustVerification (status + tier ceiling)
- ``PUT /agents/{agent_id}/trust`` — admin: set trust status / tier ceiling
"""

from __future__ import annotations

import os
from typing import NoReturn

from pydantic import Field

try:
    from fastapi import FastAPI, HTTPException
except ImportError as _exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The sandbox registry requires fastapi; install the 'sandbox' extra: "
        "pip install 'iab-agentic-primitives[sandbox]'"
    ) from _exc

from ..primitives import AccessTier, AgentType, TrustStatus, WireModel
from ..protocol import AgentCard
from ..protocol.errors import ErrorCode, ErrorDetail
from ..registry_client import TrustVerification
from .store import AgentStore, DuplicateAgentError, UnknownAgentError

ENV_SEED_PATH = "AAMP_SANDBOX_SEED_PATH"

#: registry_id stamped on every TrustVerification this sandbox answers.
SANDBOX_REGISTRY_ID = "local_sandbox"


class TrustUpdate(WireModel):
    """Admin request body for ``PUT /agents/{agent_id}/trust``."""

    trust_status: TrustStatus
    max_access_tier: AccessTier | None = Field(
        default=None,
        description="Explicit tier ceiling; omitted, the canonical ceiling "
        "for the new trust status applies.",
    )


def _error(status_code: int, code: ErrorCode, message: str) -> NoReturn:
    """Raise the canonical ErrorEnvelope shape via FastAPI's detail wrapping."""
    detail = ErrorDetail(error=code, message=message)
    raise HTTPException(status_code=status_code, detail=detail.model_dump(mode="json"))


def create_app(store: AgentStore | None = None, *, registry_id: str = SANDBOX_REGISTRY_ID):
    """Build the sandbox registry app.

    With no ``store``, one is created honoring ``AAMP_SANDBOX_PERSIST_PATH``
    and seeded from ``AAMP_SANDBOX_SEED_PATH`` when set.
    """
    if store is None:
        store = AgentStore()
        seed_path = os.environ.get(ENV_SEED_PATH)
        if seed_path:
            store.load_seed(seed_path)

    app = FastAPI(
        title="AAMP Local Sandbox Registry",
        description=(
            "Development stand-in for the IAB AAMP agent discovery and "
            "trust registry (owner decision FD-3)."
        ),
        version="0.1.0",
    )
    app.state.store = store

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "registry_id": registry_id}

    @app.post("/agents", response_model=AgentCard, status_code=201)
    def register_agent(card: AgentCard) -> AgentCard:
        try:
            return store.register(card)
        except DuplicateAgentError as exc:
            _error(409, ErrorCode.CONTENTION, str(exc))

    @app.get("/agents", response_model=list[AgentCard])
    def discover_agents(agent_type: AgentType | None = None) -> list[AgentCard]:
        return store.list_cards(agent_type)

    @app.get("/agents/{agent_id}", response_model=AgentCard)
    def fetch_card(agent_id: str) -> AgentCard:
        try:
            return store.get(agent_id).card
        except UnknownAgentError as exc:
            _error(404, ErrorCode.NOT_FOUND, str(exc))

    @app.get("/agents/{agent_id}/trust", response_model=TrustVerification)
    def verify_trust(agent_id: str) -> TrustVerification:
        try:
            return store.verification(agent_id, registry_id)
        except UnknownAgentError as exc:
            _error(404, ErrorCode.NOT_FOUND, str(exc))

    @app.put("/agents/{agent_id}/trust", response_model=TrustVerification)
    def set_trust(agent_id: str, update: TrustUpdate) -> TrustVerification:
        try:
            store.set_trust(agent_id, update.trust_status, update.max_access_tier)
        except UnknownAgentError as exc:
            _error(404, ErrorCode.NOT_FOUND, str(exc))
        return store.verification(agent_id, registry_id)

    return app


__all__ = ["SANDBOX_REGISTRY_ID", "TrustUpdate", "create_app"]
