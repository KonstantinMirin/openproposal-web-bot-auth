"""Registry dev/test doubles for the REAL agent-registry API.

The ``LOCAL`` backend of
:class:`iab_agentic_primitives.registry_client.RegistryClient` points at the
REAL Node registry (github.com/IABTechLab/agent-registry) run via the
docker-compose runner documented in SANDBOX_REGISTRY.md — that is the
authoritative local target, not a Python reimplementation.

Two in-process pieces live here:

- :func:`create_registry_double` (:mod:`.real_double`) — a MINIMAL,
  clearly-labeled TEST DOUBLE of the real ``/api/agents`` API, for
  unit-testing the client offline where Docker is unavailable.
- :func:`create_app` + :class:`AgentStore` (:mod:`.app` / :mod:`.store`) —
  the LEGACY EP-5.3 AAMP trust-tier sandbox (``/agents`` paths, an
  access-tier trust model the real registry does not have). It is retained
  ONLY because the EP-7.1 in-process interop harness still models those
  trust-tier semantics; it is not a stand-in for the real registry. New
  code should target the real ``/api/agents`` surface.

Importing this package does not require fastapi — the app factories are
loaded lazily.
"""

from typing import Any

from .store import (
    AgentRecord,
    AgentStore,
    DuplicateAgentError,
    SeedEntry,
    SeedFile,
    UnknownAgentError,
)

__all__ = [
    "AgentRecord",
    "AgentStore",
    "DuplicateAgentError",
    "SeedEntry",
    "SeedFile",
    "UnknownAgentError",
    "create_app",
    "create_registry_double",
]


def __getattr__(name: str) -> Any:
    # lazy: keeps `import ...sandbox_registry` fastapi-free
    if name == "create_app":
        from .app import create_app

        return create_app
    if name == "create_registry_double":
        from .real_double import create_registry_double

        return create_registry_double
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
