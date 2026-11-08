"""The ONE AAMP registry client — swapping registries is config, not code.

AAMP (Agentic Advertising Marketplace Protocol — this project's umbrella
name for the IAB Tech Lab agent discovery + trust flow) is how agents find
counterparties and verify their trust status. The REAL registry is the
Node.js service at github.com/IABTechLab/agent-registry (prod:
https://registry.iabtechlab.com); this client speaks its actual HTTP API.

Acronyms: JWT = JSON Web Token; OAuth = Open Authorization; IAB =
Interactive Advertising Bureau; A2A = Agent-to-Agent protocol; MCP = Model
Context Protocol; SVG = Scalable Vector Graphics.

Verified against the real registry (routes/agents.js, middleware/auth.js):

- Base path is ``/api/agents`` (NOT ``/agents``).
- Auth is a JWT sent as ``Authorization: Bearer <token>`` (HS256, issuer
  "IAB"). The registry proxies login to IAB OAuth
  (``POST /api/auth/login`` → ``api.iabtechlab.com/oauth/authmobile``);
  this client does not log in for you — you supply an already-issued token.
- The registry may hand back a refreshed token in the ``X-New-Token``
  response header; this client honors it by updating its stored token.
- Success responses are enveloped: ``{"success": true, "data": ...}``.
  A list comes back as ``{"data": {"agents": [...], "count": N, ...}}``.
- Errors are ``{"success": false, "error": "<message>"}`` with the HTTP
  status carrying the machine meaning; this client maps them onto the
  shared :class:`ErrorCode` vocabulary and raises structured
  :class:`RegistryError`.

Backend selection stays config-driven — pointing an agent at the IAB
registry is a configuration change only:

- ``AAMP_REGISTRY_BACKEND`` — one of ``LOCAL`` (default), ``IAB_SANDBOX``,
  ``IAB_PROD`` (the legacy value ``LOCAL_SANDBOX`` is still accepted as an
  alias for ``LOCAL``).
- ``AAMP_REGISTRY_URL`` — registry base URL. Defaults to
  ``http://127.0.0.1:3001`` for ``LOCAL`` (the port the real Node app binds
  in the docker-compose runner) and ``https://registry.iabtechlab.com`` for
  ``IAB_PROD``; required explicitly for ``IAB_SANDBOX``.
- ``AAMP_REGISTRY_TOKEN`` — bearer JWT, sent as ``Authorization: Bearer
  <token>`` (legacy name ``AAMP_REGISTRY_AUTH_TOKEN`` is still accepted).

Requires ``httpx`` — install the ``client`` extra:
``pip install 'iab-agentic-primitives[client]'``.
"""

from __future__ import annotations

import os
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from .primitives import AccessTier, AgentType, TrustStatus, WireModel, utc_now
from .protocol import AgentCard, AgentTrustVerification
from .protocol.errors import ErrorCode, ErrorDetail, ErrorEnvelope

try:  # httpx is the 'client' optional extra; models above stay importable without it.
    import httpx
except ImportError:  # pragma: no cover - exercised only without the extra
    httpx = None  # type: ignore[assignment]

ENV_BACKEND = "AAMP_REGISTRY_BACKEND"
ENV_URL = "AAMP_REGISTRY_URL"
ENV_TOKEN = "AAMP_REGISTRY_TOKEN"
#: Retired env name still honored so existing deployments keep working.
ENV_TOKEN_LEGACY = "AAMP_REGISTRY_AUTH_TOKEN"

#: Default base URL for the LOCAL backend: the port the real agent-registry
#: Node app binds in the docker-compose runner (see SANDBOX_REGISTRY.md).
LOCAL_DEFAULT_URL = "http://127.0.0.1:3001"
#: Retained alias for the EP-5.3 name.
LOCAL_SANDBOX_DEFAULT_URL = LOCAL_DEFAULT_URL
#: Known production URL for the IAB_PROD backend.
IAB_PROD_DEFAULT_URL = "https://registry.iabtechlab.com"

#: Response header the registry uses to hand back a refreshed JWT.
NEW_TOKEN_HEADER = "X-New-Token"

#: Base path for the agent routes on the real registry.
API_AGENTS = "/api/agents"

#: Maximum AccessTier an agent may claim per registry-verified TrustStatus.
#: Trust caps the effective tier server-side; it is never self-asserted.
#: (Legacy AAMP trust-tier model; retained for the EP-7.1 harness — see the
#: "legacy trust-tier surface" note below.)
TRUST_TIER_CEILING: dict[TrustStatus, AccessTier] = {
    TrustStatus.UNKNOWN: AccessTier.PUBLIC,
    TrustStatus.REGISTERED: AccessTier.SEAT,
    TrustStatus.APPROVED: AccessTier.AGENCY,
    TrustStatus.PREFERRED: AccessTier.ADVERTISER,
    TrustStatus.BLOCKED: AccessTier.PUBLIC,
}


class RegistryBackend(str, Enum):
    """Which registry deployment the client talks to.

    All speak the same HTTP protocol; only the base URL (and, for the
    ``IAB_*`` backends, the auth token) differs — the swap is config.
    """

    LOCAL = "LOCAL"
    IAB_SANDBOX = "IAB_SANDBOX"
    IAB_PROD = "IAB_PROD"


#: Retired backend value → canonical replacement.
_BACKEND_ALIASES = {"LOCAL_SANDBOX": RegistryBackend.LOCAL}


# ---------------------------------------------------------------------------
# Real agent-registry wire shapes
# ---------------------------------------------------------------------------


class RegistryAgent(WireModel):
    """An agent record as the REAL agent-registry stores and returns it.

    This mirrors the Node registry's agent shape (routes/agents.js +
    database columns), which diverges sharply from this library's
    :class:`~iab_agentic_primitives.primitives.Agent` card — see the
    field-by-field alignment table in SANDBOX_REGISTRY.md. Every field is
    optional except the two the registry requires at registration
    (``agent_name`` + ``primary_domain``) so a partial record round-trips;
    unknown fields are ignored (:class:`WireModel` forward-compat rule).

    Trust in the real registry is NOT the AAMP trust-tier enum; it is the
    triplet ``verification_status`` (``active``/``pending``) +
    ``domain_verified`` + ``iab_member`` (see :class:`VerifiedTrust`).
    """

    id: int | None = Field(default=None, description="Registry-issued integer id.")
    agent_name: str = Field(description="Human-readable agent name (required at register).")
    primary_domain: str = Field(description="Owning company domain (required at register).")
    # 'local' agents carry repository_url; 'remote'/'private' carry endpoint_url.
    type: str | None = Field(default=None, description="'local' | 'remote' | 'private'.")
    endpoint_url: str | None = Field(default=None, description="A2A/MCP service endpoint.")
    repository_url: str | None = None
    protocol_type: str | None = Field(default=None, description="'a2a' | 'mcp'.")
    transport_type: str | None = None
    a2a_version: str | None = None
    description: str | None = None
    legal_name: str | None = None
    gpp_id: int | None = Field(default=None, description="Global Privacy Platform vendor id.")
    gpp_verified: bool | None = None
    capabilities: list[str] = Field(default_factory=list)
    industry_roles: list[str] = Field(default_factory=list)
    certifications: list[str] = Field(default_factory=list)
    # Verification / trust triplet.
    verification_status: str | None = Field(default=None, description="'active' | 'pending'.")
    domain_verified: bool | None = None
    endpoint_health_verified: bool | None = None
    verification_method: str | None = None
    verification_token: str | None = None
    iab_member: bool | None = Field(
        default=None, description="Admin-set; drives the verification badge."
    )
    auth_required: bool | None = None
    # IAB Tech Lab taxonomy block.
    category: str | None = None
    iab_subcategories: list[str] = Field(default_factory=list)
    iab_capabilities: list[str] = Field(default_factory=list)
    endorsements: list[Any] = Field(default_factory=list)
    status: str | None = Field(default=None, description="Maturity: alpha/beta/ga/deprecated.")
    contact_email: str | None = None
    contact_website: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    verified_at: datetime | None = None


class VerifiedTrust(WireModel):
    """A trust verdict for an agent, derived from the REAL registry.

    The real registry has no AAMP trust-tier enum; ``verify_trust`` maps its
    signals to this result: ``verified`` is true when the registry marks the
    agent ``verification_status == "active"``; ``badge_available`` reflects
    the public ``/verification-badge`` endpoint (an SVG served only for IAB
    members). Consumers gate counterparty trust on ``verified`` and, for the
    IAB-member seal, ``badge_available``/``iab_member``.
    """

    agent_id: int | str
    verified: bool = Field(description="verification_status == 'active'.")
    verification_status: str | None = None
    domain_verified: bool = False
    iab_member: bool = False
    badge_available: bool = Field(
        default=False, description="The public verification-badge endpoint returned an SVG."
    )
    registry_id: str | None = Field(default=None, description="Which registry answered.")
    checked_at: datetime = Field(default_factory=utc_now)


class DomainValidation(WireModel):
    """Result of ``POST /api/agents/validate/domain`` (public endpoint)."""

    domain: str
    registered: bool = False
    verified: bool = False
    verification_method: str | None = None
    agent: dict[str, Any] | None = None
    instructions: dict[str, Any] | None = None


class AgentAuthorization(WireModel):
    """Result of ``POST /api/agents/validate/agent`` (public endpoint).

    Whether a publisher domain authorizes a given agent URL, per the
    publisher's ``/.well-known/authorized-agents.txt`` file.
    """

    authorized: bool = False
    domain: str
    agent_url: str
    agent_in_registry: bool = False
    agent_info: dict[str, Any] | None = None
    message: str | None = None


class RegistryError(Exception):
    """A structured protocol error returned by the registry.

    Carries the canonical :class:`ErrorDetail` (parsed from the shared
    :class:`ErrorEnvelope` when present, otherwise synthesized from the real
    registry's ``{"success": false, "error": ...}`` body), plus the HTTP
    status code.
    """

    def __init__(self, status_code: int, detail: ErrorDetail):
        super().__init__(f"[{status_code}] {detail.error.value}: {detail.message}")
        self.status_code = status_code
        self.detail = detail

    @property
    def code(self) -> ErrorCode:
        return self.detail.error


_FALLBACK_CODES: dict[int, ErrorCode] = {
    400: ErrorCode.VALIDATION,
    401: ErrorCode.UNAUTHORIZED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    409: ErrorCode.CONTENTION,
    410: ErrorCode.QUOTE_EXPIRED,
    422: ErrorCode.VALIDATION,
    500: ErrorCode.INTERNAL,
}


class TrustVerification(AgentTrustVerification):
    """LEGACY AAMP trust-tier result (EP-5.3), retained for the harness.

    :class:`AgentTrustVerification` plus the derived access-tier ceiling.
    The REAL registry does not model access tiers; this type backs the
    legacy trust-tier surface below (see :class:`VerifiedTrust` for the
    real trust verdict). ``max_access_tier`` is the highest
    :class:`AccessTier` an agent may be granted given its (legacy) trust
    status (see :data:`TRUST_TIER_CEILING`).
    """

    max_access_tier: AccessTier = Field(
        default=AccessTier.PUBLIC,
        description="Highest AccessTier the agent may be granted; registry-enforced.",
    )


class RegistryClient:
    """Async HTTP client for the REAL agent-registry API.

    One class for every backend: construct it with no arguments and it
    resolves ``AAMP_REGISTRY_BACKEND`` / ``AAMP_REGISTRY_URL`` /
    ``AAMP_REGISTRY_TOKEN`` from the environment. Explicit keyword arguments
    override the environment.

    Auth is a JWT bearer token; the client refreshes its stored token
    automatically whenever the registry returns one in the ``X-New-Token``
    response header.

    ``transport`` accepts any ``httpx`` transport — pass
    ``httpx.ASGITransport(app=...)`` to drive an in-process app (the real
    registry test-double, or the legacy sandbox) without a socket, exactly
    as the test suite does.
    """

    def __init__(
        self,
        backend: RegistryBackend | str | None = None,
        base_url: str | None = None,
        auth_token: str | None = None,
        *,
        transport: Any = None,
        timeout: float = 10.0,
    ):
        if httpx is None:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "RegistryClient requires httpx; install the 'client' extra: "
                "pip install 'iab-agentic-primitives[client]'"
            )
        self.backend = self._resolve_backend(backend)

        base_url = base_url or os.environ.get(ENV_URL)
        if not base_url:
            if self.backend is RegistryBackend.LOCAL:
                base_url = LOCAL_DEFAULT_URL
            elif self.backend is RegistryBackend.IAB_PROD:
                base_url = IAB_PROD_DEFAULT_URL
            else:
                raise ValueError(
                    f"{ENV_URL} (or base_url=) must be set for backend "
                    f"{self.backend.value}: the IAB sandbox registry has no default URL yet"
                )
        self.base_url = base_url.rstrip("/")

        if auth_token is None:
            auth_token = os.environ.get(ENV_TOKEN) or os.environ.get(ENV_TOKEN_LEGACY)
        self._token = auth_token
        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        self._http = httpx.AsyncClient(
            base_url=self.base_url, headers=headers, timeout=timeout, transport=transport
        )

    @staticmethod
    def _resolve_backend(backend: RegistryBackend | str | None) -> RegistryBackend:
        raw = backend or os.environ.get(ENV_BACKEND) or RegistryBackend.LOCAL
        if isinstance(raw, RegistryBackend):
            return raw
        key = str(raw).upper()
        if key in _BACKEND_ALIASES:
            return _BACKEND_ALIASES[key]
        try:
            return RegistryBackend(key)
        except ValueError:
            valid = ", ".join(b.value for b in RegistryBackend)
            raise ValueError(
                f"Unknown AAMP registry backend {raw!r}; expected one of: {valid}"
            ) from None

    @property
    def token(self) -> str | None:
        """The bearer token currently in use (updated on X-New-Token refresh)."""
        return self._token

    # -- REAL registry surface (/api/agents) -------------------------------

    async def register_agent(self, agent: RegistryAgent | dict[str, Any]) -> RegistryAgent:
        """Register an agent (``POST /api/agents``, authenticated).

        Takes a :class:`RegistryAgent` (or an equivalent dict). The
        registry requires ``agent_name`` + ``primary_domain`` and, for
        non-local agents, ``endpoint_url``; it verifies the caller's JWT
        company domain matches ``primary_domain``. Returns the stored record
        parsed from the response envelope's ``data``.
        """
        if isinstance(agent, RegistryAgent):
            body = agent.model_dump(mode="json", exclude_none=True)
        else:
            body = dict(agent)
        response = await self._request("POST", API_AGENTS, json=body)
        return RegistryAgent.model_validate(self._data(response))

    async def list_agents(self, **filters: Any) -> list[RegistryAgent]:
        """List agents (``GET /api/agents``, authenticated).

        Pass any of the registry's filters as keyword args
        (``protocol_type``, ``verification_status``, ``verified``,
        ``primary_domain``, ``category``, ``status``, ``search``,
        ``limit``, ...); ``None`` values are dropped. Returns the ``agents``
        array from the response envelope.
        """
        params = {k: _param(v) for k, v in filters.items() if v is not None}
        response = await self._request("GET", API_AGENTS, params=params)
        data = self._data(response)
        agents = data.get("agents", data) if isinstance(data, dict) else data
        return [RegistryAgent.model_validate(item) for item in agents]

    async def get_agent(self, agent_id: int | str) -> RegistryAgent:
        """Fetch one agent by registry id (``GET /api/agents/:id``, authenticated)."""
        response = await self._request("GET", f"{API_AGENTS}/{agent_id}")
        return RegistryAgent.model_validate(self._data(response))

    async def update_agent(self, agent_id: int | str, **fields: Any) -> RegistryAgent:
        """Update an agent (``PUT /api/agents/:id``, ADMIN only)."""
        response = await self._request("PUT", f"{API_AGENTS}/{agent_id}", json=fields)
        return RegistryAgent.model_validate(self._data(response))

    async def delete_agent(self, agent_id: int | str) -> None:
        """Delete an agent (``DELETE /api/agents/:id``, ADMIN only)."""
        await self._request("DELETE", f"{API_AGENTS}/{agent_id}")

    async def verify_health(self, agent_id: int | str) -> dict[str, Any]:
        """Trigger an endpoint health check (``POST /api/agents/:id/verify-health``, ADMIN)."""
        response = await self._request("POST", f"{API_AGENTS}/{agent_id}/verify-health")
        return self._data(response)

    async def validate_domain(self, domain: str) -> DomainValidation:
        """Validate domain ownership (``POST /api/agents/validate/domain``, public)."""
        response = await self._request(
            "POST", f"{API_AGENTS}/validate/domain", json={"domain": domain}
        )
        payload = response.json()
        return DomainValidation.model_validate(payload)

    async def validate_agent(self, domain: str, agent_url: str) -> AgentAuthorization:
        """Check publisher authorization for an agent (``POST /api/agents/validate/agent``)."""
        response = await self._request(
            "POST", f"{API_AGENTS}/validate/agent", json={"domain": domain, "agent_url": agent_url}
        )
        return AgentAuthorization.model_validate(response.json())

    async def verification_badge(self, agent_id: int | str) -> bytes | None:
        """Fetch the SVG verification badge (``GET /api/agents/:id/verification-badge``).

        Public endpoint; returns the SVG bytes for IAB members, or ``None``
        when the registry has no badge for the agent (404).
        """
        try:
            response = await self._request("GET", f"{API_AGENTS}/{agent_id}/verification-badge")
        except RegistryError as exc:
            if exc.status_code == 404:
                return None
            raise
        return response.content

    async def verified_trust(self, agent_id: int | str) -> VerifiedTrust:
        """Registry-verified trust verdict for an agent (:class:`VerifiedTrust`).

        This is the REAL ``/api/agents`` trust check (what EP-5.4 calls
        "verify_trust" — the method name ``verify_trust`` itself is held by
        the legacy trust-tier surface the EP-7.1 harness still calls, see the
        deviation note in SANDBOX_REGISTRY.md). It maps the real registry's
        signals to a single verdict: reads the agent record for
        ``verification_status`` / ``domain_verified`` / ``iab_member`` and
        probes the public verification-badge endpoint.
        """
        agent = await self.get_agent(agent_id)
        badge = await self.verification_badge(agent_id)
        return VerifiedTrust(
            agent_id=agent.id if agent.id is not None else agent_id,
            verified=agent.verification_status == "active",
            verification_status=agent.verification_status,
            domain_verified=bool(agent.domain_verified),
            iab_member=bool(agent.iab_member),
            badge_available=badge is not None,
            registry_id=self.backend.value,
        )

    # -- LEGACY AAMP trust-tier surface (EP-5.3) ---------------------------
    #
    # The EP-7.1 in-process interop harness (:mod:`...harness.scenario`)
    # models an AAMP trust-tier registry (register a card, set a trust
    # status, discover trusted counterparties, read an access-tier ceiling)
    # that the REAL registry does not implement. These methods speak the
    # EP-5.3 ``/agents`` protocol against the in-process legacy sandbox app
    # (:mod:`...sandbox_registry`) and are retained ONLY for that harness
    # until it migrates to the real trust signals. New code should use the
    # ``/api/agents`` surface above.

    async def register(self, card: AgentCard) -> AgentCard:
        """LEGACY: register an :class:`AgentCard` against the trust-tier sandbox."""
        response = await self._request("POST", "/agents", json=card.model_dump(mode="json"))
        return AgentCard.model_validate(response.json())

    async def discover(self, agent_type: AgentType | str | None = None) -> list[AgentCard]:
        """LEGACY: list trust-tier sandbox cards, optionally filtered by type."""
        params: dict[str, str] = {}
        if agent_type is not None:
            value = agent_type.value if isinstance(agent_type, AgentType) else str(agent_type)
            params["agent_type"] = value
        response = await self._request("GET", "/agents", params=params)
        return [AgentCard.model_validate(item) for item in response.json()]

    async def fetch_card(self, agent_id: str) -> AgentCard:
        """LEGACY: fetch a single trust-tier sandbox card by id."""
        response = await self._request("GET", f"/agents/{agent_id}")
        return AgentCard.model_validate(response.json())

    async def verify_trust(self, agent_id: str) -> TrustVerification:
        """LEGACY: AAMP trust status + access-tier ceiling for a sandbox agent.

        Retained under this name for the EP-7.1 harness; the REAL registry
        trust verdict is :meth:`verified_trust`.
        """
        response = await self._request("GET", f"/agents/{agent_id}/trust")
        return TrustVerification.model_validate(response.json())

    async def set_trust(
        self,
        agent_id: str,
        trust_status: TrustStatus,
        max_access_tier: AccessTier | None = None,
    ) -> TrustVerification:
        """LEGACY admin convenience: set a sandbox agent's AAMP trust status."""
        body: dict[str, Any] = {"trust_status": trust_status.value}
        if max_access_tier is not None:
            body["max_access_tier"] = max_access_tier.value
        response = await self._request("PUT", f"/agents/{agent_id}/trust", json=body)
        return TrustVerification.model_validate(response.json())

    # -- plumbing -----------------------------------------------------------

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Issue a request, honor an X-New-Token refresh, and raise on error."""
        response = await self._http.request(method, url, **kwargs)
        self._absorb_new_token(response)
        self._raise_for_error(response)
        return response

    def _absorb_new_token(self, response: httpx.Response) -> None:
        new_token = response.headers.get(NEW_TOKEN_HEADER)
        if new_token and new_token != self._token:
            self._token = new_token
            self._http.headers["Authorization"] = f"Bearer {new_token}"

    @staticmethod
    def _data(response: httpx.Response) -> Any:
        """Unwrap the ``data`` field from a registry success envelope."""
        payload = response.json()
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    def _raise_for_error(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        detail = self._parse_error(response)
        raise RegistryError(response.status_code, detail)

    @staticmethod
    def _parse_error(response: httpx.Response) -> ErrorDetail:
        code = _FALLBACK_CODES.get(response.status_code, ErrorCode.INTERNAL)
        try:
            payload = response.json()
        except Exception:
            return ErrorDetail(
                error=code, message=response.text[:500] or f"HTTP {response.status_code}"
            )
        # Shared ErrorEnvelope shape ({"detail": {"error", "message"}}).
        if isinstance(payload, dict) and "detail" in payload:
            try:
                return ErrorEnvelope.model_validate(payload).detail
            except Exception:
                pass
        # Real registry shape: {"success": false, "error": "<message>"}.
        message = ""
        if isinstance(payload, dict):
            message = payload.get("error") or payload.get("message") or ""
        return ErrorDetail(error=code, message=message or f"HTTP {response.status_code}")

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "RegistryClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()


def _param(value: Any) -> str:
    """Normalize a filter value to its wire string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


__all__ = [
    "API_AGENTS",
    "ENV_BACKEND",
    "ENV_TOKEN",
    "ENV_TOKEN_LEGACY",
    "ENV_URL",
    "IAB_PROD_DEFAULT_URL",
    "LOCAL_DEFAULT_URL",
    "LOCAL_SANDBOX_DEFAULT_URL",
    "NEW_TOKEN_HEADER",
    "TRUST_TIER_CEILING",
    "AgentAuthorization",
    "DomainValidation",
    "RegistryAgent",
    "RegistryBackend",
    "RegistryClient",
    "RegistryError",
    "TrustVerification",
    "VerifiedTrust",
]
