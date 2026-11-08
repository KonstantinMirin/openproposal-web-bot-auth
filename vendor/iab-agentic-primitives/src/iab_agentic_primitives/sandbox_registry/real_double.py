"""A faithful in-process TEST DOUBLE of the REAL agent-registry API.

This is NOT "the sandbox" and NOT a production registry — it is a minimal
FastAPI stand-in that reproduces the shapes of the real Node registry
(github.com/IABTechLab/agent-registry) closely enough to unit-test
:class:`~iab_agentic_primitives.registry_client.RegistryClient` where
spinning the real dockerized registry is not available (CI without Docker).
The REAL registry is what the ``LOCAL`` backend points at via the
docker-compose runner (see SANDBOX_REGISTRY.md); this double exists only so
the client's method set has fast, deterministic, offline coverage.

What it faithfully reproduces (verified against routes/agents.js +
middleware/auth.js):

- Base path ``/api/agents`` and the enveloped success shape
  ``{"success": true, "data": ...}`` (a list is
  ``{"data": {"agents": [...], "count": N, ...}}``).
- ``Authorization: Bearer <token>`` auth (401 without it), admin-gated
  ``PUT`` / ``DELETE`` / ``verify-health`` (403 for non-admins),
  domain-scoped registration (the caller's company domain must match the
  agent's ``primary_domain``, else 403).
- The ``X-New-Token`` refresh header: a token flagged as "expired-but-valid"
  is accepted AND the response carries a fresh token, exactly as the real
  ``tokenRefreshInterceptor`` does.
- Public ``validate/domain``, ``validate/agent`` and the SVG
  ``verification-badge`` (served only for ``iab_member`` agents, 404
  otherwise).
- Error bodies as ``{"success": false, "error": "<message>"}``.

Acronyms: JWT = JSON Web Token; SVG = Scalable Vector Graphics; IAB =
Interactive Advertising Bureau.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response
except ImportError as _exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The registry test double requires fastapi; install the 'sandbox' extra: "
        "pip install 'iab-agentic-primitives[sandbox]'"
    ) from _exc

#: The ``X-New-Token`` response header the real registry uses for refresh.
NEW_TOKEN_HEADER = "X-New-Token"

DEFAULT_REGISTRY_ID = "local_double"


@dataclass
class TokenCtx:
    """A resolved bearer token → the user it authenticates (test double only)."""

    company_domain: str
    admin: bool = False
    #: When set, this token is "expired-but-valid": auth succeeds AND the
    #: response returns this fresh token in ``X-New-Token``.
    refresh_to: str | None = None


def default_tokens() -> dict[str, TokenCtx]:
    """The token table the double ships with for tests."""
    return {
        "user-token": TokenCtx(company_domain="example.com", admin=False),
        "admin-token": TokenCtx(company_domain="example.com", admin=True),
        # Expired-but-valid: accepted, and refreshed to "user-token".
        "expired-token": TokenCtx(
            company_domain="example.com", admin=False, refresh_to="user-token"
        ),
    }


@dataclass
class _Store:
    tokens: dict[str, TokenCtx]
    registry_id: str
    agents: dict[int, dict] = field(default_factory=dict)
    next_id: int = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error(status: int, message: str, refresh: str | None = None) -> JSONResponse:
    resp = JSONResponse(status_code=status, content={"success": False, "error": message})
    if refresh:
        resp.headers[NEW_TOKEN_HEADER] = refresh
    return resp


def _normalize_domain(domain: str) -> str:
    return (
        domain.lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
        .removeprefix("www.")
    )


def create_registry_double(
    *,
    tokens: dict[str, TokenCtx] | None = None,
    registry_id: str = DEFAULT_REGISTRY_ID,
) -> FastAPI:
    """Build the real-API test-double app (``/api/agents`` surface)."""
    store = _Store(tokens=tokens or default_tokens(), registry_id=registry_id)

    app = FastAPI(title="agent-registry test double", version="0.0.0")
    app.state.store = store

    def authenticate(request: Request) -> tuple[TokenCtx | None, str | None]:
        """Return (ctx, refresh_token). ctx is None when auth fails."""
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return None, None
        token = header[7:].strip()
        ctx = store.tokens.get(token)
        if ctx is None:
            return None, None
        return ctx, ctx.refresh_to

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "registry_id": store.registry_id}

    @app.post("/api/auth/login")
    async def login(request: Request) -> Response:
        body = await request.json()
        if not body.get("username") or not body.get("password"):
            return _error(400, "Username and password are required")
        # The double does not talk to IAB OAuth; it just issues a test token.
        return JSONResponse({"success": True, "token": "user-token"})

    @app.post("/api/agents")
    async def register_agent(request: Request) -> Response:
        ctx, refresh = authenticate(request)
        if ctx is None:
            return _error(401, "Authentication required")
        body = await request.json()
        if not body.get("agent_name") or not body.get("primary_domain"):
            return _error(400, "Missing required fields: agent_name, primary_domain", refresh)
        if body.get("type") == "local":
            if not body.get("repository_url"):
                return _error(400, "Local agents require repository_url", refresh)
        elif not body.get("endpoint_url"):
            return _error(400, "Remote and Private agents require endpoint_url", refresh)
        if _normalize_domain(ctx.company_domain) != _normalize_domain(body["primary_domain"]):
            return _error(
                403,
                f"Domain mismatch: You can only register agents for your company domain "
                f"({ctx.company_domain}).",
                refresh,
            )
        agent = dict(body)
        agent["id"] = store.next_id
        store.next_id += 1
        # SECURITY parity: iab_member is forced false at registration.
        agent["iab_member"] = False
        agent.setdefault("domain_verified", False)
        agent.setdefault("gpp_verified", False)
        agent.setdefault("endpoint_health_verified", False)
        agent["verification_status"] = "active" if agent.get("domain_verified") else "pending"
        agent["created_at"] = _now()
        store.agents[agent["id"]] = agent
        resp = JSONResponse(
            status_code=201,
            content={
                "success": True,
                "message": "Agent registered successfully",
                "data": agent,
                "verification": {"status": agent["verification_status"]},
            },
        )
        if refresh:
            resp.headers[NEW_TOKEN_HEADER] = refresh
        return resp

    @app.get("/api/agents")
    def list_agents(request: Request) -> Response:
        ctx, refresh = authenticate(request)
        if ctx is None:
            return _error(401, "Authentication required")
        q = request.query_params
        agents = list(store.agents.values())
        if q.get("protocol_type"):
            agents = [a for a in agents if a.get("protocol_type") == q["protocol_type"]]
        if q.get("verification_status"):
            agents = [a for a in agents if a.get("verification_status") == q["verification_status"]]
        if q.get("primary_domain"):
            want = _normalize_domain(q["primary_domain"])
            agents = [a for a in agents if _normalize_domain(a.get("primary_domain", "")) == want]
        if q.get("verified") in ("true", "false"):
            want = q["verified"] == "true"
            agents = [a for a in agents if bool(a.get("domain_verified")) == want]
        resp = JSONResponse(
            {
                "success": True,
                "data": {"agents": agents, "count": len(agents), "isAdmin": ctx.admin},
            }
        )
        if refresh:
            resp.headers[NEW_TOKEN_HEADER] = refresh
        return resp

    @app.get("/api/agents/{agent_id}")
    def get_agent(agent_id: int, request: Request) -> Response:
        ctx, refresh = authenticate(request)
        if ctx is None:
            return _error(401, "Authentication required")
        agent = store.agents.get(agent_id)
        if agent is None:
            return _error(404, "Agent not found", refresh)
        resp = JSONResponse({"success": True, "data": agent})
        if refresh:
            resp.headers[NEW_TOKEN_HEADER] = refresh
        return resp

    @app.put("/api/agents/{agent_id}")
    async def update_agent(agent_id: int, request: Request) -> Response:
        ctx, refresh = authenticate(request)
        if ctx is None:
            return _error(401, "Authentication required")
        if not ctx.admin:
            return _error(403, "Admin access required", refresh)
        agent = store.agents.get(agent_id)
        if agent is None:
            return _error(404, "Agent not found", refresh)
        agent.update(await request.json())
        agent["updated_at"] = _now()
        resp = JSONResponse(
            {"success": True, "message": "Agent updated successfully", "data": agent}
        )
        if refresh:
            resp.headers[NEW_TOKEN_HEADER] = refresh
        return resp

    @app.delete("/api/agents/{agent_id}")
    def delete_agent(agent_id: int, request: Request) -> Response:
        ctx, refresh = authenticate(request)
        if ctx is None:
            return _error(401, "Authentication required")
        if not ctx.admin:
            return _error(403, "Admin access required", refresh)
        if agent_id not in store.agents:
            return _error(404, "Agent not found", refresh)
        del store.agents[agent_id]
        resp = JSONResponse({"success": True, "message": "Agent deleted successfully"})
        if refresh:
            resp.headers[NEW_TOKEN_HEADER] = refresh
        return resp

    @app.post("/api/agents/{agent_id}/verify-health")
    def verify_health(agent_id: int, request: Request) -> Response:
        ctx, refresh = authenticate(request)
        if ctx is None:
            return _error(401, "Authentication required")
        if not ctx.admin:
            return _error(403, "Admin access required", refresh)
        agent = store.agents.get(agent_id)
        if agent is None:
            return _error(404, "Agent not found", refresh)
        healthy = bool(agent.get("endpoint_url"))
        agent["endpoint_health_verified"] = healthy
        resp = JSONResponse(
            {"success": True, "message": "Health check completed", "data": {"healthy": healthy}}
        )
        if refresh:
            resp.headers[NEW_TOKEN_HEADER] = refresh
        return resp

    @app.post("/api/agents/validate/domain")
    async def validate_domain(request: Request) -> Response:
        body = await request.json()
        domain = body.get("domain")
        if not domain:
            return _error(400, "Domain is required")
        norm = _normalize_domain(domain)
        match = next(
            (
                a
                for a in store.agents.values()
                if _normalize_domain(a.get("primary_domain", "")) == norm
            ),
            None,
        )
        if match:
            return JSONResponse(
                {
                    "success": True,
                    "domain": norm,
                    "registered": True,
                    "verified": bool(match.get("domain_verified")),
                    "verification_method": match.get("verification_method"),
                    "agent": {"id": match["id"], "agent_name": match.get("agent_name")},
                }
            )
        return JSONResponse(
            {
                "success": True,
                "domain": norm,
                "registered": False,
                "verified": False,
                "message": "Domain is not registered in the Agent Registry",
            }
        )

    @app.post("/api/agents/validate/agent")
    async def validate_agent(request: Request) -> Response:
        body = await request.json()
        domain, agent_url = body.get("domain"), body.get("agent_url")
        if not domain or not agent_url:
            return _error(400, "Both domain and agent_url are required")
        norm = _normalize_domain(domain)
        in_registry = any(a.get("endpoint_url") == agent_url for a in store.agents.values())
        # The double does not fetch the publisher's authorized-agents.txt.
        return JSONResponse(
            {
                "success": True,
                "authorized": False,
                "domain": norm,
                "agent_url": agent_url,
                "agent_in_registry": in_registry,
                "message": "Agent is not authorized by this publisher",
            }
        )

    @app.get("/api/agents/{agent_id}/verification-badge")
    def verification_badge(agent_id: int) -> Response:
        agent = store.agents.get(agent_id)
        if agent is None:
            return Response(
                content=_error_badge("Agent Not Found"), status_code=404, media_type="image/svg+xml"
            )
        if not agent.get("iab_member"):
            return Response(
                content=_error_badge("Not Verified"), status_code=404, media_type="image/svg+xml"
            )
        return Response(
            content=_verified_badge(agent.get("agent_name", "Unknown")), media_type="image/svg+xml"
        )

    return app


def _verified_badge(name: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="80">'
        f'<text x="10" y="45">VERIFIED {name}</text></svg>'
    )


def _error_badge(text: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="80">'
        f'<text x="10" y="45">{text}</text></svg>'
    )


__all__ = [
    "DEFAULT_REGISTRY_ID",
    "NEW_TOKEN_HEADER",
    "TokenCtx",
    "create_registry_double",
    "default_tokens",
]
