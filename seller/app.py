"""The seller agent: issued proposals, offer acceptance, and its signed key directory.

`create_app(settings)` is the seller's composition root, and nothing happens
at import time. Uvicorn builds the app with `--factory seller.app:app_from_env`,
the only caller of `SellerSettings.from_env()`.

Every agent-facing route takes the caller from the identity boundary
(`CallerDep`, or, for the offer logic, `PrincipalDep` or `EntryWriterDep`,
seller/http.py) and nothing else. The `/operator/` routes are the seller's own controls, outside
the boundary: no front routes them, and each call carries the operator key
(transport/operator.py).
`ResponseSigningMiddleware` signs every response, refusals included, binds it
to the request it answers, and serves the seller's signed key directory.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from http import HTTPStatus

import httpx
from fastapi import APIRouter, Depends, FastAPI
from fastapi.responses import JSONResponse
from iab_agentic_primitives.web_bot_auth import (
    DirectoryPublisher,
    KeyResolver,
    MemoryNonceStore,
    NonceStore,
    PublishPolicy,
    RequestVerifier,
    ResponseSigner,
    ServerIdentity,
    keyfile,
)
from iab_agentic_primitives.web_bot_auth.asgi import ResponseSigningMiddleware, ServerEdge
from starlette.types import ASGIApp

from protocol.documents import loads_yaml
from transport.control import HEALTH, ISSUE, Health, Issued, IssueRequest
from transport.lifespan import lifespan, resolver_or_default
from transport.operator import ControlError, OperatorKey, control_route

from .boundary import IdentityBoundary
from .caller import WhoAmI
from .errors import Rejected, UnknownPrincipal
from .faults import FaultInjection
from .http import CallerDep, EntryWriterDep, PrincipalDep, RawBodyDep, answer, install_handlers
from .offers.acceptance import answer_commit
from .offers.issuance import Issuer, issue_fresh
from .offers.reading import full_representation, parse_commit
from .resources import IssuerDep, OfferStoreDep, OnboardingDep, SellerResources
from .seed import onboard
from .settings import SellerSettings
from .sqlite_store import SqliteSellerStore

#: The agent-facing routes. Each one takes its caller from the identity boundary.
api = APIRouter()


@api.get("/proposals/{proposal_id}")
async def get_proposal(
    proposal_id: str, principal: PrincipalDep, store: OfferStoreDep
) -> JSONResponse:
    return answer(full_representation(store, principal, proposal_id))


@api.post("/proposals/{proposal_id}/commit")
async def post_commit(
    proposal_id: str, writer: EntryWriterDep, store: OfferStoreDep, body: RawBodyDep
) -> JSONResponse:
    # The route takes the body as bytes, so nothing parses it before the boundary has
    # confirmed the credential: a failing credential is refused even when the JSON is broken.
    request = parse_commit(body)
    if isinstance(request, Rejected):
        return answer(request)
    return answer(answer_commit(store, writer, proposal_id, request, datetime.now(UTC)))


@api.get("/whoami")
async def whoami(caller: CallerDep) -> WhoAmI:
    """What the identity boundary resolved for this request, as `WhoAmI` shows it."""
    return caller


@control_route(api, HEALTH)
async def health() -> Health:
    return Health(ok=True)


#: The seller's own controls. `create_app` puts the operator-key guard on them.
operator = APIRouter()


@control_route(operator, ISSUE)
async def issue_proposal(body: IssueRequest, store: OnboardingDep, issuer: IssuerDep) -> Issued:
    """Issues a fresh copy of the seed proposal to a buyer this seller knows (§ 4.3).

    The live runner (runner/main.py) commits to a fresh proposal on every run,
    because an agreed line item can't be committed to again.
    """
    try:
        issued = issue_fresh(store, issuer, body.principal_id, datetime.now(UTC))
    except UnknownPrincipal as e:
        raise ControlError(HTTPStatus.NOT_FOUND, "unknown-principal", f"no principal {e}") from e
    return Issued(proposal_id=issued.proposal_id, principal_id=issued.buyer_principal_id)


def create_app(
    settings: SellerSettings,
    *,
    nonces: NonceStore | None = None,
    resolver: KeyResolver | None = None,
) -> ASGIApp:
    """The seller, from its settings. Its lifespan owns the store, the client, and the boundary.

    `nonces` and `resolver` replace the in-memory nonce store and the directory
    resolver, as a deployment with several workers or a test does. The result is
    the FastAPI app wrapped in the library's middlewares, so that every response
    is signed, a server error's included.
    """
    # The seller mints its key on first boot. No buyer is ever configured with it.
    key = keyfile.load_or_create(settings.key_file)
    identity = ServerIdentity.from_config(str(settings.self_origin))
    # The seller's one identity at its edges: the key it signs its answers with, and the
    # directory that lists it, which the edge checks against each other when it is made.
    # The response signing middleware also serves that directory at the well-known path,
    # for buyers to find the seller's key.
    edge = ServerEdge(
        identity,
        signer=ResponseSigner.of(key, identity.origin),
        publisher=DirectoryPublisher(
            identity.origin, [key], PublishPolicy(max_age=settings.directory_max_age)
        ),
    )
    issuer = Issuer(settings.own, loads_yaml(settings.template_file.read_text(encoding="utf-8")))
    resources = _Parts(settings, issuer, edge, nonces, resolver).resources
    store = partial(SqliteSellerStore, settings.data_dir / "seller.db")
    agent = FastAPI(title="Demo seller", lifespan=lifespan(store, settings.ca_bundle, resources))
    install_handlers(agent)
    agent.include_router(api)
    agent.include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])

    signed = ResponseSigningMiddleware(agent, edge)
    return _with_faults(agent, signed, edge) if settings.faults else signed


@dataclass(frozen=True)
class _Parts:
    """What `create_app` builds before the lifespan opens the store and the client."""

    settings: SellerSettings
    issuer: Issuer
    #: The seller's one identity, which the boundary rebuilds requests on and verifies for.
    edge: ServerEdge
    nonces: NonceStore | None
    resolver: KeyResolver | None

    def resources(self, store: SqliteSellerStore, client: httpx.AsyncClient) -> SellerResources:
        """The seller's resources over its open store and client: its buyer, as its
        settings name it on this boot, and the identity boundary over the store's
        principals and the request verifier. Settings that would rewrite the buyer's
        recorded identity raise `IdentityChanged`, and the seller doesn't start."""
        settings = self.settings
        onboard(
            store,
            self.issuer,
            buyer_origin=settings.peer_buyer_origin,
            buyer_legal_name=settings.peer_buyer_legal_name,
            bearer_token=settings.bearer_token,
        )
        keys = resolver_or_default(client, settings.max_cache_age, self.resolver)
        nonces = MemoryNonceStore() if self.nonces is None else self.nonces
        verifier = RequestVerifier(keys, identity=self.edge.identity, nonces=nonces)
        boundary = IdentityBoundary(store, verifier, self.edge)
        return SellerResources(store, client, boundary, self.issuer)


def _with_faults(agent: FastAPI, signed: ASGIApp, edge: ServerEdge) -> FaultInjection:
    """TEST ONLY: wraps the signed app in seller/faults.py and mounts its `PUT /test/fault`."""
    faults = FaultInjection(signed, edge)
    agent.include_router(faults.control())
    return faults


def app_from_env() -> ASGIApp:
    """Uvicorn's factory: the seller as its environment configures it."""
    return create_app(SellerSettings.from_env())
