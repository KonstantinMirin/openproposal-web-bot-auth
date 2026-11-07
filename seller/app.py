"""The seller agent: issued proposals, offer acceptance, and its signed key directory.

`create_app(settings)` is the seller's composition root, and nothing happens
at import time. Uvicorn builds the app with `--factory seller.app:app_from_env`,
the only caller of `SellerSettings.from_env()`.

Every agent-facing route takes the caller from the identity boundary
(`CallerDep`, seller/http.py) and nothing else. The `/operator/` routes are
the seller's own controls, outside the boundary: no front routes them, and
each call carries the operator key (transport/operator.py).
`ResponseSigningMiddleware` signs every response, refusals included, and binds
it to the request it answers.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TypedDict

from fastapi import APIRouter, Depends, FastAPI
from fastapi.responses import JSONResponse
from iab_agentic_primitives.web_bot_auth import (
    KeyResolver,
    MemoryNonceStore,
    NonceStore,
    PublishPolicy,
    RequestVerifier,
    ResponseSigner,
    ServerIdentity,
    keyfile,
)
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware, ResponseSigningMiddleware
from starlette.types import ASGIApp

from transport.control import Health, Issued, IssueRequest
from transport.operator import ControlError, OperatorKey
from transport.wba import directory_resolver, http_client, tls_context

from .boundary import IdentityBoundary
from .errors import Rejected, UnknownPrincipal
from .faults import FaultInjection
from .http import CallerDep, RawBodyDep, answer, install_handlers
from .offers.acceptance import answer_commit
from .offers.issuance import issue_fresh, load_template
from .offers.reading import full_representation, parse_commit
from .resources import OfferStoreDep, OnboardingDep, SellerResources, TemplateDep
from .seed import seed
from .settings import SellerSettings
from .sqlite_store import SqliteSellerStore

#: The agent-facing routes. Each one takes its caller from the identity boundary.
api = APIRouter()


@api.get("/proposals/{proposal_id}")
async def get_proposal(proposal_id: str, caller: CallerDep, store: OfferStoreDep) -> JSONResponse:
    return answer(full_representation(store, caller, proposal_id))


@api.post("/proposals/{proposal_id}/commit")
async def post_commit(
    proposal_id: str, caller: CallerDep, store: OfferStoreDep, body: RawBodyDep
) -> JSONResponse:
    # The route takes the body as bytes, so nothing parses it before the boundary has
    # confirmed the credential: a failing credential is refused even when the JSON is broken.
    request = parse_commit(body)
    if isinstance(request, Rejected):
        return answer(request)
    return answer(answer_commit(store, caller, proposal_id, request, datetime.now(UTC)))


@api.get("/whoami")
async def whoami(caller: CallerDep) -> JSONResponse:
    """What the identity boundary resolved for this request."""
    return JSONResponse(caller.model_dump(mode="json"))


@api.get("/health")
async def health() -> Health:
    return Health(ok=True)


#: The seller's own controls. `create_app` puts the operator-key guard on them.
operator = APIRouter(prefix="/operator")


@operator.post("/issue")
async def issue_proposal(body: IssueRequest, store: OnboardingDep, template: TemplateDep) -> Issued:
    """Issues a fresh copy of the seed proposal to a buyer this seller knows (§ 4.3).

    The live runner (runner/main.py) commits to a fresh proposal on every run,
    because an agreed line item can't be committed to again.
    """
    try:
        issued = issue_fresh(store, body.principal_id, template, datetime.now(UTC))
    except UnknownPrincipal as e:
        raise ControlError(404, "unknown-principal", f"no principal {e}") from e
    return Issued(proposal_id=issued.proposal_id, principal_id=issued.buyer_principal_id)


class _State(TypedDict):
    """What the lifespan yields; requests read it through seller/resources.py."""

    resources: SellerResources


def create_app(
    settings: SellerSettings,
    *,
    nonces: NonceStore | None = None,
    resolver: KeyResolver | None = None,
) -> ASGIApp:
    """The seller, from its settings. Its lifespan owns the store, the client, and the boundary.

    `nonces` and `resolver` replace the in-memory nonce store and the directory
    resolver, as a deployment with several workers or a test does.

    The result is the FastAPI app wrapped in the library's middlewares, so that
    every response is signed, a server error's included.
    """
    # The seller mints its key on first boot. No buyer is ever configured with it.
    key = keyfile.load_or_create(settings.key_file)
    identity = ServerIdentity.from_config(str(settings.self_origin))
    template = load_template()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[_State]:
        store = SqliteSellerStore(settings.data_dir / "seller.db")
        client = http_client(tls_context(settings.ca_bundle))
        try:
            seed(
                store,
                template,
                buyer_origin=settings.peer_buyer_origin,
                bearer_token=settings.bearer_token,
            )
            keys: KeyResolver = (
                directory_resolver(client, max_cache_age=settings.max_cache_age)
                if resolver is None
                else resolver
            )
            verifier = RequestVerifier(
                keys, identity=identity, nonces=MemoryNonceStore() if nonces is None else nonces
            )
            boundary = IdentityBoundary(store, verifier, identity)
            yield {"resources": SellerResources(store, client, boundary, template)}
        finally:
            await client.aclose()
            store.close()

    agent = FastAPI(title="Demo seller", lifespan=lifespan)
    install_handlers(agent)
    agent.include_router(api)
    agent.include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])

    signer = ResponseSigner(key, str(settings.self_origin))
    signed = ResponseSigningMiddleware(agent, signer, identity=identity)
    answering = _with_faults(agent, signed, signer, identity) if settings.faults else signed
    # The signed key directory at the well-known path, for buyers to find the seller's key.
    return DirectoryMiddleware(
        answering,
        [key],
        identity=identity,
        publish=PublishPolicy(max_age=settings.directory_max_age),
    )


def _with_faults(
    agent: FastAPI, signed: ASGIApp, signer: ResponseSigner, identity: ServerIdentity
) -> FaultInjection:
    """TEST ONLY: wraps the signed app in seller/faults.py and mounts its `PUT /test/fault`."""
    faults = FaultInjection(signed, signer, identity)
    agent.include_router(faults.control())
    return faults


def app_from_env() -> ASGIApp:
    """Uvicorn's factory: the seller as its environment configures it."""
    return create_app(SellerSettings.from_env())
