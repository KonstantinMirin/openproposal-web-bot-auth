"""The seller agent: issued proposals, offer acceptance, and its signed key directory.

`create_app(settings)` is the seller's composition root, and nothing happens
at import time. Uvicorn builds the app with `--factory seller.app:app_from_env`,
the only caller of `SellerSettings.from_env()`.

Every agent-facing route takes the caller from `resolve_caller` and nothing
else. The `/operator/` routes are the seller's own controls, outside the
boundary: no front routes them, and each call carries the operator key
(shared/operator.py). `ResponseSigningMiddleware` signs every response,
refusals included, and binds it to the request it answers.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TypedDict

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from iab_agentic_primitives.web_bot_auth import (
    Ed25519Key,
    KeyResolver,
    MemoryNonceStore,
    NonceStore,
    RequestVerifier,
    ResponseSigner,
    ServerIdentity,
)
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware, ResponseSigningMiddleware
from openproposal import dump
from pydantic import BaseModel
from starlette.types import ASGIApp

from protocol.values import instant
from shared.operator import OperatorKey
from shared.wba import directory_resolver, http_client, tls_context

from . import offers
from .errors import OfferError, Refused
from .faults import FaultInjection
from .identity import CallerDep
from .resources import SellerResources, StoreDep
from .seed import issue, seed
from .settings import SellerSettings
from .store import Store

#: The agent-facing routes. Each one takes its caller from the identity boundary.
api = APIRouter()


@api.get("/proposals/{proposal_id}")
async def get_proposal(proposal_id: str, caller: CallerDep, store: StoreDep) -> JSONResponse:
    return JSONResponse(offers.full_representation(store, caller, proposal_id))


# Allowlisted: the route reads the raw body from Request. Step 4 replaces it with RawBodyDep.
# ast-grep-ignore: routes-take-no-request
@api.post("/proposals/{proposal_id}/commit")
async def commit(
    proposal_id: str, caller: CallerDep, store: StoreDep, request: Request
) -> JSONResponse:
    # The route takes the body as bytes, so nothing parses it before resolve_caller has
    # confirmed the credential: a failing credential is refused even when the JSON is broken.
    body = offers.parse_commit(await request.body())
    return JSONResponse(dump(offers.commit(store, caller, proposal_id, body)))


@api.get("/whoami")
async def whoami(caller: CallerDep) -> JSONResponse:
    """What the identity boundary resolved for this request."""
    return JSONResponse(caller.model_dump())


@api.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


class Issue(BaseModel):
    principal_id: str


#: The seller's own controls. `create_app` puts the operator-key guard on them.
operator = APIRouter(prefix="/operator")


@operator.post("/issue")
async def issue_proposal(body: Issue, store: StoreDep) -> dict[str, str]:
    """Issues a fresh copy of the seed proposal to a buyer this seller knows (§ 4.3).

    The live runner (runner/live.py) commits to a fresh proposal on every run,
    because an agreed line item can't be committed to again.
    """
    principal = store.principal(body.principal_id)
    if principal is None:
        raise HTTPException(404, f"no principal {body.principal_id}")
    stamp = instant(datetime.now(UTC)).replace("-", "").replace(":", "")
    proposal_id = f"live-{body.principal_id}-{stamp}-{secrets.token_hex(2)}"
    with store.transaction():
        issue(store, principal["id"], proposal_id, principal["legal_name"], principal["domain"])
    return {"proposal_id": proposal_id, "principal_id": principal["id"]}


class _State(TypedDict):
    """What the lifespan yields; requests read it through seller/resources.py."""

    resources: SellerResources


def create_app(
    settings: SellerSettings,
    *,
    nonces: NonceStore | None = None,
    resolver: KeyResolver | None = None,
) -> ASGIApp:
    """The seller, from its settings. Its lifespan owns the store, the client, and the verifier.

    `nonces` and `resolver` replace the in-memory nonce store and the directory
    resolver, as a deployment with several workers or a test does.

    The result is the FastAPI app wrapped in the library's middlewares, so that
    every response is signed, a server error's included.
    """
    # The seller mints its key on first boot. No buyer is ever configured with it.
    key = Ed25519Key.load_or_create(settings.data_dir / "wba-key.jwk")
    identity = ServerIdentity.from_config(str(settings.self_origin))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[_State]:
        store = Store(settings.data_dir / "seller.db")
        client = http_client(tls_context(settings.ca_bundle))
        try:
            seed(store, buyer_origin=settings.peer_buyer_origin, bearer_token=settings.bearer_token)
            keys: KeyResolver = (
                directory_resolver(client, max_cache_age=settings.max_cache_age)
                if resolver is None
                else resolver
            )
            verifier = RequestVerifier(
                keys, nonces=MemoryNonceStore() if nonces is None else nonces
            )
            yield {"resources": SellerResources(identity, store, client, verifier)}
        finally:
            await client.aclose()
            store.close()

    agent = FastAPI(title="Demo seller", lifespan=lifespan)
    agent.add_exception_handler(Refused, lambda _request, e: e.response())
    agent.add_exception_handler(OfferError, lambda _request, e: e.response())
    agent.include_router(api)
    agent.include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])

    signer = ResponseSigner(key, str(settings.self_origin))
    signed = ResponseSigningMiddleware(agent, signer, identity=identity)
    answering = _with_faults(agent, signed, signer, identity) if settings.faults else signed
    # The signed key directory at the well-known path, for buyers to find the seller's key.
    return DirectoryMiddleware(
        answering, [key], identity=identity, max_age=settings.directory_max_age
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
