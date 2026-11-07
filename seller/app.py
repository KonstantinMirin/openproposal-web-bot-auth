"""The seller agent: issued proposals, offer acceptance, and its signed key directory.

Every agent-facing route takes the caller from `resolve_caller` and nothing
else. `ResponseSigningMiddleware` signs every response, refusals included, and
binds it to the request it answers.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from iab_agentic_primitives.web_bot_auth import (
    Ed25519Key,
    MemoryNonceStore,
    RequestVerifier,
    ResponseSigner,
)
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware, ResponseSigningMiddleware
from openproposal import dump
from pydantic import BaseModel

from shared.wba import directory_resolver

from . import offers
from .errors import OfferError, Refused
from .faults import MODES, FaultInjection
from .identity import CallerDep
from .seed import seed
from .store import Store

ORIGIN = os.environ.get("SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev")
DATA = Path(os.environ.get("SELLER_DATA", "/data"))
FAULTS = os.environ.get("DEMO_FAULT_INJECTION") == "1"

# The seller mints its key on first boot. No buyer is ever configured with it.
key = Ed25519Key.load_or_create(DATA / "wba-key.jwk")
store = Store(DATA / "seller.db")
seed(store, buyer_origin=os.environ.get("DEMO_BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev"),
     bearer_token=os.environ.get("DEMO_BEARER_TOKEN"))

api = FastAPI(title="Demo seller")
api.state.store = store
api.state.origin = ORIGIN
api.state.verifier = RequestVerifier(directory_resolver(), nonces=MemoryNonceStore())

api.add_exception_handler(Refused, lambda request, e: e.response())
api.add_exception_handler(OfferError, lambda request, e: e.response())


@api.exception_handler(RequestValidationError)
async def _invalid(request: Request, e: RequestValidationError) -> JSONResponse:
    detail = "; ".join(f"{'/'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors())
    return OfferError("validation", detail, retry="none").response()


@api.get("/proposals/{proposal_id}")
async def get_proposal(proposal_id: str, caller: CallerDep) -> JSONResponse:
    return JSONResponse(offers.full_representation(store, caller, proposal_id))


@api.post("/proposals/{proposal_id}/commit")
async def commit(proposal_id: str, caller: CallerDep, request: Request) -> JSONResponse:
    # The route takes the body as bytes, so nothing parses it before resolve_caller has
    # confirmed the credential: a failing credential is refused even when the JSON is broken.
    body = offers.parse_commit(await request.body())
    return JSONResponse(dump(offers.commit(store, caller, proposal_id, body)))


@api.get("/whoami")
async def whoami(caller: CallerDep) -> JSONResponse:
    """What the identity boundary resolved for this request."""
    return JSONResponse(caller.model_dump())


@api.get("/health")
async def health() -> dict:
    return {"ok": True}


class FaultMode(BaseModel):
    mode: str


if FAULTS:
    @api.put("/test/fault")
    async def set_fault(body: FaultMode) -> dict:
        """TEST ONLY: see seller/faults.py."""
        if body.mode not in MODES:
            raise OfferError("validation", f"mode is one of {MODES}", retry="none")
        FaultInjection.mode = body.mode
        return {"mode": body.mode}


signer = ResponseSigner(key, ORIGIN)
app = ResponseSigningMiddleware(api, signer, base_url=ORIGIN)
if FAULTS:
    app = FaultInjection(app, signer, ORIGIN)
# The signed key directory at the well-known path, for buyers to find the seller's key.
app = DirectoryMiddleware(app, [key], base_url=ORIGIN)
