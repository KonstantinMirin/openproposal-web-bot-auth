"""The seller agent: issued proposals, offer acceptance, and its signed key directory.

Every agent-facing route takes the caller from `resolve_caller` and nothing
else. The `/operator/` routes are the seller's own controls, outside the
boundary: no front routes them, and each call carries the operator key
(shared/operator.py). `ResponseSigningMiddleware` signs every response,
refusals included, and binds it to the request it answers.
"""

from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
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

from shared.operator import require_operator
from shared.wba import directory_resolver

from . import offers
from .errors import OfferError, Refused
from .faults import MODES, FaultInjection
from .identity import CallerDep
from .seed import issue, seed
from .store import Store

ORIGIN = os.environ.get("SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev")
DATA = Path(os.environ.get("SELLER_DATA", "/data"))
FAULTS = os.environ.get("DEMO_FAULT_INJECTION") == "1"
# How long a cache may hold the directory: its Cache-Control max-age, 300 s by default.
DIRECTORY_MAX_AGE = int(os.environ.get("WBA_DIRECTORY_MAX_AGE", "300"))

# The seller mints its key on first boot. No buyer is ever configured with it.
key = Ed25519Key.load_or_create(DATA / "wba-key.jwk")
store = Store(DATA / "seller.db")
seed(
    store,
    buyer_origin=os.environ.get("DEMO_BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev"),
    bearer_token=os.environ.get("DEMO_BEARER_TOKEN"),
)

api = FastAPI(title="Demo seller")
api.state.store = store
api.state.origin = ORIGIN
api.state.verifier = RequestVerifier(directory_resolver(), nonces=MemoryNonceStore())

api.add_exception_handler(Refused, lambda _request, e: e.response())
api.add_exception_handler(OfferError, lambda _request, e: e.response())


@api.exception_handler(RequestValidationError)
async def _invalid(_request: Request, e: RequestValidationError) -> JSONResponse:
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


class Issue(BaseModel):
    principal_id: str


operator = APIRouter(prefix="/operator", dependencies=[Depends(require_operator)])


@operator.post("/issue")
async def issue_proposal(body: Issue) -> dict:
    """Issues a fresh copy of the seed proposal to a buyer this seller knows (§ 4.3).

    The live runner (runner/live.py) commits to a fresh proposal on every run,
    because an agreed line item can't be committed to again.
    """
    principal = store.principal(body.principal_id)
    if principal is None:
        raise HTTPException(404, f"no principal {body.principal_id}")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    proposal_id = f"live-{body.principal_id}-{stamp}-{secrets.token_hex(2)}"
    with store.transaction():
        issue(store, principal["id"], proposal_id, principal["legal_name"], principal["domain"])
    return {"proposal_id": proposal_id, "principal_id": principal["id"]}


api.include_router(operator)


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
app = DirectoryMiddleware(app, [key], base_url=ORIGIN, max_age=DIRECTORY_MAX_AGE)
