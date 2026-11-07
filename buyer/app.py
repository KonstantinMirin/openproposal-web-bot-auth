"""The buyer agent: its signed key directory, and an operator trigger that runs the flow.

Agents reach `buyer.wba-demo.noetis.dev` only for the directory. The
`/operator/` routes are the buyer's own controls: the TLS front doesn't route
them, so they are reachable only inside the network.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from iab_agentic_primitives.web_bot_auth import DIRECTORY_PATH
from iab_agentic_primitives.web_bot_auth.asgi import directory_response
from pydantic import BaseModel

from shared.documents import load_yaml
from shared.wba import EvidenceResolver

from .client import call_signed
from .flow import Buyer, Outcome
from .keyring import Keyring
from .store import Store

ORIGIN = os.environ.get("BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev")
DATA = Path(os.environ.get("BUYER_DATA", "/data"))
# How long a fetched directory stays valid in a verifier's cache, in seconds.
DIRECTORY_LIFETIME = int(os.environ.get("WBA_DIRECTORY_LIFETIME", "86400"))
CFBOT_ORIGIN = os.environ.get("CFBOT_ORIGIN", "https://cfbot.wba-demo.noetis.dev")

keyring = Keyring(DATA / "keys")
store = Store(DATA / "buyer.db")
# The buyer knows the seller by its origin only. The token is the bearer flow's credential.
store.add_seller(os.environ.get("DEMO_SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev"),
                 "seller.wba-demo.noetis.dev", "Demo Seller Inc.",
                 os.environ.get("DEMO_BEARER_TOKEN"))
buyer = Buyer(store, EvidenceResolver(), keyring, ORIGIN,
              load_yaml(Path(__file__).parent / "plan.yaml"))

app = FastAPI(title="Demo buyer")


@app.get(DIRECTORY_PATH)
async def directory() -> Response:
    status, headers, body = directory_response(
        keyring.published(), ORIGIN.removeprefix("https://"), int(time.time()),
        lifetime=DIRECTORY_LIFETIME,
    )
    return Response(body, status_code=status, headers=headers)


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


class Trigger(BaseModel):
    seller: str = "https://seller.wba-demo.noetis.dev"
    proposal_id: str
    line_item_ids: list[str] = []
    credential: Literal["web_bot_auth", "bearer"] = "web_bot_auth"


@app.post("/operator/commit")
async def operator_commit(trigger: Trigger) -> Outcome:
    """Runs the whole flow: read, commit, verify the signed answer, keep the evidence."""
    if not trigger.line_item_ids:
        raise HTTPException(400, "name the line items to commit")
    return await buyer.commit(trigger.seller, trigger.proposal_id, trigger.line_item_ids,
                              trigger.credential)


@app.post("/operator/read")
async def operator_read(trigger: Trigger) -> Outcome:
    """Reads the proposal and verifies the seller's signed response."""
    return await buyer.read(trigger.seller, trigger.proposal_id, trigger.credential)


@app.get("/operator/keys")
async def list_keys() -> dict:
    return {"published": [k.kid for k in keyring.published()], "active": keyring.active().kid}


@app.post("/operator/keys")
async def add_key() -> dict:
    """Rotation, step 1: publish a new key. The newest key signs from now on."""
    keyring.add()
    return await list_keys()


@app.delete("/operator/keys/{kid}")
async def retire_key(kid: str) -> dict:
    """Rotation, step 2: take an old key out of the directory."""
    if not keyring.retire(kid):
        raise HTTPException(404, f"no retirable key {kid}")
    return await list_keys()


@app.post("/operator/cloudflare-check")
async def cloudflare_check() -> dict:
    """Signs a request to cfbot, whose verifier is Cloudflare's library, and returns its verdict."""
    body = json.dumps({"from": ORIGIN, "says": "verify me"}).encode()
    response = await call_signed("POST", f"{CFBOT_ORIGIN}/verify", signer=buyer.signer, body=body)
    return {"status": response.status_code, "verdict": response.json()}
