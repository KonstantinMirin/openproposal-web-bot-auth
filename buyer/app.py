"""The buyer agent: its signed key directory, and an operator trigger that runs the flow.

Agents reach `buyer.wba-demo.noetis.dev` only for the directory, which
`DirectoryMiddleware` serves from the keyring on every fetch. The
`/operator/` routes are the buyer's own controls: the TLS front doesn't route
them, so they are reachable only inside the network.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware
from pydantic import BaseModel

from shared.documents import load_yaml
from shared.wba import directory_resolver

from .client import call_signed
from .flow import Buyer, Outcome
from .keyring import Keyring, RotationError
from .store import Store

ORIGIN = os.environ.get("BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev")
DATA = Path(os.environ.get("BUYER_DATA", "/data"))
CFBOT_ORIGIN = os.environ.get("CFBOT_ORIGIN", "https://cfbot.wba-demo.noetis.dev")
# How long a cache may hold the directory: its Cache-Control max-age, 300 s by default.
DIRECTORY_MAX_AGE = int(os.environ.get("WBA_DIRECTORY_MAX_AGE", "300"))
# Rotation waits (buyer/keyring.py). In production, ROTATION_WAIT is the directory's
# max-age (300 s) plus the library's default max_cache_age (300 s), and signatures
# last the profile's 300 s maximum.
ROTATION_WAIT = float(os.environ.get("WBA_ROTATION_WAIT", "600"))
SIGNATURE_LIFETIME = int(os.environ.get("WBA_SIGNATURE_LIFETIME", "300"))

keyring = Keyring(DATA / "keys", rotation_wait=ROTATION_WAIT, signature_lifetime=SIGNATURE_LIFETIME)
store = Store(DATA / "buyer.db")
# The buyer knows the seller by its origin only. The token is the bearer flow's credential.
store.add_seller(os.environ.get("DEMO_SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev"),
                 "seller.wba-demo.noetis.dev", "Demo Seller Inc.",
                 os.environ.get("DEMO_BEARER_TOKEN"))
buyer = Buyer(store, directory_resolver(), keyring, ORIGIN,
              load_yaml(Path(__file__).parent / "plan.yaml"), signature_lifetime=SIGNATURE_LIFETIME)

api = FastAPI(title="Demo buyer")


@api.get("/health")
async def health() -> dict:
    return {"ok": True}


class Trigger(BaseModel):
    seller: str = "https://seller.wba-demo.noetis.dev"
    proposal_id: str
    line_item_ids: list[str] = []
    credential: Literal["web_bot_auth", "bearer"] = "web_bot_auth"


@api.post("/operator/commit")
async def operator_commit(trigger: Trigger) -> Outcome:
    """Runs the whole flow: read, commit, verify the signed answer, keep the evidence."""
    if not trigger.line_item_ids:
        raise HTTPException(400, "name the line items to commit")
    return await buyer.commit(trigger.seller, trigger.proposal_id, trigger.line_item_ids,
                              trigger.credential)


@api.post("/operator/read")
async def operator_read(trigger: Trigger) -> Outcome:
    """Reads the proposal and verifies the seller's signed response."""
    return await buyer.read(trigger.seller, trigger.proposal_id, trigger.credential)


@api.get("/operator/keys")
async def list_keys() -> dict:
    return {"published": [k.kid for k in keyring.published()], "active": keyring.active().kid}


@api.post("/operator/keys")
async def publish_key() -> dict:
    """Rotation, step 1: publish a new key next to the old one, which keeps signing."""
    return {"published_kid": keyring.publish().kid, **await list_keys()}


@api.post("/operator/keys/{kid}/activate")
async def activate_key(kid: str) -> dict:
    """Rotation, step 2: sign with the new key, once verifiers' caches list it."""
    try:
        keyring.activate(kid)
    except RotationError as e:
        raise HTTPException(409, str(e)) from e
    return await list_keys()


@api.delete("/operator/keys/{kid}")
async def retire_key(kid: str) -> dict:
    """Rotation, step 3: take the old key out of the directory, once its signatures expired."""
    try:
        keyring.retire(kid)
    except RotationError as e:
        raise HTTPException(409, str(e)) from e
    return await list_keys()


@api.post("/operator/cloudflare-check")
async def cloudflare_check() -> dict:
    """Signs a request to cfbot, whose verifier is Cloudflare's library, and returns its verdict."""
    body = json.dumps({"from": ORIGIN, "says": "verify me"}).encode()
    response = await call_signed("POST", f"{CFBOT_ORIGIN}/verify", signer=buyer.signer, body=body)
    return {"status": response.status_code, "verdict": response.json()}


# A live key source: the middleware reads the keyring on every directory fetch.
app = DirectoryMiddleware(api, keyring.published, base_url=ORIGIN, max_age=DIRECTORY_MAX_AGE)
