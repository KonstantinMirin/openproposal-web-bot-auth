"""The buyer agent: its signed key directory, and an operator trigger that runs the flow.

`create_app(settings)` is the buyer's composition root, and nothing happens at
import time. Uvicorn builds the app with `--factory buyer.app:app_from_env`,
the only caller of `BuyerSettings.from_env()`.

Agents reach `buyer.wba-demo.noetis.dev` only for the directory, which
`DirectoryMiddleware` serves from the keyring on every fetch. The
`/operator/` routes are the buyer's own controls: no front routes them, so they
are reachable only inside the network, and each call carries the operator key
(shared/operator.py).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TypedDict

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from iab_agentic_primitives.web_bot_auth import KeyResolver, ServerIdentity
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware
from openproposal import LineItemWrites
from pydantic import BaseModel, TypeAdapter
from starlette.types import ASGIApp

from protocol.documents import load_yaml
from shared.auth import AuthMethod
from shared.keyring import Keyring, RotationError
from shared.operator import OperatorKey
from shared.wba import Transport, directory_resolver, http_client, tls_context

from .client import HTTPClient, call_signed
from .flow import Buyer, Outcome
from .repository import BuyerRepository, Counterparty
from .resources import BuyerResources, FlowDep, KeyringDep, ResourcesDep, SettingsDep
from .settings import BuyerSettings

PLAN = Path(__file__).parent / "plan.yaml"
#: The buyer's plan: a § 3.4 `LineItemWrites` per line item, checked strictly.
_PLAN = TypeAdapter(dict[str, LineItemWrites])

#: The routes any caller reaches. Agents reach only the directory, which the middleware serves.
api = APIRouter()


@api.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


#: The buyer's own controls. `create_app` puts the operator-key guard on them.
operator = APIRouter(prefix="/operator")


class Trigger(BaseModel):
    #: The seller's origin; the settings' `peer_seller_origin` when omitted.
    seller: str | None = None
    proposal_id: str
    line_item_ids: list[str] = []
    credential: AuthMethod = "web_bot_auth"


def _seller(trigger: Trigger, settings: BuyerSettings) -> str:
    return str(settings.peer_seller_origin) if trigger.seller is None else trigger.seller


@operator.post("/commit")
async def operator_commit(trigger: Trigger, flow: FlowDep, settings: SettingsDep) -> Outcome:
    """Runs the whole flow: read, commit, verify the signed answer, keep the evidence."""
    if not trigger.line_item_ids:
        raise HTTPException(400, "name the line items to commit")
    return await flow.commit(
        _seller(trigger, settings), trigger.proposal_id, trigger.line_item_ids, trigger.credential
    )


@operator.post("/read")
async def operator_read(trigger: Trigger, flow: FlowDep, settings: SettingsDep) -> Outcome:
    """Reads the proposal and verifies the seller's signed response."""
    return await flow.read(_seller(trigger, settings), trigger.proposal_id, trigger.credential)


@operator.get("/keys")
async def list_keys(keyring: KeyringDep) -> dict[str, str | list[str]]:
    return {
        "published": [k.thumbprint for k in keyring.published()],
        "active": keyring.active().thumbprint,
    }


@operator.post("/keys")
async def publish_key(keyring: KeyringDep) -> dict[str, str | list[str]]:
    """Rotation, step 1: publish a new key next to the old one, which keeps signing."""
    return {"published_kid": keyring.publish().thumbprint, **await list_keys(keyring)}


@operator.post("/keys/{kid}/activate")
async def activate_key(kid: str, keyring: KeyringDep) -> dict[str, str | list[str]]:
    """Rotation, step 2: sign with the new key, once verifiers' caches list it."""
    try:
        keyring.activate(kid)
    except RotationError as e:
        raise HTTPException(409, str(e)) from e
    return await list_keys(keyring)


@operator.delete("/keys/{kid}")
async def retire_key(kid: str, keyring: KeyringDep) -> dict[str, str | list[str]]:
    """Rotation, step 3: take the old key out of the directory, once its signatures expired."""
    try:
        keyring.retire(kid)
    except RotationError as e:
        raise HTTPException(409, str(e)) from e
    return await list_keys(keyring)


@operator.post("/cloudflare-check")
async def cloudflare_check(resources: ResourcesDep) -> dict[str, object]:
    """Signs a request to cfbot, whose verifier is Cloudflare's library, and returns its verdict."""
    settings = resources.settings
    body = json.dumps({"from": str(settings.self_origin), "says": "verify me"}).encode()
    response = await call_signed(
        resources.client,
        "POST",
        f"{settings.peer_cfbot_origin}/verify",
        signer=resources.flow.signer,
        body=body,
    )
    return {"status": response.status_code, "verdict": response.json()}


class _State(TypedDict):
    """What the lifespan yields; requests read it through buyer/resources.py."""

    resources: BuyerResources


def create_app(
    settings: BuyerSettings,
    *,
    resolver: KeyResolver | None = None,
    transport: Transport | None = None,
) -> ASGIApp:
    """The buyer, from its settings. Its lifespan owns the store and the one client.

    `resolver` replaces the directory resolver the buyer verifies sellers' answers
    with. `transport` answers in place of the network, for tests.

    The result is the FastAPI app inside the library's `DirectoryMiddleware`.
    """
    # The buyer mints its first key on first boot; the directory reads the keyring live.
    keyring = Keyring(
        settings.data_dir / "keys",
        rotation_wait=settings.rotation_wait,
        signature_lifetime=settings.signature_lifetime,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[_State]:
        store = BuyerRepository(settings.data_dir / "buyer.db")
        client = http_client(tls_context(settings.ca_bundle), transport=transport)
        try:
            yield {"resources": _resources(settings, store, keyring, client, resolver)}
        finally:
            await client.aclose()
            store.close()

    agent = FastAPI(title="Demo buyer", lifespan=lifespan)
    agent.include_router(api)
    agent.include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])
    # A live key source: the middleware reads the keyring on every directory fetch.
    return DirectoryMiddleware(
        agent,
        keyring.published,
        identity=ServerIdentity.from_config(str(settings.self_origin)),
        max_age=settings.directory_max_age,
    )


def _resources(
    settings: BuyerSettings,
    store: BuyerRepository,
    keyring: Keyring,
    client: HTTPClient,
    resolver: KeyResolver | None,
) -> BuyerResources:
    # The buyer knows the seller by its origin only, and its domain is that origin's host.
    # The token is the bearer flow's credential.
    seller = settings.peer_seller_origin
    store.add_counterparty(
        Counterparty(seller, seller.host, "Demo Seller Inc.", settings.bearer_token)
    )
    flow = Buyer(
        store,
        directory_resolver(client, max_cache_age=settings.max_cache_age)
        if resolver is None
        else resolver,
        keyring,
        str(settings.self_origin),
        _PLAN.validate_python(load_yaml(PLAN)),
        client=client,
        signature_lifetime=settings.signature_lifetime,
    )
    return BuyerResources(settings, store, keyring, client, flow)


def app_from_env() -> ASGIApp:
    """Uvicorn's factory: the buyer as its environment configures it."""
    return create_app(BuyerSettings.from_env())
