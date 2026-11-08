"""The buyer agent: its signed key directory, and an operator trigger that runs the flow.

`create_app(settings)` is the buyer's composition root, and nothing happens at
import time. Uvicorn builds the app with `--factory buyer.app:app_from_env`,
the only caller of `BuyerSettings.from_env()`.

Agents reach `buyer.wba-demo.noetis.dev` only for the directory, which
`DirectoryMiddleware` serves from the keyring on every fetch. The
`/operator/` routes are the buyer's own controls: no front routes them, so they
are reachable only inside the network, and each call carries the operator key
(transport/operator.py).
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TypedDict

from fastapi import APIRouter, Depends, FastAPI
from iab_agentic_primitives.web_bot_auth import KeyResolver, PublishPolicy, ServerIdentity
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware
from starlette.types import ASGIApp

from persistence.values import Origin
from protocol.documents import loads_yaml
from shared.keyring import Keyring
from transport.control import (
    CloudflareCheck,
    CommitTrigger,
    Health,
    KeyState,
    Outcome,
    PublishedKey,
    ReadTrigger,
)
from transport.operator import OperatorKey
from transport.wba import Transport, directory_resolver, http_client, tls_context

from .cfbot import Cfbot
from .flow import Buyer
from .http import install_handlers
from .plan import Plan
from .repository import BuyerRepository, Counterparty
from .resources import BuyerResources, CfbotDep, FlowDep, KeyringDep, SettingsDep
from .seller_client import HTTPClient, SellerClient
from .settings import BuyerSettings

#: The § 3.4 writes the buyer commits for each line item it buys.
PLAN = Path(__file__).resolve().parent / "plan.yaml"

#: The routes any caller reaches. Agents reach only the directory, which the middleware serves.
api = APIRouter()


@api.get("/health")
async def health() -> Health:
    return Health(ok=True)


#: The buyer's own controls. `create_app` puts the operator-key guard on them.
operator = APIRouter(prefix="/operator")


def _seller(trigger: ReadTrigger, settings: BuyerSettings) -> Origin:
    return settings.peer_seller_origin if trigger.seller is None else trigger.seller


@operator.post("/commit")
async def operator_commit(trigger: CommitTrigger, flow: FlowDep, settings: SettingsDep) -> Outcome:
    """Runs the whole flow: read, commit, verify the signed answer, keep the evidence."""
    return await flow.commit(
        _seller(trigger, settings), trigger.proposal_id, trigger.line_item_ids, trigger.credential
    )


@operator.post("/read")
async def operator_read(trigger: ReadTrigger, flow: FlowDep, settings: SettingsDep) -> Outcome:
    """Reads the proposal and verifies the seller's signed response."""
    return await flow.read(_seller(trigger, settings), trigger.proposal_id, trigger.credential)


def _keys(keyring: Keyring) -> KeyState:
    return KeyState(
        published=[k.thumbprint for k in keyring.published()], active=keyring.active().thumbprint
    )


@operator.get("/keys")
async def list_keys(keyring: KeyringDep) -> KeyState:
    return _keys(keyring)


@operator.post("/keys")
async def publish_key(keyring: KeyringDep) -> PublishedKey:
    """Rotation, step 1: publish a new key next to the old one, which keeps signing."""
    kid = keyring.publish().thumbprint
    return PublishedKey(published_kid=kid, **_keys(keyring).model_dump())


@operator.post("/keys/{kid}/activate")
async def activate_key(kid: str, keyring: KeyringDep) -> KeyState:
    """Rotation, step 2: sign with the new key, once verifiers' caches list it."""
    keyring.activate(kid)
    return _keys(keyring)


@operator.delete("/keys/{kid}")
async def retire_key(kid: str, keyring: KeyringDep) -> KeyState:
    """Rotation, step 3: take the old key out of the directory, once its signatures expired."""
    keyring.retire(kid)
    return _keys(keyring)


@operator.post("/cloudflare-check")
async def cloudflare_check(cfbot: CfbotDep, settings: SettingsDep) -> CloudflareCheck:
    """Signs a request to cfbot, whose verifier is Cloudflare's library, and returns its verdict."""
    body = json.dumps({"from": str(settings.self_origin), "says": "verify me"}).encode()
    return await cfbot.verify(body)


class _State(TypedDict):
    """What the lifespan yields; requests read it through buyer/resources.py."""

    resources: BuyerResources


def create_app(
    settings: BuyerSettings,
    *,
    resolver: KeyResolver | None = None,
    transport: Transport | None = None,
    clock: Callable[[], float] = time.time,
) -> ASGIApp:
    """The buyer, from its settings. Its lifespan owns the store and the one client.

    `resolver` replaces the directory resolver the buyer verifies sellers' answers
    with. `transport` answers in place of the network, and `clock` tells the keyring
    the time, for tests.

    The result is the FastAPI app inside the library's `DirectoryMiddleware`.
    """
    plan = Plan.of(loads_yaml(PLAN.read_text(encoding="utf-8")))
    # The buyer mints its first key on first boot; the directory reads the keyring live.
    keyring = Keyring(
        settings.keyring_dir,
        rotation_wait=settings.rotation_wait,
        signature_lifetime=settings.signature_lifetime,
        clock=clock,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[_State]:
        store = BuyerRepository(settings.data_dir / "buyer.db")
        client = http_client(tls_context(settings.ca_bundle), transport=transport)
        try:
            keys = (
                directory_resolver(client, max_cache_age=settings.max_cache_age)
                if resolver is None
                else resolver
            )
            flow = Buyer(store, SellerClient(client, keys), keyring, settings, plan)
            yield {"resources": _resources(settings, store, client, flow)}
        finally:
            await client.aclose()
            store.close()

    agent = FastAPI(title="Demo buyer", lifespan=lifespan)
    install_handlers(agent)
    agent.include_router(api)
    agent.include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])
    # A live key source: the middleware reads the keyring on every directory fetch.
    return DirectoryMiddleware(
        agent,
        keyring.published,
        identity=ServerIdentity.from_config(str(settings.self_origin)),
        publish=PublishPolicy(max_age=settings.directory_max_age),
    )


def _resources(
    settings: BuyerSettings, store: BuyerRepository, client: HTTPClient, flow: Buyer
) -> BuyerResources:
    # The buyer knows the seller by its origin only, and its domain is that origin's host.
    # The token is the bearer flow's credential.
    seller = settings.peer_seller_origin
    store.add_counterparty(
        Counterparty(
            origin=seller,
            domain=seller.host,
            legal_name="Demo Seller Inc.",
            bearer_token=settings.bearer_token,
        )
    )
    cfbot = Cfbot(client, settings.peer_cfbot_origin, lambda: flow.signer)
    return BuyerResources(settings, store, flow.keyring, client, flow, cfbot)


def app_from_env() -> ASGIApp:
    """Uvicorn's factory: the buyer as its environment configures it."""
    return create_app(BuyerSettings.from_env())
