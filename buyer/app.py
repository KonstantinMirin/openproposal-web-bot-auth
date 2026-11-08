"""The buyer agent: its signed key directory, and an operator trigger that runs the flow.

`create_app(settings)` is the buyer's composition root, and nothing happens at
import time. Uvicorn builds the app with `--factory buyer.app:app_from_env`,
the only caller of `BuyerSettings.from_env()`.

Agents reach `buyer.wba-demo.noetis.dev` only for the directory, which
`DirectoryMiddleware` serves from the key store, which holds the keys in memory. The
`/operator/` routes are the buyer's own controls, each registered from its
`ControlOp` (transport/control.py): no front routes them, so they are reachable
only inside the network, and each call carries the operator key
(transport/operator.py).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus

from fastapi import APIRouter, Depends, FastAPI
from iab_agentic_primitives.web_bot_auth import (
    ConfigurationError,
    DirectoryPublisher,
    KeyResolver,
    PublishPolicy,
)
from iab_agentic_primitives.web_bot_auth.asgi import DirectoryMiddleware
from iab_agentic_primitives.web_bot_auth.rules import MESSAGE_WINDOW
from starlette.types import ASGIApp

from persistence.values import Origin
from protocol.documents import loads_yaml
from shared.keyring import Keyring, SigningIdentity
from shared.settings import SettingsError
from transport.control import (
    ACTIVATE,
    CLOUDFLARE_CHECK,
    COMMIT,
    HEALTH,
    KEYS,
    PUBLISH,
    READ,
    RETIRE,
    CloudflareCheck,
    CommitTrigger,
    Health,
    KeyState,
    Outcome,
    PublishedKey,
    ReadTrigger,
)
from transport.lifespan import lifespan, resolver_or_default
from transport.operator import ControlError, OperatorKey, control_route
from transport.wba import Transport, library_origin

from .cfbot import Cfbot
from .flow import Buyer
from .http import install_handlers
from .plan import Plan
from .repository import BuyerRepository, NotPendingError
from .resources import BuyerResources, CfbotDep, FlowDep, KeyringDep, SettingsDep
from .seller_client import HTTPClient, SellerClient
from .settings import BuyerSettings

#: The routes any caller reaches. Agents reach only the directory, which the middleware serves.
api = APIRouter()


@control_route(api, HEALTH)
async def health() -> Health:
    return Health(ok=True)


#: The buyer's own controls. `create_app` puts the operator-key guard on them.
operator = APIRouter()


def _seller(trigger: ReadTrigger, settings: BuyerSettings) -> Origin:
    return settings.peer_seller_origin if trigger.seller is None else trigger.seller


@control_route(operator, COMMIT)
async def operator_commit(trigger: CommitTrigger, flow: FlowDep, settings: SettingsDep) -> Outcome:
    """Runs the whole flow: read, commit, verify the signed answer, keep the evidence.

    A commit another trigger settled while this one waited for the seller answers 409
    `not-pending`, and nothing of this trigger's answer is kept.
    """
    try:
        return await flow.commit(
            _seller(trigger, settings),
            trigger.proposal_id,
            trigger.line_item_ids,
            trigger.credential,
        )
    except NotPendingError as e:
        detail = f"commit {e} is no longer pending, so it stays settled"
        raise ControlError(HTTPStatus.CONFLICT, "not-pending", detail) from e


@control_route(operator, READ)
async def operator_read(trigger: ReadTrigger, flow: FlowDep, settings: SettingsDep) -> Outcome:
    """Reads the proposal and verifies the seller's signed response."""
    return await flow.read(_seller(trigger, settings), trigger.proposal_id, trigger.credential)


def _keys(keyring: Keyring) -> KeyState:
    return KeyState(
        published=[k.thumbprint for k in keyring.store.published()],
        active=keyring.store.active().thumbprint,
    )


@control_route(operator, KEYS)
async def list_keys(keyring: KeyringDep) -> KeyState:
    return _keys(keyring)


@control_route(operator, PUBLISH)
async def publish_key(keyring: KeyringDep) -> PublishedKey:
    """Rotation, step 1: publish a new key next to the old one, which keeps signing."""
    kid = keyring.publish().thumbprint
    return PublishedKey(published_kid=kid, **_keys(keyring).model_dump())


@control_route(operator, ACTIVATE)
async def activate_key(kid: str, keyring: KeyringDep) -> KeyState:
    """Rotation, step 2: sign with the new key, once verifiers' caches list it."""
    keyring.activate(kid)
    return _keys(keyring)


@control_route(operator, RETIRE)
async def retire_key(kid: str, keyring: KeyringDep) -> KeyState:
    """Rotation, step 3: take the old key out of the directory, once its signatures expired."""
    keyring.retire(kid)
    return _keys(keyring)


@control_route(operator, CLOUDFLARE_CHECK)
async def cloudflare_check(cfbot: CfbotDep, settings: SettingsDep) -> CloudflareCheck:
    """Signs a request to cfbot, whose verifier is Cloudflare's library, and returns its verdict."""
    body = json.dumps({"from": str(settings.self_origin), "says": "verify me"}).encode()
    return await cfbot.verify(body)


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

    The result is the FastAPI app inside the library's `DirectoryMiddleware`. A
    signature lifetime the library wouldn't sign with stops the boot with
    `SettingsError`, naming `WBA_SIGNATURE_LIFETIME`, before any key is minted.
    """
    _check_lifetime(settings.signature_lifetime)
    plan = Plan.of(loads_yaml(settings.plan_file.read_text(encoding="utf-8")))
    # The buyer mints its first key on first boot only. Its signer and its directory read the
    # key store, which each rotation step refreshes.
    keyring = Keyring.create(
        settings.keys_dir,
        directory_max_age=settings.directory_max_age,
        signature_lifetime=settings.signature_lifetime,
        clock=clock,
    )
    signing = SigningIdentity(keyring, settings.self_origin)
    resources = _Parts(settings, signing, plan, resolver).resources
    store = partial(BuyerRepository, settings.data_dir / "buyer.db")
    opened = lifespan(store, settings.ca_bundle, resources, transport=transport)
    agent = FastAPI(title="Demo buyer", lifespan=opened)
    install_handlers(agent)
    agent.include_router(api)
    agent.include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])
    # A live key source: each fetch lists the keys the store holds now.
    return DirectoryMiddleware(
        agent,
        DirectoryPublisher(
            library_origin(settings.self_origin),
            keyring.store.published,
            PublishPolicy(max_age=settings.directory_max_age),
        ),
    )


def _check_lifetime(lifetime: int) -> None:
    """Refuses, at boot, a lifetime outside the library's rule for every signer: 1 to 300 s."""
    try:
        MESSAGE_WINDOW.checked_lifetime(lifetime)
    except ConfigurationError as e:
        raise SettingsError("WBA_SIGNATURE_LIFETIME", str(e)) from e


@dataclass(frozen=True)
class _Parts:
    """What `create_app` builds before the lifespan opens the store and the client."""

    settings: BuyerSettings
    #: The buyer's one signing identity, over its keyring; the flow and cfbot both sign with it.
    signing: SigningIdentity
    plan: Plan
    resolver: KeyResolver | None

    def resources(self, store: BuyerRepository, client: HTTPClient) -> BuyerResources:
        """The buyer's resources over its open store and client: the offer flow, with the
        sellers its settings name on this boot, and cfbot, both signing with the one signing
        identity."""
        settings = self.settings
        signing = self.signing
        keys = resolver_or_default(client, settings.max_cache_age, self.resolver)
        sellers = SellerClient(client, keys, settings.own)
        flow = Buyer(store, settings.counterparties, sellers, signing, self.plan)
        cfbot = Cfbot(client, settings.peer_cfbot_origin, signing)
        return BuyerResources(settings, store, signing.keyring, client, flow, cfbot)


def app_from_env() -> ASGIApp:
    """Uvicorn's factory: the buyer as its environment configures it."""
    return create_app(BuyerSettings.from_env())
