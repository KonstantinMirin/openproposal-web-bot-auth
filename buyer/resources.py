"""What the buyer's lifespan opens, and the typed providers its routes read it from.

`create_app` (buyer/app.py) opens these once at startup and closes them on
shutdown. `resources` is the one function that reads the lifespan's state
(through transport/lifespan.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request

from shared.keyring import Keyring
from transport.lifespan import state_of

from .cfbot import Cfbot
from .flow import Buyer
from .repository import BuyerRepository
from .seller_client import HTTPClient
from .settings import BuyerSettings


@dataclass(frozen=True)
class BuyerResources:
    settings: BuyerSettings
    store: BuyerRepository
    keyring: Keyring
    #: The one client every call to a seller, a directory, or cfbot goes through.
    client: HTTPClient
    #: The offer flow, over the store, the seller client, the signing identity, and the plan.
    flow: Buyer
    #: The one peer the buyer signs for without verifying an answer.
    cfbot: Cfbot


def resources(request: Request) -> BuyerResources:
    """The resources the lifespan yielded."""
    return state_of(request, BuyerResources)


ResourcesDep = Annotated[BuyerResources, Depends(resources)]


def settings(resources: ResourcesDep) -> BuyerSettings:
    return resources.settings


def keyring(resources: ResourcesDep) -> Keyring:
    return resources.keyring


def flow(resources: ResourcesDep) -> Buyer:
    return resources.flow


def cfbot(resources: ResourcesDep) -> Cfbot:
    return resources.cfbot


SettingsDep = Annotated[BuyerSettings, Depends(settings)]
KeyringDep = Annotated[Keyring, Depends(keyring)]
FlowDep = Annotated[Buyer, Depends(flow)]
CfbotDep = Annotated[Cfbot, Depends(cfbot)]
