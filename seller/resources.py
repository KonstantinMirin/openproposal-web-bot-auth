"""What the seller's lifespan opens, and the typed providers handlers read it from.

`create_app` (seller/app.py) opens these once at startup and closes them on
shutdown. `resources` is the one function that reads the lifespan's state
(through shared/lifespan.py). Every route asks for a port of the one store
(`OfferStoreDep`, `OnboardingDep`), and seller/http.py takes the identity
boundary from here, so the boundary resolves the caller in the same database
the handlers then write to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import httpx
from fastapi import Depends, Request

from protocol.values import JsonObject
from shared.lifespan import state_of

from .boundary import IdentityBoundary
from .ports import OfferStore, Onboarding
from .sqlite_store import SqliteSellerStore


@dataclass(frozen=True)
class SellerResources:
    store: SqliteSellerStore
    #: The one client every directory fetch goes through.
    client: httpx.AsyncClient
    #: The identity boundary, over the store's principals and the request verifier.
    boundary: IdentityBoundary
    #: The proposal every buyer is issued, loaded once at startup.
    template: JsonObject


def resources(request: Request) -> SellerResources:
    """The resources the lifespan yielded."""
    return state_of(request, SellerResources)


ResourcesDep = Annotated[SellerResources, Depends(resources)]


def offer_store(resources: ResourcesDep) -> OfferStore:
    return resources.store


def onboarding(resources: ResourcesDep) -> Onboarding:
    return resources.store


def boundary(resources: ResourcesDep) -> IdentityBoundary:
    return resources.boundary


def template(resources: ResourcesDep) -> JsonObject:
    return resources.template


OfferStoreDep = Annotated[OfferStore, Depends(offer_store)]
OnboardingDep = Annotated[Onboarding, Depends(onboarding)]
BoundaryDep = Annotated[IdentityBoundary, Depends(boundary)]
TemplateDep = Annotated[JsonObject, Depends(template)]
