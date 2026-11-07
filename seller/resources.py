"""What the seller's lifespan opens, and the typed providers handlers and the boundary read it from.

`create_app` (seller/app.py) opens these once at startup and closes them on
shutdown. `resources` is the one function that reads the lifespan's state
(through shared/lifespan.py). Every route and the identity boundary ask for a
port of the one store (`BoundaryRecordsDep`, `OfferStoreDep`, `OnboardingDep`),
or for `VerifierDep` or `IdentityDep`, so the boundary resolves the caller in
the same database the handlers then write to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import httpx
from fastapi import Depends, Request
from iab_agentic_primitives.web_bot_auth import RequestVerifier, ServerIdentity

from shared.lifespan import state_of

from .ports import BoundaryRecords, OfferStore, Onboarding
from .sqlite_store import SqliteSellerStore


@dataclass(frozen=True)
class SellerResources:
    identity: ServerIdentity
    store: SqliteSellerStore
    #: The one client every directory fetch goes through.
    client: httpx.AsyncClient
    verifier: RequestVerifier


def resources(request: Request) -> SellerResources:
    """The resources the lifespan yielded."""
    return state_of(request, SellerResources)


ResourcesDep = Annotated[SellerResources, Depends(resources)]


def boundary_records(resources: ResourcesDep) -> BoundaryRecords:
    return resources.store


def offer_store(resources: ResourcesDep) -> OfferStore:
    return resources.store


def onboarding(resources: ResourcesDep) -> Onboarding:
    return resources.store


def verifier(resources: ResourcesDep) -> RequestVerifier:
    return resources.verifier


def identity(resources: ResourcesDep) -> ServerIdentity:
    return resources.identity


BoundaryRecordsDep = Annotated[BoundaryRecords, Depends(boundary_records)]
OfferStoreDep = Annotated[OfferStore, Depends(offer_store)]
OnboardingDep = Annotated[Onboarding, Depends(onboarding)]
VerifierDep = Annotated[RequestVerifier, Depends(verifier)]
IdentityDep = Annotated[ServerIdentity, Depends(identity)]
