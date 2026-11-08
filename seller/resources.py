"""What the seller's lifespan opens, and the typed providers handlers read it from.

`create_app` (seller/app.py) opens these once at startup and closes them on
shutdown. `resources` is the one function that reads the lifespan's state
(through transport/lifespan.py). Every route asks for a port of the one store
(`OfferStoreDep`, `OnboardingDep`), and seller/http.py takes the identity
boundary and the evidence port (`KeptEvidenceDep`) from here, so the boundary
resolves the caller in the same database the handlers then write to. Every
provider is `async def`, so FastAPI runs it on the event loop's thread, where the
store's connection lives (persistence/sqlite.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import httpx
from fastapi import Depends, Request

from transport.lifespan import state_of

from .boundary import IdentityBoundary
from .offers.issuance import Issuer
from .ports import KeptEvidence, OfferStore, Onboarding
from .sqlite_store import SqliteSellerStore


@dataclass(frozen=True)
class SellerResources:
    store: SqliteSellerStore
    #: The one client every directory fetch goes through.
    client: httpx.AsyncClient
    #: The identity boundary, over the store's principals and the request verifier.
    boundary: IdentityBoundary
    #: What every proposal starts from: the seller's own party and the template, read once.
    issuer: Issuer


async def resources(request: Request) -> SellerResources:
    """The resources the lifespan yielded."""
    return state_of(request, SellerResources)


ResourcesDep = Annotated[SellerResources, Depends(resources)]


async def offer_store(resources: ResourcesDep) -> OfferStore:
    return resources.store


async def onboarding(resources: ResourcesDep) -> Onboarding:
    return resources.store


async def kept_evidence(resources: ResourcesDep) -> KeptEvidence:
    return resources.store


async def boundary(resources: ResourcesDep) -> IdentityBoundary:
    return resources.boundary


async def issuer(resources: ResourcesDep) -> Issuer:
    return resources.issuer


OfferStoreDep = Annotated[OfferStore, Depends(offer_store)]
OnboardingDep = Annotated[Onboarding, Depends(onboarding)]
KeptEvidenceDep = Annotated[KeptEvidence, Depends(kept_evidence)]
BoundaryDep = Annotated[IdentityBoundary, Depends(boundary)]
IssuerDep = Annotated[Issuer, Depends(issuer)]
