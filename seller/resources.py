"""What the seller's lifespan opens, and the typed providers handlers and the boundary read it from.

`create_app` (seller/app.py) opens these once at startup and closes them on
shutdown. `resources` is the one function that reads the lifespan's state
(through shared/lifespan.py). Every route and the identity boundary ask for
`StoreDep`, `VerifierDep`, or `IdentityDep`, so the boundary resolves the
caller in the same database the handlers then write to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import httpx
from fastapi import Depends, Request
from iab_agentic_primitives.web_bot_auth import RequestVerifier, ServerIdentity

from shared.lifespan import state_of

from .store import Store


@dataclass(frozen=True)
class SellerResources:
    identity: ServerIdentity
    store: Store
    #: The one client every directory fetch goes through.
    client: httpx.AsyncClient
    verifier: RequestVerifier


def resources(request: Request) -> SellerResources:
    """The resources the lifespan yielded."""
    return state_of(request, SellerResources)


ResourcesDep = Annotated[SellerResources, Depends(resources)]


def store(resources: ResourcesDep) -> Store:
    return resources.store


def verifier(resources: ResourcesDep) -> RequestVerifier:
    return resources.verifier


def identity(resources: ResourcesDep) -> ServerIdentity:
    return resources.identity


StoreDep = Annotated[Store, Depends(store)]
VerifierDep = Annotated[RequestVerifier, Depends(verifier)]
IdentityDep = Annotated[ServerIdentity, Depends(identity)]
