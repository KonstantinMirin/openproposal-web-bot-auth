"""What an agent's lifespan opens, and how a request reads it.

Both agents compose the same way: `create_app` reads its settings, builds what
needs no I/O, and passes `lifespan(...)` the store to open and a function that
builds its resources from the open store and client. The lifespan only opens,
yields, and closes. It opens the store first and the one HTTP client next, on
one `AsyncExitStack`, so any later failure, a bad `ca_bundle` included, closes
what was already open, and shutdown closes both.

The lifespan yields `{"resources": <its resources>}`, which Starlette hands
every request as `request.state`. `state_of` is the one reader of it, and it
returns a typed value.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager, closing
from pathlib import Path
from typing import Protocol

import httpx
from fastapi import Request
from iab_agentic_primitives.web_bot_auth import KeyResolver

from .wba import Transport, directory_resolver, http_client, tls_context


class Store(Protocol):
    """An agent's store, which its lifespan closes."""

    def close(self) -> None: ...


#: What a lifespan is to FastAPI: entered with the app, it yields the request state.
Lifespan = Callable[[object], AbstractAsyncContextManager[Mapping[str, object]]]


def lifespan[S: Store](
    open_store: Callable[[], S],
    ca_bundle: Path | None,
    resources: Callable[[S, httpx.AsyncClient], object],
    *,
    transport: Transport | None = None,
) -> Lifespan:
    """The lifespan that opens the store, then the client that trusts `ca_bundle`, yields
    `resources(store, client)`, and closes both. `transport` is for tests."""

    @asynccontextmanager
    async def run(_app: object) -> AsyncIterator[Mapping[str, object]]:
        async with AsyncExitStack() as opened:
            store = opened.enter_context(closing(open_store()))
            client = await opened.enter_async_context(
                http_client(tls_context(ca_bundle), transport=transport)
            )
            yield {"resources": resources(store, client)}

    return run


def resolver_or_default(
    client: httpx.AsyncClient, max_cache_age: int | None, resolver: KeyResolver | None
) -> KeyResolver:
    """`resolver` when a test or a deployment injects one, or the directory resolver both
    parties verify with, fetching through `client`."""
    if resolver is not None:
        return resolver
    return directory_resolver(client, max_cache_age=max_cache_age)


class LifespanNotRunError(RuntimeError):
    """A request arrived without the lifespan's resources: the app was served without its
    lifespan, or the lifespan yielded something else."""


def state_of[T](request: Request, kind: type[T]) -> T:
    """The `kind` value the lifespan yielded as `resources`."""
    value = getattr(request.state, "resources", None)
    if not isinstance(value, kind):
        raise LifespanNotRunError(kind.__name__)
    return value
