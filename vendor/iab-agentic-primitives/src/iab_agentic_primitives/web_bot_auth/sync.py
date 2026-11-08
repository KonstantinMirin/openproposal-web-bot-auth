"""Synchronous code and the async verifiers: one loop, owned by whoever owns the resolver.

The verifiers are async, and a :class:`~.resolver.DirectoryResolver` belongs
to the event loop it first resolves on: its fetches in flight and its
client's connection pool live there. :class:`SyncRuntime` is that loop for
synchronous code. It runs one loop on its own thread for its whole life, and
every sync call runs there, so the pool is reused across calls instead of
being stranded on a closed loop.

.. code-block:: python

    resolver = DirectoryResolver()
    with SyncRuntime(resolver) as runtime:
        verifier = SyncRequestVerifier(RequestVerifier(resolver, ...), runtime=runtime)
        verified = verifier.verify(request)

Create one runtime per resolver, where the resolver is created, and pass it
to every façade and :class:`~.httpx.WebBotAuth` that verifies through that
resolver. Closing the runtime cancels the calls still running, which raise
:class:`ConfigurationError`, closes the resolver, and stops the thread.

A sync call made inside a running event loop raises ``RuntimeError``, as
``asyncio.run`` does, instead of blocking that loop: await the verifier there,
or :meth:`SyncRuntime.run_async` for a resolver the runtime owns.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import Coroutine
from dataclasses import dataclass
from types import TracebackType
from typing import Final, Self, TypeVar

from .errors import ConfigurationError
from .message import HTTPRequest, HTTPResponse
from .resolver import DirectoryResolver
from .roles import RequestConfirmer, ResponseConfirmer
from .values import Origin, UnixSeconds
from .verifier import VerifiedRequest, VerifiedResponse

T = TypeVar("T")


class SyncRuntime:
    """One event loop on its own thread, run under :class:`asyncio.Runner` until :meth:`close`.

    ``resolver``, when given, is the resolver the runtime owns: it is closed
    on the runtime's loop when the runtime closes. Use it as a context
    manager, or call :meth:`close`.
    """

    __slots__ = ("_closed", "_loop", "_ready", "_resolver", "_stopping", "_thread")

    def __init__(self, resolver: DirectoryResolver | None = None) -> None:
        self._resolver: Final = resolver
        self._ready: Final = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stopping: asyncio.Event | None = None
        self._closed = False
        self._thread: Final = threading.Thread(
            target=self._main, name="web-bot-auth-sync", daemon=True
        )
        self._thread.start()
        self._ready.wait()

    def _main(self) -> None:
        with asyncio.Runner() as runner:
            runner.run(self._serve())

    async def _serve(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stopping = asyncio.Event()
        self._ready.set()
        await self._stopping.wait()
        # The calls still running are cancelled before the resolver closes under them.
        current = asyncio.current_task()
        running = [task for task in asyncio.all_tasks() if task is not current]
        for task in running:
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)
        if self._resolver is not None:
            await self._resolver.aclose()

    def _submit(self, coroutine: Coroutine[object, object, T]) -> concurrent.futures.Future[T]:
        if self._closed or self._loop is None:
            coroutine.close()
            raise ConfigurationError("the sync runtime is closed")
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop)

    def run(self, coroutine: Coroutine[object, object, T]) -> T:
        """Runs ``coroutine`` on the runtime's loop and returns its result.

        Raises ``RuntimeError`` inside a running event loop, and
        :class:`ConfigurationError` when the runtime is closed, or closes
        while the call runs.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            coroutine.close()
            raise RuntimeError(
                "a sync verify inside a running event loop would block it; await verify() there"
            )
        try:
            return self._submit(coroutine).result()
        except concurrent.futures.CancelledError as e:
            raise ConfigurationError("the sync runtime closed while the call ran") from e

    async def run_async(self, coroutine: Coroutine[object, object, T]) -> T:
        """Runs ``coroutine`` on the runtime's loop and awaits it from the caller's loop.

        Async code that shares a resolver with synchronous code reaches the
        resolver this way, on its one loop.
        """
        try:
            return await asyncio.wrap_future(self._submit(coroutine))
        except asyncio.CancelledError as e:
            if not self._closed:
                raise
            raise ConfigurationError("the sync runtime closed while the call ran") from e

    def close(self) -> None:
        """Cancels the calls still running, closes the resolver it owns, and stops the thread.

        Closing twice does nothing.
        """
        if self._closed:
            return
        self._closed = True
        if self._loop is not None and self._stopping is not None:
            self._loop.call_soon_threadsafe(self._stopping.set)
        self._thread.join()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class SyncRequestVerifier:
    """A :class:`~.roles.RequestConfirmer` for synchronous code, run on ``runtime``."""

    verifier: RequestConfirmer
    runtime: SyncRuntime

    def verify(self, request: HTTPRequest, *, now: UnixSeconds | None = None) -> VerifiedRequest:
        """:meth:`RequestVerifier.verify`, run to completion on the runtime's loop."""
        return self.runtime.run(self.verifier.verify(request, now=now))


@dataclass(frozen=True, slots=True)
class SyncResponseVerifier:
    """A :class:`~.roles.ResponseConfirmer` for synchronous code, run on ``runtime``."""

    verifier: ResponseConfirmer
    runtime: SyncRuntime

    def verify(
        self,
        response: HTTPResponse,
        *,
        expected_origin: Origin | None = None,
        now: UnixSeconds | None = None,
    ) -> VerifiedResponse:
        """:meth:`ResponseVerifier.verify`, run to completion on the runtime's loop."""
        coroutine = self.verifier.verify(response, expected_origin=expected_origin, now=now)
        return self.runtime.run(coroutine)


__all__ = ["SyncRequestVerifier", "SyncResponseVerifier", "SyncRuntime"]
