"""The httpx directory fetcher: one client, its TLS, the timeouts, and the bounded read.

:class:`HttpxDirectoryFetcher` is the default
:class:`~.ports.DirectoryFetcher`. It fetches exactly the URL it is given, with
``Accept-Encoding: identity``, never follows a redirect, and reads the body as
sent, in chunks, stopping one byte past the cap. It translates every transport
failure, and only those, to a ``directory-unavailable`` refusal.

It leaves address policy to the client: in production, inject one that guards
against server-side request forgery, and have it raise :class:`BlockedAddress`
for an address it refuses.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from types import TracebackType

import httpx

from .directory import DirectoryResponse, FetchLimits
from .errors import ConfigurationError, Refusal, refuse
from .values import DIRECTORY_MEDIA_TYPE, Origin, UnixSeconds


class BlockedAddress(httpx.TransportError):
    """An address the deployment's policy doesn't let a directory fetch connect to.

    A guarding transport or client raises it, for example for a private or
    loopback address (Web Bot Auth section 6.7). The fetcher turns it into a
    ``directory-unavailable`` refusal, and the resolver holds the failure back
    like any other.
    """


#: The failures of a fetch, as httpx and the TLS and socket layers raise them.
#: :class:`BlockedAddress` is an ``httpx.TransportError``, so it is among them.
_TRANSPORT_ERRORS = (httpx.HTTPError, httpx.InvalidURL, ssl.SSLError, OSError)


@dataclass(frozen=True, slots=True)
class TLSConfig:
    """The trust store of the client the fetcher builds.

    ``ca_bundle`` replaces the system trust store with a PEM file, and
    ``extra_ca`` adds a PEM file of trust anchors to it. The system store
    honors ``SSL_CERT_FILE``.
    """

    ca_bundle: str | None = None
    extra_ca: str | None = None

    def ssl_context(self) -> ssl.SSLContext:
        """A new context with these trust anchors; ``FileNotFoundError`` for a missing file."""
        context = ssl.create_default_context(cafile=self.ca_bundle)
        if self.extra_ca is not None:
            context.load_verify_locations(cafile=self.extra_ca)
        return context


class _Borrowed(httpx.AsyncBaseTransport):
    """A caller's transport, which closing the fetcher's client leaves open."""

    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        self._transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        """The caller closes its own transport."""


def _client(tls: TLSConfig | None, transport: httpx.AsyncBaseTransport | None) -> httpx.AsyncClient:
    if transport is not None:
        if tls is not None:
            raise ConfigurationError("a transport brings its own TLS; pass tls= or transport=")
        return httpx.AsyncClient(transport=_Borrowed(transport), trust_env=False)
    context = (tls or TLSConfig()).ssl_context()
    return httpx.AsyncClient(verify=context, follow_redirects=False, trust_env=False)


async def _bounded(response: httpx.Response, max_bytes: int) -> bytes:
    """The body as sent on the wire, read until it is ``max_bytes`` plus one byte or ends."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_raw():
        chunks.append(chunk)
        size += len(chunk)
        if size > max_bytes:
            break
    return b"".join(chunks)


class HttpxDirectoryFetcher:
    """Fetches directory responses through one ``httpx.AsyncClient``.

    ``client`` is the client every fetch goes through, such as one that guards
    against server-side request forgery; the fetcher never closes it. Without
    one, the fetcher builds one client, once, with ``tls`` as its trust store,
    or on ``transport`` (an ``httpx.ASGITransport`` for an in-process peer, or
    :func:`~.testing.directory_transport` in tests), and closes that client in
    :meth:`aclose`. It never closes a caller's transport. Passing ``tls`` or
    ``transport`` together with ``client`` raises :class:`ConfigurationError`:
    an injected client brings its own TLS.

    The client is bound to the event loop it first fetches on.
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        tls: TLSConfig | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if client is not None and (tls is not None or transport is not None):
            raise ConfigurationError(
                "an injected client brings its own TLS and transport; pass client= alone"
            )
        self._owned = client is None
        self._client = _client(tls, transport) if client is None else client

    async def fetch(
        self, origin: Origin, *, limits: FetchLimits, now: UnixSeconds
    ) -> DirectoryResponse:
        """Fetches ``origin``'s directory; a ``directory-unavailable`` refusal when it fails."""
        url = origin.directory_url
        try:
            async with asyncio.timeout(limits.total_timeout):
                return await self._get(url, limits, now)
        except TimeoutError as e:
            raise refuse(
                Refusal.DIRECTORY_UNAVAILABLE, f"directory fetch of {url} timed out"
            ) from e
        except _TRANSPORT_ERRORS as e:
            raise refuse(
                Refusal.DIRECTORY_UNAVAILABLE, f"directory fetch of {url} failed: {e}"
            ) from e

    async def _get(self, url: str, limits: FetchLimits, now: UnixSeconds) -> DirectoryResponse:
        request = self._client.build_request(
            "GET",
            url,
            headers={"Accept": DIRECTORY_MEDIA_TYPE, "Accept-Encoding": "identity"},
            timeout=httpx.Timeout(limits.total_timeout, connect=limits.connect_timeout),
        )
        response = await self._client.send(request, stream=True, follow_redirects=False)
        try:
            body = await _bounded(response, limits.max_bytes)
        finally:
            await response.aclose()
        return DirectoryResponse(
            str(response.url), response.status_code, response.headers.multi_items(), body, now
        )

    async def aclose(self) -> None:
        """Closes the client the fetcher built; an injected client stays open."""
        if self._owned:
            await self._client.aclose()

    async def __aenter__(self) -> HttpxDirectoryFetcher:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


__all__ = [
    "BlockedAddress",
    "HttpxDirectoryFetcher",
    "TLSConfig",
]
