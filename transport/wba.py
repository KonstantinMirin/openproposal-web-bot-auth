"""Web Bot Auth wiring both parties share, and the one codec between the wire, the kept
values (persistence/values.py), and the library's own types. Every rule comes from the
library module.

Each agent's lifespan opens one `Network` from these: one transport, which
trusts the agent's TLS context, a plain client over it for directory fetches,
and the Web Bot Auth clients the library builds over the same transport, one
per call. Shutdown closes the plain client, and with it the transport.

The codec is the only code that turns field lines from bytes into text and
back: `lines_of` decodes, `asgi_lines` encodes, and both use latin-1, which
maps every byte to one character and back. The rest of the demo holds text
lines, as the library's `HTTPRequest` and `HTTPResponse` do. The codec also
converts the demo's `Origin`, `KeptRequest`, `KeptResponse`, and
`DirectoryFetch` to and from the library's types, here and nowhere else.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType
from typing import Self

import httpx
from iab_agentic_primitives.web_bot_auth import (
    CachePolicy,
    DirectoryResolver,
    DirectoryResponse,
    HeaderLines,
    HTTPRequest,
    HTTPResponse,
    UnixSeconds,
)
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from iab_agentic_primitives.web_bot_auth import is_signed as library_is_signed
from iab_agentic_primitives.web_bot_auth.asgi import Scope, ServerEdge
from iab_agentic_primitives.web_bot_auth.fetcher import HttpxDirectoryFetcher
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth
from iab_agentic_primitives.web_bot_auth.httpx import sent_request as library_sent_request

from persistence.values import DirectoryFetch, HeaderLine, KeptRequest, KeptResponse, Origin

#: The encoding of a field line on the wire, as RFC 9110 reads it: each byte one character.
_WIRE = "latin-1"

#: What answers a client's requests: the network by default, a stand-in in tests.
Transport = httpx.AsyncBaseTransport


def tls_context(ca_bundle: Path | None) -> ssl.SSLContext:
    """The trust store: `ca_bundle` (public roots plus the demo CA in the e2e stack), or the
    system's when it is None."""
    return ssl.create_default_context(cafile=ca_bundle)


def http_client(
    context: ssl.SSLContext,
    *,
    timeout: float = 5.0,
    transport: Transport | None = None,
) -> httpx.AsyncClient:
    """A plain client that trusts `context` and never follows redirects.

    A production deployment injects an SSRF-guarded client here. The demo
    doesn't: address policy is outside what it demonstrates. `transport` is for
    tests, which answer in place of the network.
    """
    return httpx.AsyncClient(
        verify=context,
        follow_redirects=False,
        trust_env=False,
        timeout=timeout,
        transport=transport,
    )


class _Borrowed(httpx.AsyncBaseTransport):
    """The network's transport, lent to one Web Bot Auth client: closing the client leaves
    it open for the next."""

    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(request)


class Network:
    """An agent's one way to the network: one transport that trusts `context` and never
    follows redirects, the plain `client` over it, and a Web Bot Auth client per call
    (`signed`). `transport` is for tests, which answer in place of the network.

    A production deployment injects an SSRF-guarded transport here. The demo
    doesn't: address policy is outside what it demonstrates.
    """

    def __init__(
        self, context: ssl.SSLContext, *, timeout: float = 5.0, transport: Transport | None = None
    ) -> None:
        self._transport = (
            httpx.AsyncHTTPTransport(verify=context) if transport is None else transport
        )
        self._timeout = timeout
        #: The plain client, for directory fetches; it owns the transport and closes it.
        self.client = httpx.AsyncClient(
            transport=self._transport, follow_redirects=False, trust_env=False, timeout=timeout
        )

    def signed(self, auth: WebBotAuth) -> httpx.AsyncClient:
        """The library's client for `auth`, which signs and verifies each request, over the
        network's transport."""
        return auth.async_client(
            transport=_Borrowed(self._transport), follow_redirects=False, timeout=self._timeout
        )

    async def __aenter__(self) -> Self:
        await self.client.__aenter__()
        return self

    async def __aexit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        await self.client.__aexit__(kind, error, trace)


def directory_resolver(
    client: httpx.AsyncClient, *, max_cache_age: int | None
) -> DirectoryResolver:
    """The resolver both parties verify with, fetching through `client`. Each
    `VerifiedRequest` and `VerifiedResponse` it yields carries the verified
    directory response, which § 4.1.2 asks a party to keep.

    `max_cache_age` shortens how long a cached directory answers without a
    fetch, for the e2e stack's rotation scenario. None keeps the library's
    default, 300 s.
    """
    cache = CachePolicy() if max_cache_age is None else CachePolicy(max_cache_age=max_cache_age)
    return DirectoryResolver(HttpxDirectoryFetcher(client), cache=cache)


# The codec


class NotAnHTTPScopeError(TypeError):
    """An ASGI scope without an HTTP method and field lines."""

    def __init__(self, scope: Scope) -> None:
        super().__init__(f"not an HTTP scope: {scope.get('type')!r}")


def lines_of(raw: Iterable[tuple[bytes, bytes]]) -> tuple[HeaderLine, ...]:
    """Field lines as the wire carries them, as text: in order, each name in its own case."""
    return tuple((name.decode(_WIRE), value.decode(_WIRE)) for name, value in raw)


def asgi_lines(lines: Iterable[HeaderLine]) -> list[tuple[bytes, bytes]]:
    """Field lines as ASGI sends them: lowercase names, and the bytes `lines_of` decoded."""
    return [(name.lower().encode(_WIRE), value.encode(_WIRE)) for name, value in lines]


def is_signed(lines: Iterable[HeaderLine]) -> bool:
    """Whether a message is signed, by the library's rule: it carries `Signature-Input`."""
    return library_is_signed(HeaderLines(tuple(lines)))


def request_of(scope: Scope, edge: ServerEdge, body: bytes) -> KeptRequest:
    """The request an ASGI app received, as the library verifies it: the URL rebuilt on the
    base URL of the server's one identity (`edge`), and every field line as received."""
    method, raw = scope["method"], scope["headers"]
    if not isinstance(method, str) or not isinstance(raw, Iterable):
        raise NotAnHTTPScopeError(scope)
    return KeptRequest(method=method, url=edge.request_url(scope), lines=lines_of(raw), body=body)


class NotSentByWebBotAuthError(ValueError):
    """A response no Web Bot Auth client received, so there is no request as sent."""


def sent_request(response: httpx.Response) -> KeptRequest:
    """The request the library's client sent for `response`, exactly as on the wire: the URL
    the signature covers, and every field line as sent but `Authorization`, so a bearer
    token is never kept."""
    sent = library_sent_request(response)
    if sent is None:
        raise NotSentByWebBotAuthError(str(response.url))
    lines = tuple((k, v) for k, v in sent.headers.items() if k.lower() != "authorization")
    return KeptRequest(method=sent.method, url=sent.url, lines=lines, body=sent.body)


def to_library(request: KeptRequest) -> HTTPRequest:
    """A kept request as the library's `HTTPRequest`."""
    return HTTPRequest(request.method, request.url, list(request.lines), request.body)


def response_to_library(response: KeptResponse) -> HTTPResponse:
    """A kept response as the library's `HTTPResponse`, bound to its request."""
    return HTTPResponse(
        response.status, list(response.lines), response.body, to_library(response.request)
    )


def fetch_of(evidence: DirectoryResponse) -> DirectoryFetch:
    """The directory response a verification used, as a party keeps it."""
    return DirectoryFetch(
        url=evidence.url,
        status=evidence.status,
        lines=evidence.headers.items(),
        body=evidence.body,
        fetched_at=evidence.fetched_at,
    )


def directory_response_of(fetch: DirectoryFetch) -> DirectoryResponse:
    """A kept directory fetch as the library's `DirectoryResponse`, to verify it again."""
    return DirectoryResponse(
        fetch.url, fetch.status, fetch.lines, fetch.body, UnixSeconds(fetch.fetched_at)
    )


def origin_of(origin: LibraryOrigin) -> Origin:
    """An origin the library established, as the demo holds it."""
    return Origin(host=origin.host)


def library_origin(origin: Origin) -> LibraryOrigin:
    """An origin as the library takes it."""
    return LibraryOrigin(origin.host)
