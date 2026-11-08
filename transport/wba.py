"""Web Bot Auth wiring both parties share, and the one codec between the wire, the kept
values (persistence/values.py), and the library's own types. Every rule comes from the
library module.

Each agent's lifespan builds one TLS context and one client from these, uses
them for every call it makes, and closes the client on shutdown.

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

import httpx
from iab_agentic_primitives.web_bot_auth import (
    DirectoryResolver,
    DirectoryResponse,
    HeaderLines,
    HTTPRequest,
    HTTPResponse,
    MemoryDirectoryStore,
    ServerIdentity,
)
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from iab_agentic_primitives.web_bot_auth.asgi import Scope, request_url
from iab_agentic_primitives.web_bot_auth.fetcher import HttpxDirectoryFetcher

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
    store = (
        MemoryDirectoryStore()
        if max_cache_age is None
        else MemoryDirectoryStore(max_cache_age=max_cache_age)
    )
    return DirectoryResolver(HttpxDirectoryFetcher(client), store)


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
    """Whether a message carries signature fields, by the library's rule."""
    return HeaderLines(tuple(lines)).is_signed()


def request_of(scope: Scope, identity: ServerIdentity, body: bytes) -> KeptRequest:
    """The request an ASGI app received, as the library verifies it: the URL rebuilt on the
    server's own base URL, and every field line as received."""
    method, raw = scope["method"], scope["headers"]
    if not isinstance(method, str) or not isinstance(raw, Iterable):
        raise NotAnHTTPScopeError(scope)
    return KeptRequest(
        method=method, url=request_url(scope, identity), lines=lines_of(raw), body=body
    )


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
        fetch.url, fetch.status, list(fetch.lines), fetch.body, fetch.fetched_at
    )


def origin_of(origin: LibraryOrigin) -> Origin:
    """An origin the library established, as the demo holds it."""
    return Origin(host=origin.host)


def library_origin(origin: Origin) -> LibraryOrigin:
    """An origin as the library takes it."""
    return LibraryOrigin(origin.host)
