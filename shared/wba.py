"""Web Bot Auth wiring both parties share. Every rule comes from the library module.

Each agent's lifespan builds one TLS context and one client from these, uses
them for every call it makes, and closes the client on shutdown.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import httpx
from iab_agentic_primitives.web_bot_auth import DirectoryResolver, FetchPolicy

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
    policy = FetchPolicy() if max_cache_age is None else FetchPolicy(max_cache_age=max_cache_age)
    return DirectoryResolver(policy, client=client)
