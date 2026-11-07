"""Web Bot Auth wiring both parties share. Every rule comes from the library module."""

from __future__ import annotations

import os
import ssl

import httpx
from iab_agentic_primitives.web_bot_auth import DirectoryResolver, FetchPolicy


def ca_bundle() -> str | None:
    """The trust store: public roots plus the demo CA in the e2e stack, else the system's."""
    return os.environ.get("SSL_CERT_FILE")


def http_client(**kwargs) -> httpx.AsyncClient:
    """A plain client that trusts `ca_bundle()` and never follows redirects.

    A production deployment injects an SSRF-guarded client here. The demo
    doesn't: address policy is outside what it demonstrates.
    """
    context = ssl.create_default_context(cafile=ca_bundle())
    return httpx.AsyncClient(verify=context, follow_redirects=False, trust_env=False, **kwargs)


def directory_resolver() -> DirectoryResolver:
    """The resolver both parties verify with. Each `VerifiedSignature` it yields carries
    the verified directory, whose `evidence()` § 4.1.2 asks a party to keep.

    `WBA_MAX_CACHE_AGE` shortens how long a cached directory answers without a
    fetch, for the e2e stack's rotation scenario. Production uses the library's
    default, 300 s.
    """
    age = os.environ.get("WBA_MAX_CACHE_AGE")
    policy = FetchPolicy(max_cache_age=float(age)) if age else FetchPolicy()
    return DirectoryResolver(policy, client=http_client())
