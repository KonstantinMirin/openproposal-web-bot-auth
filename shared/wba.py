"""Web Bot Auth wiring both parties share. Every rule comes from the library module.

The one thing added here is evidence: OpenProposal § 4.1.2 says a party that
keeps evidence keeps "the bytes of the key directory it verified against", and
the library's `VerifiedDirectory` holds only the parsed keys. `EvidenceResolver`
captures each directory response its client receives and keeps the bytes of
the ones the library then verified.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass

import httpx
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    DirectoryResolver,
    VerifiedDirectory,
    directory_url,
)


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


@dataclass(frozen=True)
class DirectoryBytes:
    """A directory response as received: its header lines and its exact body."""

    url: str
    headers: list[tuple[str, str]]
    body: bytes


class EvidenceResolver(DirectoryResolver):
    """A `DirectoryResolver` that keeps the bytes of each directory it verified."""

    def __init__(self) -> None:
        self._received: dict[str, DirectoryBytes] = {}
        #: The bytes of the directory now cached for each origin.
        self.verified: dict[str, DirectoryBytes] = {}
        super().__init__(client=http_client(event_hooks={"response": [self._capture]}))

    async def _capture(self, response: httpx.Response) -> None:
        if response.request.url.path == DIRECTORY_PATH and response.status_code == 200:
            await response.aread()
            url = str(response.request.url)
            self._received[url] = DirectoryBytes(url, response.headers.multi_items(), response.content)

    async def fetch(self, origin: str, *, now: float | None = None) -> VerifiedDirectory:
        url = directory_url(origin)
        try:
            directory = await super().fetch(origin, now=now)
        finally:
            received = self._received.pop(url, None)
        # The library verified these bytes, and its cache now holds this directory.
        if received is not None:
            self.verified[origin] = received
        return directory
