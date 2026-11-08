"""The ports of key resolution: what a verifier asks for, and what a resolver composes. No I/O.

- :class:`KeyResolver` is what a verifier calls: ``(origin, keyid)`` at
  ``now`` to a :class:`ResolvedKey`.
- :class:`DirectoryFetcher` fetches a directory response from the network.
- :class:`DirectoryStore` keeps directory responses and failure deadlines as
  plain data, and only keeps them: the resolver verifies what it returns
  again, and decides what a stored directory is still good for.

:class:`~.resolver.DirectoryResolver` composes a fetcher and a store;
:class:`~.fetcher.HttpxDirectoryFetcher` and
:class:`~.resolver.MemoryDirectoryStore` are the defaults.
:func:`~.testing.check_directory_store` checks a store against this contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .directory import DirectoryResponse, FetchLimits, VerifiedDirectory
from .values import KeyId, Origin, UnixSeconds


@dataclass(frozen=True, slots=True)
class ResolvedKey:
    """A resolved public key, and the verified directory it came from when there is one.

    ``directory`` keeps the directory response as evidence; a resolver with no
    directory, such as :class:`~.resolver.StaticKeyResolver`, leaves it ``None``.
    """

    public_key: Ed25519PublicKey
    directory: VerifiedDirectory | None = None


@runtime_checkable
class KeyResolver(Protocol):
    """Returns the key ``keyid`` of the identity ``origin`` at ``now``, or raises a ``403``."""

    async def resolve(self, origin: Origin, keyid: KeyId, *, now: UnixSeconds) -> ResolvedKey: ...


@runtime_checkable
class DirectoryFetcher(Protocol):
    """Fetches ``origin``'s directory response, from ``origin.directory_url`` exactly.

    The fetcher applies ``limits``' timeouts, reads at most
    ``limits.max_bytes`` plus one byte of body, never follows a redirect, and
    stamps the response with ``now``. It returns any status; the fetch rules
    are checked afterwards.

    When the directory can't be fetched, it raises a ``directory-unavailable``
    :class:`~.errors.WebBotAuthError` and nothing else; any other error is a
    bug that propagates. A transport or client that refuses an address for
    the deployment's policy (OpenProposal § 2.8.3, Web Bot Auth section 6.7)
    raises :class:`~.fetcher.BlockedAddress`, which
    :class:`~.fetcher.HttpxDirectoryFetcher` turns into that refusal like
    every other transport failure.
    """

    async def fetch(
        self, origin: Origin, *, limits: FetchLimits, now: UnixSeconds
    ) -> DirectoryResponse: ...


@runtime_checkable
class DirectoryStore(Protocol):
    """Keeps each origin's last directory response, and when its failed fetches stop holding.

    The store persists plain data and decides nothing. :meth:`put` keeps the
    :class:`~.directory.DirectoryResponse` a resolver verified for
    ``origin``, replacing that origin's last one and no other's; :meth:`get`
    returns what :meth:`put` kept for ``origin``, or ``None``. A response is
    its URL, status, field lines, body bytes, and ``fetched_at``, so a store
    outside the process can serialize it, for example from
    :meth:`~.directory.DirectoryResponse.document`. The resolver verifies
    what :meth:`get` returns again, as fetched and under its own limits,
    then judges its expiry and age; a response that doesn't verify is a
    cache miss. :meth:`record_failure` keeps the time until which a failed
    fetch of ``origin`` holds, and :meth:`failure_until` returns it, or
    ``None``.
    """

    async def get(self, origin: Origin) -> DirectoryResponse | None: ...

    async def put(self, origin: Origin, response: DirectoryResponse) -> None: ...

    async def record_failure(self, origin: Origin, until: UnixSeconds) -> None: ...

    async def failure_until(self, origin: Origin) -> UnixSeconds | None: ...


__all__ = [
    "DirectoryFetcher",
    "DirectoryStore",
    "KeyResolver",
    "ResolvedKey",
]
