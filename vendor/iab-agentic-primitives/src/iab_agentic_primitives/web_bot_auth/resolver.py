"""Key resolution: from ``(origin, keyid)`` to an Ed25519 public key.

:class:`DirectoryResolver` composes a :class:`~.ports.DirectoryFetcher` and a
:class:`~.ports.DirectoryStore`, and owns every rule about what a stored
directory is good for (OpenProposal § 2.8.3):

- It fetches exactly ``https://<host>/.well-known/http-message-signatures-directory``
  and verifies the response with :func:`~.directory.verify_directory` under
  one :class:`~.directory.FetchLimits`.
- A stored directory answers only for its own origin, and only until the
  earliest ``expires`` among its signatures, whatever the store returns.
- While it is younger than :attr:`CachePolicy.max_cache_age` it answers every
  keyid without a fetch. A directory that resolves without the key replaces
  the stored one. A failed fetch does not evict it, and isn't retried for
  :attr:`CachePolicy.negative_ttl` seconds.
- Concurrent resolves of one origin share one fetch.

Keys are always looked up by the pair ``(origin, keyid)``, never by ``keyid``
alone. :class:`StaticKeyResolver` resolves from keys pinned by configuration,
with no network.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import partial
from types import TracebackType
from typing import TYPE_CHECKING, Final

from .directory import (
    DEFAULT_LIMITS,
    FetchLimits,
    KeyInput,
    KeySet,
    VerifiedDirectory,
    verify_directory,
)
from .errors import ConfigurationError, Refusal, WebBotAuthError, refuse
from .ports import DirectoryFetcher, DirectoryStore, KeyResolver, ResolvedKey
from .rules import CACHE
from .values import KeyId, Origin, UnixSeconds, whole_number

if TYPE_CHECKING:
    from .fetcher import HttpxDirectoryFetcher

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CachePolicy:
    """How long a resolver keeps a directory. It checks itself.

    A directory answers without a fetch for ``max_cache_age`` seconds after it
    was fetched (300 by default), and a failed fetch isn't retried for
    ``negative_ttl`` seconds (60 by default), as OpenProposal § 2.8.3 states.
    Each is a whole number of seconds, 0 or more; anything else raises
    :class:`ConfigurationError`.
    """

    max_cache_age: int = CACHE.fresh_for
    negative_ttl: int = CACHE.retry_after_failure

    def __post_init__(self) -> None:
        whole_number("max_cache_age", self.max_cache_age, minimum=0)
        whole_number("negative_ttl", self.negative_ttl, minimum=0)


#: The profile's cache rules.
DEFAULT_CACHE: Final = CachePolicy()


class MemoryDirectoryStore:
    """An in-process :class:`~.ports.DirectoryStore`, bounded, and safe across threads.

    When either map holds ``max_entries`` origins, a new entry pushes out the
    oldest: for directories, those that expired before the new one was
    fetched go first. ``max_entries`` is a whole number, 1 or more; anything
    else raises :class:`ConfigurationError`.
    """

    __slots__ = ("_directories", "_failures", "_lock", "_max_entries")

    def __init__(self, *, max_entries: int = 10_000) -> None:
        self._max_entries: Final = whole_number("max_entries", max_entries, minimum=1)
        self._directories: dict[Origin, VerifiedDirectory] = {}
        self._failures: dict[Origin, UnixSeconds] = {}
        self._lock: Final = threading.Lock()

    async def get(self, origin: Origin) -> VerifiedDirectory | None:
        with self._lock:
            return self._directories.get(origin)

    async def put(self, directory: VerifiedDirectory) -> None:
        now = directory.evidence.fetched_at
        with self._lock:
            self._directories.pop(directory.origin, None)
            self._directories[directory.origin] = directory
            if len(self._directories) > self._max_entries:
                for origin in [o for o, d in self._directories.items() if d.expires < now]:
                    del self._directories[origin]
            self._bound(self._directories)

    async def record_failure(self, origin: Origin, until: UnixSeconds) -> None:
        with self._lock:
            self._failures.pop(origin, None)
            self._failures[origin] = until
            self._bound(self._failures)

    async def failure_until(self, origin: Origin) -> UnixSeconds | None:
        with self._lock:
            return self._failures.get(origin)

    def clear(self) -> None:
        """Forgets every directory and failure."""
        with self._lock:
            self._directories.clear()
            self._failures.clear()

    def _bound(self, entries: dict[Origin, VerifiedDirectory] | dict[Origin, UnixSeconds]) -> None:
        """Drops the oldest entries while ``entries`` is over the bound."""
        while len(entries) > self._max_entries:
            del entries[next(iter(entries))]


class DirectoryResolver:
    """Resolves keys from each origin's signed key directory, through a fetcher and a store.

    ``fetcher`` fetches directory responses; without one, the resolver builds
    an :class:`~.fetcher.HttpxDirectoryFetcher` with a plain client and closes
    it in :meth:`aclose`. An injected fetcher belongs to the caller. ``store``
    persists verified directories; :class:`MemoryDirectoryStore` by default.
    ``limits`` holds the profile's fetch limits, and ``cache`` how long a
    directory is kept. Each is fixed when the resolver is made.

    A fresh directory answers every keyid without a fetch, so an unknown keyid
    never causes one. A stale but valid directory is fetched again; when that
    fetch fails, the stored keys still answer. Only a refusal is a failed
    fetch; any other error propagates and records nothing.

    A resolver belongs to the event loop it first resolves on, as its fetches
    in flight and its client's connections do: a resolve on another loop
    raises :class:`ConfigurationError`, and so does one after :meth:`aclose`.
    Synchronous code reaches it through one :class:`~.sync.SyncRuntime`.
    """

    __slots__ = (
        "_cache",
        "_closed",
        "_fetcher",
        "_flights",
        "_limits",
        "_loop",
        "_owned",
        "_store",
    )

    def __init__(
        self,
        fetcher: DirectoryFetcher | None = None,
        store: DirectoryStore | None = None,
        *,
        limits: FetchLimits = DEFAULT_LIMITS,
        cache: CachePolicy = DEFAULT_CACHE,
    ) -> None:
        if not isinstance(limits, FetchLimits) or not isinstance(cache, CachePolicy):
            raise ConfigurationError("limits is a FetchLimits and cache a CachePolicy")
        owned: HttpxDirectoryFetcher | None = None
        if fetcher is None:
            from .fetcher import HttpxDirectoryFetcher

            fetcher = owned = HttpxDirectoryFetcher()
        self._owned: Final = owned
        self._fetcher: Final = fetcher
        self._store: Final = MemoryDirectoryStore() if store is None else store
        self._limits: Final = limits
        self._cache: Final = cache
        self._flights: Final[dict[Origin, asyncio.Future[VerifiedDirectory]]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False

    @property
    def fetcher(self) -> DirectoryFetcher:
        return self._fetcher

    @property
    def store(self) -> DirectoryStore:
        return self._store

    @property
    def limits(self) -> FetchLimits:
        return self._limits

    @property
    def cache(self) -> CachePolicy:
        return self._cache

    async def resolve(self, origin: Origin, keyid: KeyId, *, now: UnixSeconds) -> ResolvedKey:
        """Returns the key ``keyid`` of ``origin`` with the verified directory it came from."""
        self._bind()
        directory = await self._directory(origin, now)
        return ResolvedKey(directory.key(keyid), directory)

    def _bind(self) -> None:
        """Binds the resolver to the running loop on first use; refuses any other loop."""
        if self._closed:
            raise ConfigurationError("the resolver is closed")
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise ConfigurationError(
                "this resolver is bound to another event loop; share it through one SyncRuntime"
            )

    async def _stored(self, origin: Origin, now: UnixSeconds) -> VerifiedDirectory | None:
        """The stored directory, when it is ``origin``'s own and still valid at ``now``."""
        directory = await self._store.get(origin)
        if directory is None or directory.origin != origin or now > directory.expires:
            return None
        return directory

    def _fresh(self, directory: VerifiedDirectory | None, now: UnixSeconds) -> bool:
        age = 0 if directory is None else now - directory.evidence.fetched_at
        return directory is not None and age < self._cache.max_cache_age

    async def _directory(self, origin: Origin, now: UnixSeconds) -> VerifiedDirectory:
        stored = await self._stored(origin, now)
        if stored is not None and self._fresh(stored, now):
            return stored
        flight = self._flights.get(origin)
        if flight is None:
            flight = asyncio.ensure_future(self._refresh(origin, now))
            self._flights[origin] = flight
            flight.add_done_callback(partial(self._landed, origin))
        return await asyncio.shield(flight)

    def _landed(self, origin: Origin, flight: asyncio.Future[VerifiedDirectory]) -> None:
        if self._flights.get(origin) is flight:
            del self._flights[origin]
        if not flight.cancelled():
            flight.exception()  # retrieved here too, so a flight nobody awaits stays quiet

    async def _failing(self, origin: Origin, now: UnixSeconds) -> bool:
        until = await self._store.failure_until(origin)
        return until is not None and now < until

    async def _refresh(self, origin: Origin, now: UnixSeconds) -> VerifiedDirectory:
        """One fetch for ``origin``; it rechecks the store, which a landed flight may fill."""
        stored = await self._stored(origin, now)
        if stored is not None and self._fresh(stored, now):
            return stored
        if await self._failing(origin, now):
            if stored is not None:
                return stored
            raise refuse(
                Refusal.DIRECTORY_UNAVAILABLE, f"the directory of {origin} failed recently"
            )
        try:
            response = await self._fetcher.fetch(origin, limits=self._limits, now=now)
            directory = verify_directory(response, origin, now, self._limits)
        except WebBotAuthError as e:
            until = UnixSeconds(now + self._cache.negative_ttl)
            await self._store.record_failure(origin, until)
            logger.warning(
                "directory fetch of %s failed, not retried before %s%s: %s %s",
                origin,
                until,
                "; the stored keys still answer" if stored is not None else "",
                e.reason,
                e,
            )
            if stored is not None:
                return stored  # a failed fetch doesn't evict
            raise
        # A directory that resolves is evidence: it replaces the entry, with or without the key.
        await self._store.put(directory)
        return directory

    async def aclose(self) -> None:
        """Closes the resolver, and the fetcher it built; an injected fetcher stays open."""
        self._closed = True
        if self._owned is not None:
            await self._owned.aclose()

    async def __aenter__(self) -> DirectoryResolver:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


class StaticKeyResolver(KeyResolver):
    """Resolves keys from a fixed map of origin to keys, with no network.

    Each value is a :class:`~.directory.KeySet`, such as a verified
    directory's ``keys``, or keys to build one from. Use it in tests, or for a
    peer whose keys you pin by configuration. Pinned keys don't expire, so
    the time a verifier passes doesn't change the answer.
    """

    __slots__ = ("_keys",)

    def __init__(self, directories: Mapping[Origin | str, KeySet | Iterable[KeyInput]]) -> None:
        self._keys: Final[dict[Origin, KeySet]] = {
            name if isinstance(name, Origin) else Origin.parse(name): (
                keys if isinstance(keys, KeySet) else KeySet.from_keys(keys)
            )
            for name, keys in directories.items()
        }

    async def resolve(self, origin: Origin, keyid: KeyId, *, now: UnixSeconds) -> ResolvedKey:
        """The pinned key ``keyid`` of ``origin``. Pinned keys don't expire; ``now`` goes unread."""
        return ResolvedKey(self._keys.get(origin, _NO_KEYS).lookup(keyid))


_NO_KEYS = KeySet({})


__all__ = [
    "DEFAULT_CACHE",
    "CachePolicy",
    "DirectoryResolver",
    "MemoryDirectoryStore",
    "StaticKeyResolver",
]
