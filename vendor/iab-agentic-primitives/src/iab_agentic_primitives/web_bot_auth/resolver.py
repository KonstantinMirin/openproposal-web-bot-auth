"""Key resolution: from ``(origin, keyid)`` to an Ed25519 public key.

:class:`DirectoryResolver` composes a :class:`~.ports.DirectoryFetcher` and a
:class:`~.ports.DirectoryStore`, and owns every rule about what a stored
directory is good for (OpenProposal § 2.8.3):

- It fetches exactly ``https://<host>/.well-known/http-message-signatures-directory``
  and verifies the response with :func:`~.directory.verify_directory` under
  one :class:`~.directory.FetchLimits`, at the time it was fetched.
- A directory is verified once, when it enters the process: from the fetcher,
  or as bytes the store returns that the resolver hasn't verified. The
  resolver holds each :class:`~.directory.VerifiedDirectory` in memory by
  origin, and answers from it while the store returns the response it was
  verified from. Stored bytes it doesn't hold are verified, as fetched, for
  the origin it asked for and under its own limits; a stored response that
  doesn't verify is a cache miss.
- The resolver's own clock stamps each fetch and judges the cache: a
  directory younger than :attr:`CachePolicy.max_cache_age` answers every
  keyid without a fetch. A directory that resolves without the key replaces
  the stored one. A failed fetch does not evict it, and isn't retried for
  :attr:`CachePolicy.negative_ttl` seconds.
- The time a verifier judges at decides only whether the directory still
  holds then: it answers until the earliest ``expires`` among its signatures.
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
    DirectoryResponse,
    FetchLimits,
    KeyInput,
    KeySet,
    VerifiedDirectory,
    verify_directory,
)
from .errors import ConfigurationError, Refusal, WebBotAuthError, refuse
from .ports import DirectoryFetcher, DirectoryStore, KeyResolver, ResolvedKey
from .rules import CACHE
from .values import Clock, KeyId, Origin, UnixSeconds, system_clock, whole_number

if TYPE_CHECKING:
    from .fetcher import HttpxDirectoryFetcher

logger = logging.getLogger(__name__)

#: The most verified directories a resolver holds in memory; past it, the oldest goes.
_MAX_HELD: Final = 10_000


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
    one written longest ago. ``max_entries`` is a whole number, 1 or more;
    anything else raises :class:`ConfigurationError`.
    """

    __slots__ = ("_directories", "_failures", "_lock", "_max_entries")

    def __init__(self, *, max_entries: int = 10_000) -> None:
        self._max_entries: Final = whole_number("max_entries", max_entries, minimum=1)
        self._directories: dict[Origin, DirectoryResponse] = {}
        self._failures: dict[Origin, UnixSeconds] = {}
        self._lock: Final = threading.Lock()

    async def get(self, origin: Origin) -> DirectoryResponse | None:
        with self._lock:
            return self._directories.get(origin)

    async def put(self, origin: Origin, response: DirectoryResponse) -> None:
        with self._lock:
            self._directories.pop(origin, None)
            self._directories[origin] = response
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

    def _bound(self, entries: dict[Origin, DirectoryResponse] | dict[Origin, UnixSeconds]) -> None:
        """Drops the oldest entries while ``entries`` is over the bound."""
        while len(entries) > self._max_entries:
            del entries[next(iter(entries))]


class DirectoryResolver:
    """Resolves keys from each origin's signed key directory, through a fetcher and a store.

    ``fetcher`` fetches directory responses; without one, the resolver builds
    an :class:`~.fetcher.HttpxDirectoryFetcher` with a plain client and closes
    it in :meth:`aclose`. An injected fetcher belongs to the caller. ``store``
    keeps each origin's directory response; :class:`MemoryDirectoryStore` by
    default. ``limits`` holds the profile's fetch limits, ``cache`` how long a
    directory is kept, and ``clock`` the time the resolver stamps fetches with
    and judges its cache and failures by. Each is fixed when the resolver is
    made.

    A directory is verified once, when it enters the process. The resolver
    holds each verified directory in memory by origin, for a bounded number
    of origins, and answers from it while the store returns the
    response it was verified from, so a cache hit or an unknown keyid costs
    no verification. A stored response it doesn't hold, such as one another
    worker wrote, is verified at the time it was fetched and under
    ``limits``; a response that doesn't verify is a cache miss. A fresh
    directory answers every keyid without a fetch, so an unknown keyid never
    causes one. A stale but valid directory is fetched again; when that fetch
    fails, the stored keys still answer. Only a refusal is a failed fetch; any
    other error propagates and records nothing. The ``now`` a resolve is
    judged at decides only whether the directory has expired by then
    (``directory-window``); it never stamps or ages the cache.

    A resolver belongs to the event loop it first resolves on, as its fetches
    in flight and its client's connections do: a resolve on another loop
    raises :class:`ConfigurationError`, and so does one after :meth:`aclose`.
    Synchronous code reaches it through one :class:`~.sync.SyncRuntime`.
    """

    __slots__ = (
        "_cache",
        "_clock",
        "_closed",
        "_fetcher",
        "_flights",
        "_held",
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
        clock: Clock = system_clock,
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
        self._clock: Final = clock
        self._flights: Final[dict[Origin, asyncio.Future[VerifiedDirectory]]] = {}
        self._held: Final[dict[Origin, VerifiedDirectory]] = {}
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

    @property
    def clock(self) -> Clock:
        return self._clock

    async def resolve(self, origin: Origin, keyid: KeyId, *, now: UnixSeconds) -> ResolvedKey:
        """Returns the key ``keyid`` of ``origin`` with the verified directory it came from.

        ``now`` is the time the caller judges at: a directory that has
        expired by then is refused ``directory-window``.
        """
        self._bind()
        directory = await self._directory(origin)
        if now > directory.expires:
            raise refuse(
                Refusal.DIRECTORY_WINDOW,
                f"the directory of {origin} expired at {directory.expires}, before {now}",
            )
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

    def _hold(self, directory: VerifiedDirectory) -> VerifiedDirectory:
        """Holds ``directory`` as its origin's, the newest; the oldest goes past the bound."""
        self._held.pop(directory.origin, None)
        self._held[directory.origin] = directory
        while len(self._held) > _MAX_HELD:
            del self._held[next(iter(self._held))]
        return directory

    def _known(self, response: DirectoryResponse, origin: Origin) -> VerifiedDirectory:
        """``response`` verified for ``origin``: the held directory when it was verified from it.

        Bytes the resolver doesn't hold came from outside the process, so they
        are verified, as fetched and under the resolver's limits, and held.
        """
        held = self._held.get(origin)
        if held is not None and held.evidence == response:
            return held
        verified = verify_directory(response, origin, response.fetched_at, self._limits)
        return self._hold(verified)

    async def _stored(self, origin: Origin, at: UnixSeconds) -> VerifiedDirectory | None:
        """The stored directory of ``origin``, verified once and unexpired at ``at``.

        A stored response that doesn't verify, such as another origin's, is a miss.
        """
        response = await self._store.get(origin)
        if response is None:
            self._held.pop(origin, None)
            return None
        try:
            directory = self._known(response, origin)
        except WebBotAuthError as e:
            logger.warning(
                "the stored directory of %s doesn't verify, so it is fetched again: %s %s",
                origin,
                e.reason,
                e,
            )
            return None
        return None if at > directory.expires else directory

    def _fresh(self, directory: VerifiedDirectory, at: UnixSeconds) -> bool:
        """Younger than the cache age at ``at``; a fetch stamped after ``at`` isn't."""
        age = at - directory.evidence.fetched_at
        return 0 <= age < self._cache.max_cache_age

    async def _directory(self, origin: Origin) -> VerifiedDirectory:
        now = self._clock()
        stored = await self._stored(origin, now)
        if stored is not None and self._fresh(stored, now):
            return stored
        flight = self._flights.get(origin)
        if flight is None:
            flight = asyncio.ensure_future(self._refresh(origin))
            self._flights[origin] = flight
            flight.add_done_callback(partial(self._landed, origin))
        return await asyncio.shield(flight)

    def _landed(self, origin: Origin, flight: asyncio.Future[VerifiedDirectory]) -> None:
        if self._flights.get(origin) is flight:
            del self._flights[origin]
        if not flight.cancelled():
            flight.exception()  # retrieved here too, so a flight nobody awaits stays quiet

    async def _failing(self, origin: Origin, at: UnixSeconds) -> bool:
        until = await self._store.failure_until(origin)
        return until is not None and at < until

    async def _refresh(self, origin: Origin) -> VerifiedDirectory:
        """One fetch for ``origin``; it rechecks the store, which a landed flight may fill."""
        now = self._clock()
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
            directory = verify_directory(response, origin, response.fetched_at, self._limits)
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
        await self._store.put(origin, response)
        return self._hold(directory)

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
