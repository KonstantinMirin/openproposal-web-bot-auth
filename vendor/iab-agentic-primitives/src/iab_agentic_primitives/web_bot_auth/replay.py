"""Replay protection: one use per ``(origin, nonce)`` pair.

A verifier refuses a nonce it has already seen for the same identity within the
signature's lifetime, with ``429``. The store is pluggable: a deployment with
several worker processes backs :class:`NonceStore` with shared storage, such as
Redis ``SET key 1 NX EX ttl``.
"""

from __future__ import annotations

import heapq
import threading
from typing import Protocol, runtime_checkable

from .values import Clock, Origin, Seconds, UnixSeconds, system_clock, whole_number


class NonceStoreUnavailable(Exception):
    """Raised by a :class:`NonceStore` that can't record a nonce now, such as a full store.

    The verifier answers ``503``, not ``429``: the nonce isn't a replay, and a
    client that re-signs would only be refused again.
    """


@runtime_checkable
class NonceStore(Protocol):
    """Records each ``(origin, nonce)`` pair once.

    ``check_and_record`` is atomic: it records the pair and returns ``True``
    when the pair is new, and returns ``False`` without changing anything when
    the pair is already recorded. When it can't record the pair, such as when
    its backend is down, it raises :class:`NonceStoreUnavailable` and nothing
    else; the verifier answers that with ``503``, and any other error is a bug
    that propagates. ``ttl`` is how long, in seconds, the store must keep the
    pair: the signature's remaining lifetime plus the clock skew.
    """

    async def check_and_record(self, origin: Origin, nonce: str, ttl: Seconds) -> bool: ...


class MemoryNonceStore:
    """An in-process :class:`NonceStore` whose entries expire after their TTL.

    It is safe across threads and event loops within one process. Use shared
    storage when several processes verify requests for the same identity. When
    it holds ``max_entries`` live pairs, it raises :class:`NonceStoreUnavailable`
    instead of forgetting one. ``max_entries`` is a whole number, 1 or more;
    anything else raises :class:`ConfigurationError`.
    """

    def __init__(self, *, clock: Clock = system_clock, max_entries: int = 1_000_000) -> None:
        self._clock = clock
        self._max_entries = whole_number("max_entries", max_entries, minimum=1)
        self._seen: dict[tuple[Origin, str], UnixSeconds] = {}
        self._expiry: list[tuple[UnixSeconds, tuple[Origin, str]]] = []
        self._lock = threading.Lock()

    def _evict(self, now: UnixSeconds) -> None:
        while self._expiry and self._expiry[0][0] < now:
            deadline, entry = heapq.heappop(self._expiry)
            if self._seen.get(entry) == deadline:
                del self._seen[entry]

    def _check_and_record(self, origin: Origin, nonce: str, ttl: Seconds) -> bool:
        now = self._clock()
        entry = (origin, nonce)
        with self._lock:
            self._evict(now)
            if entry in self._seen:
                return False
            if len(self._seen) >= self._max_entries:
                # Refuse rather than forget: a full store must not admit a replay.
                raise NonceStoreUnavailable(f"the nonce store holds {self._max_entries} entries")
            # At least one second, so a clock with whole-second resolution keeps the pair
            # through the tick it was recorded in.
            deadline = UnixSeconds(now + max(ttl, 1))
            self._seen[entry] = deadline
            heapq.heappush(self._expiry, (deadline, entry))
            return True

    async def check_and_record(self, origin: Origin, nonce: str, ttl: Seconds) -> bool:
        return self._check_and_record(origin, nonce, ttl)

    def __len__(self) -> int:
        with self._lock:
            self._evict(self._clock())
            return len(self._seen)


__all__ = [
    "MemoryNonceStore",
    "NonceStore",
    "NonceStoreUnavailable",
]
