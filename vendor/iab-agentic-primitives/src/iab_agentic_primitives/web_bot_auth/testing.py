"""Test support: directories served from data, and the contracts of the store ports.

:func:`directory_transport` answers the well-known directory path of each
origin it is given, and ``404`` to anything else, and :func:`served_resolver`
is a resolver over it. It streams each body, so a
fetch through it runs the same bounded read as a fetch over the network.

:func:`check_directory_store` and :func:`check_nonce_store` check a
:class:`~.ports.DirectoryStore` or a :class:`~.replay.NonceStore` against its
contract, so a deployment can run them on its own backend, such as Redis. Each
raises ``AssertionError`` naming the rule a store breaks.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

import httpx

from .directory import DirectoryResponse, VerifiedDirectory, publish_directory, verify_directory
from .fetcher import HttpxDirectoryFetcher
from .keys import Ed25519Key
from .message import Answer, HeaderLines
from .ports import DirectoryStore
from .replay import NonceStore
from .resolver import DirectoryResolver
from .values import Clock, Origin, Seconds, UnixSeconds

_NOT_FOUND = Answer(404, HeaderLines(), b"")


def directory_transport(responses: Mapping[Origin, Answer]) -> httpx.MockTransport:
    """Returns an httpx transport that serves directory responses from data.

    ``responses`` maps an origin to the :class:`~.message.Answer` its
    directory URL serves. Any other URL gets ``404``. Use it with
    ``HttpxDirectoryFetcher(transport=directory_transport(...))``.
    """
    served = {origin.directory_url: answer for origin, answer in responses.items()}

    def handler(request: httpx.Request) -> httpx.Response:
        url = f"{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}"
        answer = served.get(url, _NOT_FOUND)
        return httpx.Response(
            answer.status, headers=answer.headers.items(), stream=httpx.ByteStream(answer.body)
        )

    return httpx.MockTransport(handler)


def served_resolver(directories: Mapping[Origin, Answer]) -> DirectoryResolver:
    """A resolver that fetches each origin's directory from ``directories``, with no network.

    The fetch runs the same bounded read as one over the network.
    """
    return DirectoryResolver(HttpxDirectoryFetcher(transport=directory_transport(directories)))


# ── the store contracts ───────────────────────────────────────────────────

#: The instant the contracts' directories are fetched at: 2026-11-07T12:00:00Z.
_AT = UnixSeconds(1794052800)


def _directory(host: str, key: Ed25519Key) -> VerifiedDirectory:
    """A real verified directory of ``https://<host>``, fetched at :data:`_AT`."""
    origin = Origin(host)
    published = publish_directory(origin, [key], now=_AT)
    fetched = DirectoryResponse(
        origin.directory_url, published.status, published.headers, published.body, _AT
    )
    return verify_directory(fetched, origin, _AT)


def _require(holds: bool, rule: str) -> None:
    """Raises ``AssertionError`` naming ``rule`` when it doesn't hold, under ``-O`` too."""
    if not holds:
        raise AssertionError(f"the store breaks its contract: {rule}")


def _same(got: VerifiedDirectory | None, want: VerifiedDirectory, rule: str) -> None:
    """``got`` is ``want``: the same origin, keys, expiry, and evidence."""
    _require(got is not None, f"{rule} (get returned nothing)")
    if got is not None:
        found = (got.origin, list(got.keys), got.expires, got.evidence)
        _require(found == (want.origin, list(want.keys), want.expires, want.evidence), rule)


async def check_directory_store(make: Callable[[], DirectoryStore]) -> None:
    """Checks the stores ``make`` returns, each empty, against the DirectoryStore contract.

    A store keeps each directory under its own origin, in either order of
    puts, replaces only that origin's, and keeps each origin's failure
    deadline apart from the others'.
    """
    key = Ed25519Key.generate()
    a, b = _directory("a.store-check.example", key), _directory("b.store-check.example", key)
    for first, second in ((a, b), (b, a)):
        store = make()
        _require(await store.get(first.origin) is None, "an empty store holds nothing")
        await store.put(first)
        await store.put(second)
        _same(await store.get(first.origin), first, "a put keeps other origins' directories")
        _same(await store.get(second.origin), second, "a put keeps its origin's directory")
    store = make()
    await store.put(a)
    await store.put(b)
    again = _directory("a.store-check.example", Ed25519Key.generate())
    await store.put(again)
    _same(await store.get(a.origin), again, "a put replaces its origin's directory")
    _same(await store.get(b.origin), b, "a put replaces no other origin's directory")
    until = UnixSeconds(_AT + 60)
    await store.record_failure(a.origin, until)
    _require(await store.failure_until(a.origin) == until, "a failure deadline is kept")
    _require(await store.failure_until(b.origin) is None, "a failure is its origin's alone")
    await store.record_failure(a.origin, UnixSeconds(until + 60))
    _require(await store.failure_until(a.origin) == until + 60, "a later failure replaces one")


async def check_nonce_store(make: Callable[[Clock], NonceStore]) -> None:
    """Checks the stores ``make`` returns for a clock against the NonceStore contract.

    A store records each ``(origin, nonce)`` pair once, apart for each origin,
    and keeps it for its ``ttl``.
    """
    now = [_AT]
    store = make(lambda: now[0])
    a, b = Origin("a.store-check.example"), Origin("b.store-check.example")

    async def record(origin: Origin, nonce: str) -> bool:
        return await store.check_and_record(origin, nonce, Seconds(60))

    _require(await record(a, "n1"), "a new pair is recorded")
    _require(not await record(a, "n1"), "a recorded pair is refused")
    _require(await record(b, "n1"), "a nonce is recorded per origin")
    _require(await record(a, "n2"), "another nonce is a new pair")
    now[0] = UnixSeconds(_AT + 60)
    _require(not await record(a, "n1"), "a pair is kept for its ttl")


__all__ = [
    "check_directory_store",
    "check_nonce_store",
    "directory_transport",
    "served_resolver",
]
