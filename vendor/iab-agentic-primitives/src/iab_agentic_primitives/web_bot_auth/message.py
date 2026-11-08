"""The message model: immutable field lines, requests, and responses.

A message has one form. :class:`HeaderLines` is an immutable, ordered sequence
of ``(name, value)`` field lines, read once from whatever the caller passes, so
a one-shot iterator is never read twice. :class:`HTTPRequest` and
:class:`HTTPResponse` are frozen. The signers return a new message, and the
verifiers take one. :class:`Answer` is what a server sends back.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import NamedTuple

#: Header input: a mapping, or ``(name, value)`` field lines, read once.
Headers = Mapping[str, str] | Iterable[tuple[str, str]]


def _lines_of(headers: Headers | None) -> tuple[tuple[str, str], ...]:
    if headers is None:
        return ()
    if isinstance(headers, HeaderLines):
        return headers.items()
    items = headers.items() if isinstance(headers, Mapping) else headers
    lines: list[tuple[str, str]] = []
    for line in items:
        name, value = line
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError(f"a field line is a pair of str, not {line!r}")
        lines.append((name, value))
    return tuple(lines)


class HeaderLines:
    """Field lines in wire order, immutable, with case-insensitive lookup.

    Build one from a mapping, a sequence of ``(name, value)`` pairs, or another
    :class:`HeaderLines`. A name or value that isn't a ``str`` raises
    ``TypeError``. Iterating yields the pairs, and ``lines[name]`` reads one
    field's combined value. Nothing changes a :class:`HeaderLines`; the
    ``with_*`` methods return a new one.
    """

    __slots__ = ("_lines",)

    def __init__(self, headers: Headers | None = None) -> None:
        self._lines = _lines_of(headers)

    def items(self) -> tuple[tuple[str, str], ...]:
        """The field lines, in order."""
        return self._lines

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._lines)

    def __len__(self) -> int:
        return len(self._lines)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and any(n.lower() == name.lower() for n, _ in self._lines)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, HeaderLines) and self._lines == other._lines

    def __hash__(self) -> int:
        return hash(self._lines)

    def __repr__(self) -> str:
        return f"HeaderLines({list(self._lines)!r})"

    def get_all(self, name: str) -> tuple[str, ...]:
        """The values of every line named ``name``, in order."""
        return tuple(v for n, v in self._lines if n.lower() == name.lower())

    def get(self, name: str) -> str | None:
        """The combined value of every line named ``name``, or ``None``."""
        values = [v.strip(" \t") for v in self.get_all(name)]
        return ", ".join(values) if values else None

    def __getitem__(self, name: str) -> str:
        """The combined value of every line named ``name``; ``KeyError`` when there is none."""
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def with_added(self, name: str, value: str) -> HeaderLines:
        """A copy with one more line, ``name: value``, at the end."""
        return HeaderLines((*self._lines, (name, value)))

    def with_replaced(self, name: str, value: str) -> HeaderLines:
        """A copy without any line named ``name``, and ``name: value`` at the end."""
        kept = tuple((n, v) for n, v in self._lines if n.lower() != name.lower())
        return HeaderLines((*kept, (name, value)))

    def carries_signature_field(self) -> bool:
        """True when the message carries ``Signature`` or ``Signature-Input``, of any scheme.

        This is not whether the message is signed under the profile, which
        :func:`~.verifier.is_signed` decides. It is whether a signer must
        leave the message alone, and whether a response is already signed.
        """
        return "signature" in self or "signature-input" in self

    def media_type(self) -> str | None:
        """The ``Content-Type`` media type, lowercased and without parameters."""
        value = self.get("content-type")
        return None if value is None else value.split(";")[0].strip().lower()


def target_uri(url: str) -> str:
    """``url`` as the profile signs and rebuilds it: without an empty query.

    A server can't tell ``https://seller.example.com/p?`` from
    ``https://seller.example.com/p`` (ASGI gives both the query string
    ``b""``), so the signer and the server's edge both drop the ``?``. Any
    other URL is returned as given.
    """
    head, mark, query = url.partition("?")
    return head if mark and not query else url


def _header_lines(headers: Headers | None) -> HeaderLines:
    return headers if isinstance(headers, HeaderLines) else HeaderLines(headers)


@dataclass(frozen=True, slots=True, init=False)
class HTTPRequest:
    """A request as the profile sees it: method, absolute URL, field lines, and body bytes.

    ``headers`` may be given as a mapping, a sequence of pairs, or
    :class:`HeaderLines`; it is read once into :class:`HeaderLines`.
    """

    method: str
    url: str
    headers: HeaderLines
    body: bytes

    def __init__(
        self, method: str, url: str, headers: Headers | None = None, body: bytes = b""
    ) -> None:
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "headers", _header_lines(headers))
        object.__setattr__(self, "body", body)


@dataclass(frozen=True, slots=True, init=False)
class HTTPResponse:
    """A response, with the request it answers and binds to."""

    status: int
    headers: HeaderLines
    body: bytes
    request: HTTPRequest

    def __init__(
        self, status: int, headers: Headers | None, body: bytes, request: HTTPRequest
    ) -> None:
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "headers", _header_lines(headers))
        object.__setattr__(self, "body", body)
        object.__setattr__(self, "request", request)


class Answer(NamedTuple):
    """An answer a server sends: status, field lines, and body bytes.

    Every answer the module builds is one: a refusal, a directory response,
    and a served test response alike.
    """

    status: int
    headers: HeaderLines
    body: bytes


__all__ = [
    "Answer",
    "HTTPRequest",
    "HTTPResponse",
    "HeaderLines",
    "Headers",
    "target_uri",
]
