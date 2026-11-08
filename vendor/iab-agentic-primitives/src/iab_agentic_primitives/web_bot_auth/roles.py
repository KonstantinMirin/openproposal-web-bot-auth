"""The role ports: what the edges and façades take. No I/O.

- :class:`RequestConfirmer` confirms a request's signature for a server:
  :class:`~.verifier.RequestVerifier` is one, and so is an application's own
  confirmer, such as one that allows only listed origins.
- :class:`ResponseConfirmer` confirms a response's signature and its binding:
  :class:`~.verifier.ResponseVerifier` is one.
- :class:`RequestSigning` and :class:`ResponseSigning` sign as one origin:
  :class:`~.signer.RequestSigner` and :class:`~.signer.ResponseSigner` are
  the profile's.

An edge reads what it needs from the port it is given, such as the server's
identity from a :class:`RequestConfirmer`, and holds no second copy.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .message import HTTPRequest, HTTPResponse
from .values import KeyId, Origin, ServerIdentity, UnixSeconds
from .verifier import SAME_ORIGIN, ExpectedOrigin, VerifiedRequest, VerifiedResponse


@runtime_checkable
class RequestConfirmer(Protocol):
    """Confirms a request's signature as the server ``identity``, or raises a refusal."""

    @property
    def identity(self) -> ServerIdentity: ...

    async def verify(
        self, request: HTTPRequest, *, now: UnixSeconds | None = None
    ) -> VerifiedRequest: ...


@runtime_checkable
class ResponseConfirmer(Protocol):
    """Confirms a response's signature and its binding, or raises a refusal.

    ``expected_origin`` names whose signature the response must carry, as
    :meth:`~.verifier.ResponseVerifier.verify` reads it.
    """

    async def verify(
        self,
        response: HTTPResponse,
        *,
        expected_origin: ExpectedOrigin = SAME_ORIGIN,
        now: UnixSeconds | None = None,
    ) -> VerifiedResponse: ...


@runtime_checkable
class RequestSigning(Protocol):
    """Signs requests as ``origin``."""

    @property
    def origin(self) -> Origin: ...

    def sign(
        self, request: HTTPRequest, *, now: UnixSeconds | None = None, nonce: str | None = None
    ) -> HTTPRequest: ...


@runtime_checkable
class ResponseSigning(Protocol):
    """Signs responses as ``origin`` with the key ``keyid``, bound to the requests they answer.

    A server checks ``keyid`` against the directory it publishes, so it never
    signs with a key its peers can't find.
    """

    @property
    def origin(self) -> Origin: ...

    @property
    def keyid(self) -> KeyId: ...

    def sign(self, response: HTTPResponse, *, now: UnixSeconds | None = None) -> HTTPResponse: ...


__all__ = [
    "RequestConfirmer",
    "RequestSigning",
    "ResponseConfirmer",
    "ResponseSigning",
]
