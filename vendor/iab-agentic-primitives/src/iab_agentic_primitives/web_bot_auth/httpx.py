"""An ``httpx.Auth`` that signs outbound requests and verifies signed responses.

.. code-block:: python

    async with DirectoryResolver() as resolver:
        auth = WebBotAuth(RequestSigner.of(key, "https://buyer.example.com"),
                          ResponseVerifier(resolver))
        async with httpx.AsyncClient(auth=auth) as client:
            response = await client.post(url, json=commit)
            verified = verified_response(response)  # a VerifiedResponse, or None
            outcome = verification(response)  # what the auth found out, whatever it was

The auth always returns the response, with what it found out about it: a
:class:`VerifiedResponse`, :class:`Unsigned`, or :class:`VerificationFailed`.
It raises only :class:`ResponseNotVerified`, which carries the response, for a
``2xx`` it couldn't verify when it is told to require signed responses.

A synchronous ``httpx.Client`` verifies on a :class:`~.sync.SyncRuntime` that
the caller owns, passed as ``runtime=``.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Coroutine, Generator
from dataclasses import dataclass
from typing import Final

import httpx

from .errors import ConfigurationError, Refusal, WebBotAuthError
from .message import HeaderLines, HTTPRequest, HTTPResponse
from .roles import RequestSigning, ResponseConfirmer
from .rules import STREAMING_MEDIA_TYPES
from .sync import SyncRuntime
from .values import Origin
from .verifier import SAME_ORIGIN, ExpectedOrigin, VerifiedResponse, is_signed

#: The key of the response's :data:`Verification` in ``response.extensions``.
EXTENSION = "web_bot_auth"

#: Whose signature a response must carry, as :meth:`ResponseVerifier.verify` reads it.
Expect = ExpectedOrigin


@dataclass(frozen=True, slots=True)
class Unsigned:
    """The response carries no ``Signature-Input``, so there was nothing to verify."""


#: The one :class:`Unsigned` value.
UNSIGNED: Final = Unsigned()


@dataclass(frozen=True, slots=True)
class VerificationFailed:
    """The response carries a signature that failed verification.

    ``reason`` says why, in the profile's vocabulary, and ``detail`` is for
    logs. It is what the client found out about the response, not a status
    anybody sent: the response's own status is ``response.status_code``.
    """

    reason: Refusal
    detail: str


#: What :class:`WebBotAuth` found out about a response.
Verification = VerifiedResponse | Unsigned | VerificationFailed


def verification(response: httpx.Response) -> Verification | None:
    """What :class:`WebBotAuth` found out about ``response``.

    ``None`` when no auth with a response verifier saw it.
    """
    found = response.extensions.get(EXTENSION)
    return found if isinstance(found, (VerifiedResponse, Unsigned, VerificationFailed)) else None


def verified_response(response: httpx.Response) -> VerifiedResponse | None:
    """The :class:`VerifiedResponse` that :class:`WebBotAuth` stored on ``response``.

    ``None`` when the auth didn't verify the response: it was unsigned, its
    signature failed (:func:`verification` says why), or no auth saw it.
    """
    found = verification(response)
    return found if isinstance(found, VerifiedResponse) else None


class ResponseNotVerified(Exception):
    """A ``2xx`` response the auth couldn't verify, when it requires signed responses.

    ``response`` is the response as received, its body read, and
    ``verification`` says why it isn't verified. The peer did answer: a
    caller can still read what it said, as an unverified answer.
    """

    def __init__(self, response: httpx.Response, verification: Unsigned | VerificationFailed):
        super().__init__(response, verification)
        self.response = response
        self.verification = verification

    def __str__(self) -> str:
        found = self.verification
        why = "it is unsigned" if isinstance(found, Unsigned) else f"{found.reason.code}: {found}"
        return f"the {self.response.status_code} response is not verified: {why}"


def _media_type(response: httpx.Response) -> str | None:
    return HeaderLines(response.headers.multi_items()).media_type()


class WebBotAuth(httpx.Auth):
    """Signs each request with ``signer`` and, optionally, verifies the response.

    With ``response_verifier``, the auth decides from the response's header
    lines alone whether it is signed. An unsigned response is returned
    unread, so a stream arrives as it is sent. A signed one is read and
    verified, signature and binding to the request. Either way the auth
    returns the response, and :func:`verification` reads what it found out:
    a :class:`VerifiedResponse` (which :func:`verified_response` returns),
    :class:`Unsigned`, or :class:`VerificationFailed`.

    With ``require_signed_response`` (the default), a ``2xx`` response that
    isn't verified raises :class:`ResponseNotVerified`, which carries the
    response. An unsigned response of a media type a server streams unsigned
    (:data:`~.rules.STREAMING_MEDIA_TYPES`, ``text/event-stream``) is let
    through, and so is every response that isn't a ``2xx``, such as a
    refusal a verifier sends unsigned (``400``, ``403``, ``429``, ``503``) or
    a proxy's ``502``: its status, headers, and body are the peer's own.

    ``expect`` names whose signature the response carries, as
    :meth:`ResponseVerifier.verify` reads it: ``"same-origin"`` (the
    default), the identity of the host the request went to; an
    :class:`Origin`; or ``None`` for any identity.

    The auth signs each request for its own URL, so it doesn't follow
    redirects, and the client mustn't either (httpx's default,
    ``follow_redirects=False``). A redirect response is returned with
    ``response.next_request`` stripped of the auth's signature fields:
    sending it through the auth signs it afresh for its new URL. A client
    that follows a redirect has already resent the signature to another URL,
    and the auth raises :class:`ConfigurationError` when it sees the result.

    ``runtime`` is the :class:`~.sync.SyncRuntime` of the verifier's
    resolver, owned by the caller. With it, the auth verifies on the
    runtime's loop, so one auth serves an ``httpx.Client`` and an
    ``httpx.AsyncClient`` alike. Without it, only an async client can verify:
    a sync client's request raises :class:`ConfigurationError` before it is
    sent. The auth starts no thread and owns nothing to close.

    With no ``signer``, the auth leaves requests unsigned, for a call that
    authenticates another way, such as a bearer token, and still verifies the
    signed response; :meth:`verify_only` builds one. A response to an unsigned
    request needs no binding.

    When it verifies responses, the auth sends ``Accept-Encoding: identity``:
    ``Content-Digest`` covers the content as sent, and httpx decodes a
    compressed body before the auth sees it. Its settings are fixed when it
    is made.
    """

    requires_request_body = True
    requires_response_body = False

    def __init__(
        self,
        signer: RequestSigning | None,
        response_verifier: ResponseConfirmer | None = None,
        *,
        runtime: SyncRuntime | None = None,
        expect: Expect = SAME_ORIGIN,
        require_signed_response: bool = True,
    ) -> None:
        if signer is None and response_verifier is None:
            raise ConfigurationError("an auth that signs nothing must verify responses")
        if expect not in (SAME_ORIGIN, None) and not isinstance(expect, Origin):
            raise ConfigurationError(f"expect is an Origin, 'same-origin', or None, not {expect!r}")
        self._signer: Final = signer
        self._verifier: Final = response_verifier
        self._runtime: Final = runtime
        self._expect: Final = expect
        self._require_signed: Final = require_signed_response

    @classmethod
    def verify_only(
        cls,
        response_verifier: ResponseConfirmer,
        *,
        runtime: SyncRuntime | None = None,
        expect: Expect = SAME_ORIGIN,
        require_signed_response: bool = True,
    ) -> WebBotAuth:
        """An auth that sends requests unsigned and verifies each signed response."""
        return cls(
            None,
            response_verifier,
            runtime=runtime,
            expect=expect,
            require_signed_response=require_signed_response,
        )

    @property
    def signer(self) -> RequestSigning | None:
        return self._signer

    @property
    def response_verifier(self) -> ResponseConfirmer | None:
        return self._verifier

    @property
    def runtime(self) -> SyncRuntime | None:
        return self._runtime

    def _sign(self, request: httpx.Request) -> tuple[HTTPRequest, tuple[str, ...]]:
        """The request as sent, and the names of the field lines signing added to it."""
        if self._verifier is not None:
            request.headers["Accept-Encoding"] = "identity"
        sent = HTTPRequest(
            request.method, str(request.url), request.headers.multi_items(), request.content
        )
        if self._signer is None:
            return sent, ()
        signed = self._signer.sign(sent)
        # Signing only appends field lines, so the new ones follow the request's own.
        added = signed.headers.items()[len(sent.headers) :]
        for name, value in added:
            request.headers[name] = value
        return signed, tuple(name for name, _ in added)

    def _redirect_boundary(self, response: httpx.Response, added: tuple[str, ...]) -> None:
        """Keeps the request's signature on the URL it was made for."""
        if response.history:
            raise ConfigurationError(
                f"the client followed a redirect to {response.request.url}, resending the "
                "request as signed for another URL; WebBotAuth needs follow_redirects=False"
            )
        follow = response.next_request
        if follow is not None:
            for name in added:
                follow.headers.pop(name, None)

    def _verify(
        self, verifier: ResponseConfirmer, response: httpx.Response, sent: HTTPRequest
    ) -> Coroutine[object, object, VerifiedResponse]:
        message = HTTPResponse(
            response.status_code, response.headers.multi_items(), response.content, sent
        )
        return verifier.verify(message, expected_origin=self._expect)

    def _settle(self, response: httpx.Response, found: Verification) -> ResponseNotVerified | None:
        """Stores ``found`` on ``response``; the error to raise when the auth refuses it."""
        response.extensions[EXTENSION] = found
        if isinstance(found, VerifiedResponse) or not self._require_signed:
            return None
        if not response.is_success:
            return None
        if isinstance(found, Unsigned) and _media_type(response) in STREAMING_MEDIA_TYPES:
            return None
        return ResponseNotVerified(response, found)

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        runtime = self._runtime
        if self._verifier is not None and runtime is None:
            raise ConfigurationError(
                "a sync client verifies on a SyncRuntime: pass WebBotAuth(..., runtime=...)"
            )
        request.read()
        sent, added = self._sign(request)
        response = yield request
        self._redirect_boundary(response, added)
        verifier = self._verifier
        if verifier is None or runtime is None:
            return
        found: Verification = UNSIGNED
        if is_signed(HeaderLines(response.headers.multi_items())):
            response.read()
            try:
                found = runtime.run(self._verify(verifier, response, sent))
            except WebBotAuthError as e:
                found = VerificationFailed(e.refusal, e.detail)
        refused = self._settle(response, found)
        if refused is not None:
            response.read()
            raise refused

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        await request.aread()
        sent, added = self._sign(request)
        response = yield request
        self._redirect_boundary(response, added)
        verifier = self._verifier
        if verifier is None:
            return
        found: Verification = UNSIGNED
        if is_signed(HeaderLines(response.headers.multi_items())):
            await response.aread()
            try:
                verify = self._verify(verifier, response, sent)
                runtime = self._runtime
                found = await (verify if runtime is None else runtime.run_async(verify))
            except WebBotAuthError as e:
                found = VerificationFailed(e.refusal, e.detail)
        refused = self._settle(response, found)
        if refused is not None:
            await response.aread()
            raise refused


__all__ = [
    "EXTENSION",
    "UNSIGNED",
    "Expect",
    "ResponseNotVerified",
    "Unsigned",
    "Verification",
    "VerificationFailed",
    "WebBotAuth",
    "verification",
    "verified_response",
]
