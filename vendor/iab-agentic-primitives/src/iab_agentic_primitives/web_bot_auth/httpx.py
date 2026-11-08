"""httpx clients that sign every request on the wire and verify every signed response.

.. code-block:: python

    async with DirectoryResolver() as resolver:
        auth = WebBotAuth(RequestSigner.of(key, "https://buyer.example.com"),
                          ResponseVerifier(resolver))
        async with auth.async_client() as client:
            response = await client.post(url, json=commit)
            verified = verified_response(response)  # a VerifiedResponse, or None
            outcome = verification(response)  # what the client found out, whatever it was
            sent = sent_request(response)  # the request as signed and sent

:class:`WebBotAuth` is the configuration, and the library builds the client
from it, so the signing transport is always the client's one transport. The
transport signs each wire hop for its own URL and verifies the response to it
against the exact request sent on that hop. A redirect, followed or not, is
signed afresh for its own URL, so a signature never reaches another URI
(OpenProposal § 2.8.2).

The client always returns the response, with what it found out about it: a
:class:`VerifiedResponse`, :class:`Unsigned`, or :class:`VerificationFailed`.
It raises only :class:`ResponseNotVerified`, which carries the response, for a
``2xx`` it couldn't verify when it is told to require signed responses.

A synchronous ``httpx.Client`` verifies on a :class:`~.sync.SyncRuntime` that
the caller owns, passed as ``runtime=``.
"""

from __future__ import annotations

from collections.abc import Coroutine, Mapping
from dataclasses import dataclass, replace
from typing import Final, TypedDict, Unpack

import httpx

from .errors import ConfigurationError, Refusal, WebBotAuthError
from .message import HeaderLines, HTTPRequest, HTTPResponse, target_uri
from .roles import RequestSigning, ResponseConfirmer
from .rules import STREAMING_MEDIA_TYPES
from .sync import SyncRuntime
from .values import Origin
from .verifier import SAME_ORIGIN, ExpectedOrigin, VerifiedResponse, is_signed

#: The key of the response's :data:`Verification` in ``response.extensions``.
EXTENSION = "web_bot_auth"
#: The key of the request as sent, an :class:`~.message.HTTPRequest`, in ``response.extensions``.
_SENT = "web_bot_auth.sent"

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
    """What a :class:`WebBotAuth` client found out about ``response``.

    ``None`` when no client with a response verifier received it.
    """
    found = response.extensions.get(EXTENSION)
    return found if isinstance(found, (VerifiedResponse, Unsigned, VerificationFailed)) else None


def verified_response(response: httpx.Response) -> VerifiedResponse | None:
    """The :class:`VerifiedResponse` that a :class:`WebBotAuth` client stored on ``response``.

    ``None`` when the client didn't verify the response: it was unsigned, its
    signature failed (:func:`verification` says why), or no client saw it.
    """
    found = verification(response)
    return found if isinstance(found, VerifiedResponse) else None


def sent_request(response: httpx.Response) -> HTTPRequest | None:
    """The request a :class:`WebBotAuth` client sent for ``response``, exactly as on the wire.

    It is the request as signed, the one the response is bound to; the
    client's own ``response.request`` is the request before signing. ``None``
    when no :class:`WebBotAuth` client sent it.
    """
    sent = response.extensions.get(_SENT)
    return sent if isinstance(sent, HTTPRequest) else None


class ResponseNotVerified(Exception):
    """A ``2xx`` response the client couldn't verify, when it requires signed responses.

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


class ClientOptions(TypedDict, total=False):
    """The httpx client settings :meth:`WebBotAuth.async_client` and :meth:`WebBotAuth.client`
    pass through. Connection settings, such as TLS, proxies, and HTTP/2, belong to the
    ``transport`` the signing transport wraps."""

    auth: httpx.Auth | None
    params: Mapping[str, str] | None
    headers: Mapping[str, str] | None
    cookies: httpx.Cookies | dict[str, str] | None
    timeout: httpx.Timeout | float | None
    follow_redirects: bool
    max_redirects: int
    base_url: httpx.URL | str
    default_encoding: str


def _checked_options(options: Mapping[str, object]) -> None:
    """Refuses a setting that would route a request around the signing transport."""
    unknown = sorted(set(options) - ClientOptions.__optional_keys__)
    if unknown:
        raise ConfigurationError(
            f"{', '.join(unknown)} can't be set on a Web Bot Auth client: every request goes "
            "through its signing transport; configure TLS, proxies, and HTTP/2 on the "
            "transport= it wraps"
        )


def _media_type(response: httpx.Response) -> str | None:
    return HeaderLines(response.headers.multi_items()).media_type()


@dataclass(frozen=True, slots=True, init=False)
class WebBotAuth:
    """How a client signs requests and verifies responses. It builds the client.

    ``signer`` signs every request; with no signer, requests go unsigned,
    for a call that authenticates another way, such as a bearer token, and
    the client still verifies the signed response (:meth:`verify_only`). A
    response to an unsigned request needs no binding.

    With ``response_verifier``, the client decides from a response's header
    lines alone whether it is signed. An unsigned response is returned
    unread, so a stream arrives as it is sent. A signed one is read and
    verified, signature and binding to the request sent on that hop. Either
    way the client returns the response, and :func:`verification` reads what
    it found out: a :class:`VerifiedResponse` (which :func:`verified_response`
    returns), :class:`Unsigned`, or :class:`VerificationFailed`.

    With ``require_signed_response`` (the default), a ``2xx`` response that
    isn't verified raises :class:`ResponseNotVerified`, which carries the
    response. An unsigned response of a media type a server streams unsigned
    (:data:`~.rules.STREAMING_MEDIA_TYPES`, ``text/event-stream``) is let
    through, and so is every response that isn't a ``2xx``, such as a
    refusal a verifier sends unsigned (``400``, ``403``, ``429``, ``503``),
    a redirect, or a proxy's ``502``: its status, headers, and body are the
    peer's own.

    ``expect`` names whose signature the response carries, as
    :meth:`ResponseVerifier.verify` reads it: ``"same-origin"`` (the
    default), the identity of the host each hop went to; an :class:`Origin`;
    or ``None`` for any identity.

    ``runtime`` is the :class:`~.sync.SyncRuntime` of the verifier's
    resolver, owned by the caller. With it, the client verifies on the
    runtime's loop, so one configuration serves an ``httpx.Client`` and an
    ``httpx.AsyncClient`` alike. Without it, only an async client can
    verify: :meth:`client` raises :class:`ConfigurationError`.

    When it verifies responses, the client sends ``Accept-Encoding:
    identity``: ``Content-Digest`` covers the content as sent. The settings
    are fixed when the configuration is made.
    """

    signer: RequestSigning | None
    response_verifier: ResponseConfirmer | None
    runtime: SyncRuntime | None
    expect: Expect
    require_signed_response: bool

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
            raise ConfigurationError("a client that signs nothing must verify responses")
        if expect not in (SAME_ORIGIN, None) and not isinstance(expect, Origin):
            raise ConfigurationError(f"expect is an Origin, 'same-origin', or None, not {expect!r}")
        object.__setattr__(self, "signer", signer)
        object.__setattr__(self, "response_verifier", response_verifier)
        object.__setattr__(self, "runtime", runtime)
        object.__setattr__(self, "expect", expect)
        object.__setattr__(self, "require_signed_response", require_signed_response)

    @classmethod
    def verify_only(
        cls,
        response_verifier: ResponseConfirmer,
        *,
        runtime: SyncRuntime | None = None,
        expect: Expect = SAME_ORIGIN,
        require_signed_response: bool = True,
    ) -> WebBotAuth:
        """A configuration that sends requests unsigned and verifies each signed response."""
        return cls(
            None,
            response_verifier,
            runtime=runtime,
            expect=expect,
            require_signed_response=require_signed_response,
        )

    def async_client(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        **options: Unpack[ClientOptions],
    ) -> httpx.AsyncClient:
        """An ``httpx.AsyncClient`` whose one transport signs and verifies each wire hop.

        ``transport`` is the transport it wraps, ``httpx.AsyncHTTPTransport()``
        by default; set TLS, proxies, and HTTP/2 there. ``options`` are the
        client settings :class:`ClientOptions` lists; any other raises
        :class:`ConfigurationError`. The client reads no proxy from the
        environment, since a proxy mounted from it would bypass the signing
        transport.
        """
        _checked_options(options)
        inner = httpx.AsyncHTTPTransport() if transport is None else transport
        return httpx.AsyncClient(transport=_AsyncTransport(self, inner), trust_env=False, **options)

    def client(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        **options: Unpack[ClientOptions],
    ) -> httpx.Client:
        """An ``httpx.Client`` whose one transport signs and verifies each wire hop.

        It takes what :meth:`async_client` takes, with ``httpx.HTTPTransport()``
        as the default transport. It verifies on :attr:`runtime`: a
        configuration with a response verifier and no runtime raises
        :class:`ConfigurationError`.
        """
        _checked_options(options)
        if self.response_verifier is not None and self.runtime is None:
            raise ConfigurationError(
                "a sync client verifies on a SyncRuntime: pass WebBotAuth(..., runtime=...)"
            )
        inner = httpx.HTTPTransport() if transport is None else transport
        return httpx.Client(transport=_SyncTransport(self, inner), trust_env=False, **options)

    # ── one wire hop ──────────────────────────────────────────────────────

    def _wire(self, request: httpx.Request) -> tuple[httpx.Request, HTTPRequest]:
        """The request to send on this hop, signed for its own URL, and the request as sent.

        The client's request is left as it is, so nothing it builds from it,
        such as the request that follows a redirect, carries this signature.
        """
        lines = HeaderLines(request.headers.multi_items())
        if self.response_verifier is not None:
            lines = lines.with_replaced("Accept-Encoding", "identity")
        sent = HTTPRequest(request.method, str(request.url), lines, request.content)
        if self.signer is None:
            sent = replace(sent, url=target_uri(sent.url))
        else:
            sent = self.signer.sign(sent)
        wire = httpx.Request(
            sent.method,
            sent.url,
            headers=sent.headers.items(),
            stream=request.stream,
            extensions=request.extensions,
        )
        return wire, sent

    def _verify(
        self, verifier: ResponseConfirmer, response: httpx.Response, sent: HTTPRequest
    ) -> Coroutine[object, object, VerifiedResponse]:
        """Verifies the read ``response`` against ``sent``, the request this hop sent."""
        lines = response.headers.multi_items()
        message = HTTPResponse(response.status_code, lines, response.content, sent)
        return verifier.verify(message, expected_origin=self.expect)

    def _settle(self, response: httpx.Response, found: Verification) -> ResponseNotVerified | None:
        """Stores ``found`` on ``response``; the error to raise when the client refuses it."""
        response.extensions[EXTENSION] = found
        if isinstance(found, VerifiedResponse) or not self.require_signed_response:
            return None
        if not response.is_success:
            return None
        if isinstance(found, Unsigned) and _media_type(response) in STREAMING_MEDIA_TYPES:
            return None
        return ResponseNotVerified(response, found)


class _AsyncTransport(httpx.AsyncBaseTransport):
    """Signs each wire hop for its own URL and verifies the response to it, for an async client."""

    def __init__(self, auth: WebBotAuth, inner: httpx.AsyncBaseTransport) -> None:
        self._auth: Final = auth
        self._inner: Final = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        auth = self._auth
        wire, sent = auth._wire(request)
        response = await self._inner.handle_async_request(wire)
        response.request, response.extensions[_SENT] = wire, sent
        verifier = auth.response_verifier
        if verifier is None:
            return response
        found: Verification = UNSIGNED
        if is_signed(HeaderLines(response.headers.multi_items())):
            await response.aread()
            try:
                verify = auth._verify(verifier, response, sent)
                runtime = auth.runtime
                found = await (verify if runtime is None else runtime.run_async(verify))
            except WebBotAuthError as e:
                found = VerificationFailed(e.refusal, e.detail)
        refused = auth._settle(response, found)
        if refused is not None:
            await response.aread()
            raise refused
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class _SyncTransport(httpx.BaseTransport):
    """Signs each wire hop for its own URL and verifies the response to it, for a sync client."""

    def __init__(self, auth: WebBotAuth, inner: httpx.BaseTransport) -> None:
        self._auth: Final = auth
        self._inner: Final = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.read()
        auth = self._auth
        wire, sent = auth._wire(request)
        response = self._inner.handle_request(wire)
        response.request, response.extensions[_SENT] = wire, sent
        verifier, runtime = auth.response_verifier, auth.runtime
        if verifier is None or runtime is None:
            return response
        found: Verification = UNSIGNED
        if is_signed(HeaderLines(response.headers.multi_items())):
            response.read()
            try:
                found = runtime.run(auth._verify(verifier, response, sent))
            except WebBotAuthError as e:
                found = VerificationFailed(e.refusal, e.detail)
        refused = auth._settle(response, found)
        if refused is not None:
            response.read()
            raise refused
        return response

    def close(self) -> None:
        self._inner.close()


__all__ = [
    "EXTENSION",
    "UNSIGNED",
    "ClientOptions",
    "Expect",
    "ResponseNotVerified",
    "Unsigned",
    "Verification",
    "VerificationFailed",
    "WebBotAuth",
    "sent_request",
    "verification",
    "verified_response",
]
