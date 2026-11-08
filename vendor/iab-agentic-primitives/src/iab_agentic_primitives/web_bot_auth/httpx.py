"""An ``httpx.Auth`` that signs outbound requests and verifies signed responses.

.. code-block:: python

    async with DirectoryResolver() as resolver:
        auth = WebBotAuth(RequestSigner.of(key, "https://buyer.example.com"),
                          ResponseVerifier(resolver))
        async with httpx.AsyncClient(auth=auth) as client:
            response = await client.post(url, json=commit)
            verified = verified_response(response)  # a VerifiedResponse, or None

A synchronous ``httpx.Client`` verifies on a :class:`~.sync.SyncRuntime` that
the caller owns, passed as ``runtime=``.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from typing import Final, Literal

import httpx

from .errors import ConfigurationError, Refusal, WebBotAuthError, refuse
from .message import HTTPRequest, HTTPResponse
from .roles import RequestSigning, ResponseConfirmer
from .sync import SyncRuntime
from .values import Origin
from .verifier import VerifiedResponse

#: The key of the response's :class:`VerifiedResponse` in ``response.extensions``.
EXTENSION = "web_bot_auth"


def verified_response(response: httpx.Response) -> VerifiedResponse | None:
    """The :class:`VerifiedResponse` that :class:`WebBotAuth` stored on ``response``.

    ``None`` when the auth didn't verify the response, such as an unsigned
    response it was told to accept.
    """
    verified = response.extensions.get(EXTENSION)
    return verified if isinstance(verified, VerifiedResponse) else None


#: Whose signature a response must carry: an :class:`Origin`, the identity of the
#: host the client called (``"same-origin"``), or any identity (``None``).
Expect = Origin | Literal["same-origin"] | None


def _host_origin(request: httpx.Request) -> Origin:
    """The identity of the host ``request`` went to, ``https://<host>``, whatever its port."""
    host = request.url.host
    try:
        return Origin.parse(f"https://[{host}]" if ":" in host else f"https://{host}")
    except ConfigurationError as e:
        raise refuse(Refusal.ORIGIN_MISMATCH, f"{host!r} is not a host an identity can name") from e


class WebBotAuth(httpx.Auth):
    """Signs each request with ``signer`` and, optionally, verifies the response.

    With ``response_verifier``, the auth verifies the response signature and
    its binding to the request, and :func:`verified_response` returns the
    :class:`VerifiedResponse`. A response that fails verification raises
    :class:`WebBotAuthError`. An unsigned response raises too when
    ``require_signed_response`` is set; otherwise :func:`verified_response`
    returns ``None``. ``expect`` names whose signature the response carries:
    ``"same-origin"`` (the default), the identity of the host the client
    called, ``https://<host>``, whatever the URL's scheme and port; an
    :class:`Origin`; or ``None`` for any identity.

    ``runtime`` is the :class:`~.sync.SyncRuntime` of the verifier's
    resolver, owned by the caller. With it, the auth verifies on the
    runtime's loop, so one auth serves an ``httpx.Client`` and an
    ``httpx.AsyncClient`` alike. Without it, only an async client can verify:
    a sync client's verify raises :class:`ConfigurationError`. The auth
    starts no thread and owns nothing to close.

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

    def __init__(
        self,
        signer: RequestSigning | None,
        response_verifier: ResponseConfirmer | None = None,
        *,
        runtime: SyncRuntime | None = None,
        expect: Expect = "same-origin",
        require_signed_response: bool = True,
    ) -> None:
        if signer is None and response_verifier is None:
            raise ConfigurationError("an auth that signs nothing must verify responses")
        if expect is not None and expect != "same-origin" and not isinstance(expect, Origin):
            raise ConfigurationError(f"expect is an Origin, 'same-origin', or None, not {expect!r}")
        self._signer: Final = signer
        self._verifier: Final = response_verifier
        self._runtime: Final = runtime
        self._expect: Final = expect
        self._require_signed: Final = require_signed_response
        self.requires_response_body = response_verifier is not None

    @classmethod
    def verify_only(
        cls,
        response_verifier: ResponseConfirmer,
        *,
        runtime: SyncRuntime | None = None,
        expect: Expect = "same-origin",
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

    def _sign(self, request: httpx.Request) -> HTTPRequest:
        if self._verifier is not None:
            request.headers["Accept-Encoding"] = "identity"
        sent = HTTPRequest(
            request.method, str(request.url), request.headers.multi_items(), request.content
        )
        if self._signer is None:
            return sent
        signed = self._signer.sign(sent)
        # Signing only appends field lines, so the new ones follow the request's own.
        for name, value in signed.headers.items()[len(sent.headers) :]:
            request.headers[name] = value
        return signed

    def _verify_args(
        self, request: httpx.Request, response: httpx.Response, sent: HTTPRequest
    ) -> tuple[HTTPResponse, Origin | None]:
        """What both flows verify: the response as received, and the origin it must carry."""
        message = HTTPResponse(
            response.status_code, response.headers.multi_items(), response.content, sent
        )
        expected = _host_origin(request) if self._expect == "same-origin" else self._expect
        return message, expected

    def _settle(self, response: httpx.Response, verified: VerifiedResponse | None) -> None:
        response.extensions[EXTENSION] = verified

    def _allow_unsigned(self, error: WebBotAuthError) -> None:
        """Accepts an unsigned response when that is allowed; re-raises any other refusal."""
        if error.refusal is not Refusal.SIGNATURE_MISSING or self._require_signed:
            raise error

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        sent = self._sign(request)
        response = yield request
        if self._verifier is None:
            return
        if self._runtime is None:
            raise ConfigurationError(
                "a sync client verifies on a SyncRuntime: pass WebBotAuth(..., runtime=...)"
            )
        response.read()
        verified: VerifiedResponse | None = None
        try:
            message, expected = self._verify_args(request, response, sent)
            verify = self._verifier.verify(message, expected_origin=expected)
            verified = self._runtime.run(verify)
        except WebBotAuthError as e:
            self._allow_unsigned(e)
        self._settle(response, verified)

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        sent = self._sign(request)
        response = yield request
        if self._verifier is None:
            return
        await response.aread()
        verified: VerifiedResponse | None = None
        try:
            message, expected = self._verify_args(request, response, sent)
            verify = self._verifier.verify(message, expected_origin=expected)
            runtime = self._runtime
            verified = await (verify if runtime is None else runtime.run_async(verify))
        except WebBotAuthError as e:
            self._allow_unsigned(e)
        self._settle(response, verified)


__all__ = [
    "Expect",
    "WebBotAuth",
    "verified_response",
]
