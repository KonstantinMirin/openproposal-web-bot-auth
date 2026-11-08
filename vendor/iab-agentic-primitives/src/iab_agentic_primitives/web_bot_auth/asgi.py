"""Thin ASGI helpers: sign responses, serve the signed key directory, and,
opt-in, require a signature.

These are plain ASGI and import no framework, so they work with Starlette,
FastAPI, or any ASGI server.

- :class:`ResponseSigningMiddleware` signs each buffered response and binds it
  to the request it answers, and serves the directory of the key it signs
  with. It passes streaming responses (``text/event-stream``) through unsigned.
- :class:`DirectoryMiddleware` answers ``GET`` on the well-known directory path
  with the signed key directory of a :class:`~.directory.DirectoryPublisher`,
  for a party that signs no responses. A framework route answers the same with
  :meth:`DirectoryPublisher.answer`.
- :class:`RequireSignatureMiddleware` is opt-in. It verifies inbound
  signatures, refuses failures, and hands the app the :class:`VerifiedRequest`,
  which :func:`verified_request` reads from the scope. An application that
  resolves identity at its own boundary calls :meth:`RequestVerifier.verify`
  there instead.

Every answer the helpers write, refusals included, comes from
:mod:`.presentation`; this module only serializes it to ASGI messages.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Literal, TypeVar
from urllib.parse import quote

from .directory import DirectoryPublisher
from .errors import ConfigurationError, SigningError, WebBotAuthError
from .message import Answer, HeaderLines, HTTPRequest, HTTPResponse
from .presentation import (
    body_too_large_response,
    method_not_allowed_response,
    refusal_response,
    unsignable_response,
)
from .roles import RequestConfirmer, ResponseSigning
from .rules import STREAMING_MEDIA_TYPES
from .values import DIRECTORY_PATH, Clock, ServerIdentity, is_decimal, system_clock, whole_number
from .verifier import VerifiedRequest, is_signed

Scope = MutableMapping[str, object]
Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

#: The ``scope["state"]`` key that holds the :class:`VerifiedRequest`.
STATE_KEY = "web_bot_auth"
logger = logging.getLogger(__name__)


# ── reading ASGI mappings, typed once ─────────────────────────────────────

T = TypeVar("T")


def _of_type(mapping: Scope | Message, key: str, kind: type[T], default: T) -> T:
    value = mapping.get(key, default)
    if not isinstance(value, kind):
        raise TypeError(f"ASGI {key!r} is a {kind.__name__}, not {value!r}")
    return value


def _method(scope: Scope) -> str:
    return _of_type(scope, "method", str, "GET")


def _state(scope: Scope) -> dict[str, object]:
    state = scope.get("state")
    return dict(state) if isinstance(state, Mapping) else {}


def _raw_lines(scope_or_message: Scope | Message) -> list[tuple[bytes, bytes]]:
    lines = scope_or_message.get("headers", [])
    if not isinstance(lines, Iterable):
        raise TypeError(f"ASGI headers are pairs of bytes, not {lines!r}")
    return [(bytes(k), bytes(v)) for k, v in lines]


def _headers(scope_or_message: Scope | Message) -> list[tuple[str, str]]:
    return [(k.decode("latin-1"), v.decode("latin-1")) for k, v in _raw_lines(scope_or_message)]


def verified_request(scope: Scope) -> VerifiedRequest | None:
    """The :class:`VerifiedRequest` that :class:`RequireSignatureMiddleware` put on ``scope``.

    ``None`` for a request the middleware let through unsigned, or didn't see.
    """
    verified = _state(scope).get(STATE_KEY)
    return verified if isinstance(verified, VerifiedRequest) else None


def _checked_identity(identity: object) -> ServerIdentity:
    if not isinstance(identity, ServerIdentity):
        raise ConfigurationError(
            "identity is a ServerIdentity, such as "
            f"ServerIdentity.from_config('https://seller.example.com'), not {identity!r}"
        )
    return identity


def request_url(scope: Scope, identity: ServerIdentity) -> str:
    """Rebuilds the absolute URL the client requested, on the server's own base URL.

    ``identity.base_url``, such as ``https://seller.example.com``, is the
    server's public base URL. It is required: the ``Host`` header is the
    client's claim, and a signature covers ``@authority`` and ``@target-uri``
    so that a request signed for one server doesn't verify at another.
    """
    root = _checked_identity(identity).base_url
    raw_path = _of_type(scope, "raw_path", bytes, b"")
    path = (
        raw_path.decode("latin-1")
        if raw_path
        else quote(_of_type(scope, "path", str, "/"), safe="/:@!$&'()*+,;=-._~%")
    )
    query = _of_type(scope, "query_string", bytes, b"").decode("latin-1")
    return f"{root}{path}" + (f"?{query}" if query else "")


async def _read_body(
    receive: Receive, limit: int, headers: HeaderLines
) -> tuple[bytes, list[Message]]:
    """The request body and the messages it came in; ``_BodyTooLarge`` past ``limit`` bytes."""
    declared = _declared_length(headers)
    if declared is not None and declared > limit:
        raise _BodyTooLarge
    chunks: list[bytes] = []
    messages: list[Message] = []
    size = 0
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":  # http.disconnect
            break
        chunk = _of_type(message, "body", bytes, b"")
        size += len(chunk)
        if size > limit:
            raise _BodyTooLarge
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks), messages


def _replay(messages: list[Message], receive: Receive) -> Receive:
    pending = list(messages)

    async def replay() -> Message:
        if pending:
            return pending.pop(0)
        return await receive()

    return replay


#: The default body limit of both middlewares, in bytes.
MAX_BODY_BYTES = 1024 * 1024


def _declared_length(lines: HeaderLines) -> int | None:
    value = lines.get("content-length")
    return int(value) if value is not None and is_decimal(value) else None


def _raw(lines: Iterable[tuple[str, str]]) -> list[tuple[bytes, bytes]]:
    """Field lines as ASGI encodes them: lowercase latin-1 names, latin-1 values."""
    return [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in lines]


async def _send(send: Send, answer: Answer, *, head: bool = False) -> None:
    """Sends ``answer``, the one serializer of every answer the helpers write.

    ``Content-Length`` is always the length of ``answer.body``. For ``HEAD``
    the body isn't sent, and every header, ``Content-Length`` included, is the
    one ``GET`` gets (RFC 9110 section 9.3.2).
    """
    raw = _raw(answer.headers)
    raw.append((b"content-length", str(len(answer.body)).encode()))
    await send({"type": "http.response.start", "status": answer.status, "headers": raw})
    await send({"type": "http.response.body", "body": b"" if head else answer.body})


@dataclass(frozen=True, slots=True, init=False)
class DirectoryMiddleware:
    """Serves the signed key directory at the well-known path and passes other requests on.

    ``publisher`` is the :class:`~.directory.DirectoryPublisher` of the
    server's own identity: it reads the key source on every request and signs
    the response afresh, for its origin's authority, whatever ``Host`` the
    client sends, so the ``"@authority";req`` binding keeps another domain from
    serving the key set again. ``GET`` and ``HEAD`` are answered; anything else
    gets ``405``. It is immutable.
    """

    app: ASGIApp
    publisher: DirectoryPublisher
    clock: Clock

    def __init__(
        self, app: ASGIApp, publisher: DirectoryPublisher, *, clock: Clock = system_clock
    ) -> None:
        if not isinstance(publisher, DirectoryPublisher):
            raise ConfigurationError(f"publisher is a DirectoryPublisher, not {publisher!r}")
        object.__setattr__(self, "app", app)
        object.__setattr__(self, "publisher", publisher)
        object.__setattr__(self, "clock", clock)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != DIRECTORY_PATH:
            await self.app(scope, receive, send)
            return
        method = _method(scope)
        if method not in ("GET", "HEAD"):
            await _send(send, method_not_allowed_response())
            return
        await _send(send, await self.publisher.answer(self.clock()), head=method == "HEAD")


#: The ASGI extensions that let an app send a response the middleware can't buffer
#: and sign: a file by path, a file by descriptor, and trailers. The app never sees them.
UNSIGNABLE_EXTENSIONS = (
    "http.response.pathsend",
    "http.response.zerocopy",
    "http.response.trailers",
)


def _signable_scope(scope: Scope) -> Scope:
    """``scope`` without the extensions that bypass a buffered response."""
    extensions = scope.get("extensions")
    if not isinstance(extensions, Mapping) or not extensions:
        return scope
    kept = {k: v for k, v in extensions.items() if k not in UNSIGNABLE_EXTENSIONS}
    return {**scope, "extensions": kept}


#: Where a buffered response is: before its start, holding it back, passing it
#: through unsigned, or answered.
_State = Literal["waiting", "holding", "passthrough", "done"]


class _BufferedResponse:
    """The ``send`` a signed app gets: it holds back the start, buffers the body up to
    ``limit`` bytes, and sends the signed response when the body ends.

    A response that is already signed or streams (``skip``) passes through as
    sent. A second start, any other message after a held-back start, and a
    body over ``limit`` can't be signed, and are answered with ``500``.
    """

    def __init__(self, signer: ResponseSigning, request: HTTPRequest, options: _Options) -> None:
        self._signer = signer
        self._request = request
        self._options = options
        self._state: _State = "waiting"
        self._start: Message = {}
        self._chunks: list[bytes] = []
        self._size = 0

    async def __call__(self, message: Message) -> None:
        kind = message["type"]
        match self._state, kind:
            case ("passthrough", _) | ("waiting", "http.response.body"):
                await self._options.send(message)
            case ("waiting", "http.response.start"):
                await self._started(message)
            case ("holding", "http.response.body"):
                await self._body(message)
            case ("holding", _):
                await self._unsignable(SigningError(f"the app sent {kind!r}, not a body"))
            case _:
                pass  # the answer is sent; nothing more belongs to it

    async def _started(self, message: Message) -> None:
        lines = HeaderLines(_headers(message))
        if lines.carries_signature_field() or lines.media_type() in self._options.skip:
            self._state = "passthrough"
            await self._options.send(message)
            return
        self._state, self._start = "holding", message
        declared = _declared_length(lines)
        if declared is not None and declared > self._options.limit:
            await self._too_large()

    async def _body(self, message: Message) -> None:
        chunk = _of_type(message, "body", bytes, b"")
        self._size += len(chunk)
        if self._size > self._options.limit:
            await self._too_large()
            return
        self._chunks.append(chunk)
        if not message.get("more_body", False):
            await self._finish()

    async def _finish(self) -> None:
        body = b"".join(self._chunks)
        status = _of_type(self._start, "status", int, 0)
        response = HTTPResponse(status, _headers(self._start), body, self._request)
        try:
            signed = self._signer.sign(response)
        except SigningError as e:
            await self._unsignable(e)
            return
        self._state = "done"
        added = _raw(signed.headers.items()[len(response.headers) :])
        await self._options.send({**self._start, "headers": [*_raw_lines(self._start), *added]})
        await self._options.send({"type": "http.response.body", "body": body})

    async def _too_large(self) -> None:
        limit = self._options.limit
        await self._unsignable(SigningError(f"the response body exceeds {limit} bytes"))

    async def _unsignable(self, error: SigningError) -> None:
        # A response the profile can't sign, such as a body without Content-Type, is an
        # application bug. Refuse loudly instead of sending it unsigned.
        self._state = "done"
        logger.error(
            "cannot sign the response to %s %s: %s", self._request.method, self._request.url, error
        )
        await _send(self._options.send, unsignable_response(error))


@dataclass(frozen=True, slots=True)
class _Options:
    send: Send
    skip: tuple[str, ...]
    limit: int


@dataclass(frozen=True, slots=True)
class SigningPolicy:
    """What :class:`ResponseSigningMiddleware` signs, checked once.

    Responses of the ``skip_media_types`` (``text/event-stream`` by default)
    stream, and pass through unsigned. A response body is buffered up to
    ``max_body_bytes`` (1 MiB by default). A bad value raises
    :class:`ConfigurationError`.
    """

    skip_media_types: tuple[str, ...] = STREAMING_MEDIA_TYPES
    max_body_bytes: int = MAX_BODY_BYTES

    def __post_init__(self) -> None:
        types = self.skip_media_types
        if isinstance(types, str) or not all(isinstance(t, str) for t in types):
            raise ConfigurationError(f"skip_media_types is a tuple of media types, not {types!r}")
        object.__setattr__(self, "skip_media_types", tuple(t.lower() for t in types))
        whole_number("max_body_bytes", self.max_body_bytes, minimum=0)


#: The default signing policy: stream ``text/event-stream`` unsigned, buffer 1 MiB at most.
DEFAULT_SIGNING = SigningPolicy()


@dataclass(frozen=True, slots=True, init=False)
class ResponseSigningMiddleware:
    """Signs every buffered response with ``signer``, bound to the request it answers,
    and serves the directory its peers verify those signatures with.

    ``identity`` is the server's own :class:`ServerIdentity`: the request each
    response answers is rebuilt on its ``base_url``. ``publisher`` is the
    :class:`~.directory.DirectoryPublisher` of the same identity, which the
    middleware serves at the well-known path as :class:`DirectoryMiddleware`
    does. The three are checked against each other when the middleware is
    made: ``signer`` signs as the identity's origin, the publisher publishes
    that origin's directory, and a publisher with a list of keys lists the
    signer's key. A mismatch raises :class:`ConfigurationError`, so a server
    never starts up signing what its peers would refuse.

    :class:`SigningPolicy` holds the options. The middleware passes through
    unsigned the responses of its ``skip_media_types``, which stream, and
    responses that already carry a signature. A response it can't sign under
    the profile, such as a body without ``Content-Type``, or a body over
    ``max_body_bytes``, becomes a ``500`` with error ``response-unsignable``
    and is logged, so a route never sends an unsigned answer silently. The
    app's scope doesn't advertise ``http.response.pathsend``,
    ``http.response.zerocopy``, or ``http.response.trailers``, so a file
    response is sent as a body and signed. A request whose ``web-bot-auth``
    signature is incomplete (no ``Signature`` member) gets an unbound
    response. It is immutable.
    """

    app: ASGIApp
    signer: ResponseSigning
    identity: ServerIdentity
    directory: DirectoryMiddleware
    policy: SigningPolicy

    def __init__(
        self,
        app: ASGIApp,
        signer: ResponseSigning,
        *,
        identity: ServerIdentity,
        publisher: DirectoryPublisher,
        policy: SigningPolicy = DEFAULT_SIGNING,
    ) -> None:
        checked = _checked_identity(identity)
        if signer.origin != checked.origin:
            raise ConfigurationError(
                f"the signer signs as {signer.origin}, but the server's identity is "
                f"{checked.origin}"
            )
        directory = DirectoryMiddleware(app, publisher)
        publisher.check_signer(signer.origin, signer.keyid)
        object.__setattr__(self, "app", app)
        object.__setattr__(self, "signer", signer)
        object.__setattr__(self, "identity", checked)
        object.__setattr__(self, "directory", directory)
        object.__setattr__(self, "policy", policy)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("path") == DIRECTORY_PATH:
            await self.directory(scope, receive, send)
            return
        request = HTTPRequest(_method(scope), request_url(scope, self.identity), _headers(scope))
        policy = self.policy
        options = _Options(send, policy.skip_media_types, policy.max_body_bytes)
        await self.app(
            _signable_scope(scope), receive, _BufferedResponse(self.signer, request, options)
        )


#: What :class:`RequireSignatureMiddleware` does with an unsigned request.
OnUnsigned = Literal["refuse", "pass"]


@dataclass(frozen=True, slots=True)
class RequirePolicy:
    """What :class:`RequireSignatureMiddleware` requires of a request, checked once.

    ``prefixes`` are the paths it guards. An unsigned request is refused
    (``on_unsigned="refuse"``, the default) or passed on with no identity
    (``"pass"``). A signed request's body is read up to ``max_body_bytes``
    (1 MiB by default). A bad value raises :class:`ConfigurationError`.
    """

    prefixes: tuple[str, ...] = ("/",)
    on_unsigned: OnUnsigned = "refuse"
    max_body_bytes: int = MAX_BODY_BYTES

    def __post_init__(self) -> None:
        if isinstance(self.prefixes, str) or not all(isinstance(p, str) for p in self.prefixes):
            raise ConfigurationError(f"prefixes is a tuple of paths, not {self.prefixes!r}")
        if self.on_unsigned not in ("refuse", "pass"):
            raise ConfigurationError(f"on_unsigned is 'refuse' or 'pass', not {self.on_unsigned!r}")
        whole_number("max_body_bytes", self.max_body_bytes, minimum=0)


#: The default policy: guard every path, refuse an unsigned request, and read 1 MiB at most.
DEFAULT_REQUIRE = RequirePolicy()


class _BodyTooLarge(Exception):
    pass


def _has_body(headers: HeaderLines) -> bool:
    """Whether the request declares a body, read from its header alone."""
    return bool(_declared_length(headers)) or "transfer-encoding" in headers


@dataclass(frozen=True, slots=True, init=False)
class RequireSignatureMiddleware:
    """Opt-in: verifies inbound signatures on the paths ``policy.prefixes`` names.

    ``confirmer`` is a :class:`~.roles.RequestConfirmer`, such as a
    :class:`RequestVerifier`; the middleware rebuilds each request URL on the
    confirmer's own ``identity``. :class:`RequirePolicy` holds the options. An
    unsigned request is refused (``on_unsigned="refuse"``, the default) or
    passed on with no identity (``"pass"``), decided from its header before
    any of its body is read: a request is signed when it carries
    ``Signature-Input`` (:func:`~.verifier.is_signed`). A signed request's body is read up to
    ``max_body_bytes`` (1 MiB by default); a larger one is answered ``413``. A
    request whose signature fails is always refused, with
    :func:`~.presentation.refusal_response`. A verified request reaches the app
    with its :class:`VerifiedRequest`, which :func:`verified_request` reads. It
    is immutable.
    """

    app: ASGIApp
    confirmer: RequestConfirmer
    policy: RequirePolicy

    def __init__(
        self, app: ASGIApp, confirmer: RequestConfirmer, *, policy: RequirePolicy = DEFAULT_REQUIRE
    ) -> None:
        _checked_identity(confirmer.identity)
        object.__setattr__(self, "app", app)
        object.__setattr__(self, "confirmer", confirmer)
        object.__setattr__(self, "policy", policy)

    def _guarded(self, scope: Scope) -> bool:
        path = _of_type(scope, "path", str, "")
        return (
            scope["type"] == "http"
            and path != DIRECTORY_PATH
            and path.startswith(self.policy.prefixes)
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self._guarded(scope):
            await self.app(scope, receive, send)
            return
        headers = HeaderLines(_headers(scope))
        url = request_url(scope, self.confirmer.identity)
        if not is_signed(headers):
            if self.policy.on_unsigned == "pass":
                await self.app(scope, receive, send)
                return
            # The core refuses it from the header alone; the body is never read.
            await self._verify(send, HTTPRequest(_method(scope), url, headers), _has_body(headers))
            return
        try:
            body, messages = await _read_body(receive, self.policy.max_body_bytes, headers)
        except _BodyTooLarge:
            await _send(send, body_too_large_response(self.policy.max_body_bytes))
            return
        verified = await self._verify(
            send, HTTPRequest(_method(scope), url, headers, body), bool(body)
        )
        if verified is not None:
            state = {**_state(scope), STATE_KEY: verified}
            await self.app({**scope, "state": state}, _replay(messages, receive), send)

    async def _verify(
        self, send: Send, request: HTTPRequest, has_body: bool
    ) -> VerifiedRequest | None:
        """The verified request, or ``None`` once its refusal is sent."""
        try:
            return await self.confirmer.verify(request)
        except WebBotAuthError as e:
            await _send(send, refusal_response(e, has_body=has_body))
            return None


__all__ = [
    "DEFAULT_REQUIRE",
    "DEFAULT_SIGNING",
    "MAX_BODY_BYTES",
    "STREAMING_MEDIA_TYPES",
    "ASGIApp",
    "DirectoryMiddleware",
    "Message",
    "OnUnsigned",
    "Receive",
    "RequirePolicy",
    "RequireSignatureMiddleware",
    "ResponseSigningMiddleware",
    "Scope",
    "Send",
    "SigningPolicy",
    "request_url",
    "verified_request",
]
