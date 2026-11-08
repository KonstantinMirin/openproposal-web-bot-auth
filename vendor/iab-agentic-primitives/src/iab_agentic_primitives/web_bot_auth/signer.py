"""Signing requests and responses under the profile.

Both signers take a message and return a new, signed message; the caller's
message is immutable. ``Signature-Agent`` names the signer's key directory URL,
``https://<host>/.well-known/http-message-signatures-directory``, with no member
parameters.

A request signature covers ``@method``, ``@target-uri``, ``@authority``, and
``"signature-agent";key=<label>``; with a body, also ``content-type`` and
``content-digest``. Its parameters are ``created``, ``keyid``, ``alg``,
``expires`` (300 s later), a 64-byte ``nonce``, and ``tag="web-bot-auth"``.

A response signature covers ``@status``, ``"@method";req``, ``"@target-uri";req``,
and ``"signature-agent";key=<label>``; with a body, also ``content-type`` and
``content-digest``; and, when the request carried a ``web-bot-auth`` signature,
``"signature";req;key=<request label>``, which binds the response to that
exact request. It carries no nonce: the binding gives freshness.

The signers sign what the profile requires and nothing else; they take no
parameter that departs from it, so a signer can't emit what a verifier
refuses. Each holds one frozen :class:`SignerConfig`.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, replace
from typing import Self, TypeVar

from . import _sig
from ._wire import ContentDigestError, check_content_digest, content_digest
from .errors import ConfigurationError, SigningError
from .keys import Ed25519Key
from .message import HeaderLines, HTTPRequest, HTTPResponse
from .rules import (
    MAX_LIFETIME,
    MESSAGE_WINDOW,
    NONCE_BYTES,
    NONCE_RULE,
    REQUEST,
    RESPONSE,
    Rules,
    Stamp,
    validate_nonce,
)
from .values import Clock, KeyId, Origin, UnixSeconds, b64url_encode, system_clock

M = TypeVar("M", HTTPRequest, HTTPResponse)
N = TypeVar("N", str, str | None)

#: A Structured Fields Dictionary key, which a signature label must be (RFC 9651 section 3.2).
_LABEL = re.compile(r"[a-z*][a-z0-9_.*-]*")


def generate_nonce() -> str:
    """Returns 64 random bytes as unpadded base64url."""
    return b64url_encode(secrets.token_bytes(NONCE_BYTES))


def _checked_label(label: object) -> str:
    """A label that can key the signature fields: a Structured Fields Dictionary key."""
    if not isinstance(label, str) or _LABEL.fullmatch(label) is None:
        raise ConfigurationError(f"label {label!r} is not a Structured Fields Dictionary key")
    return label


@dataclass(frozen=True, slots=True)
class SignerConfig:
    """A signer's configuration, checked once when it is made, then immutable.

    ``origin`` is the identity the signer signs as. ``label`` must be a
    Structured Fields Dictionary key, and ``lifetime`` whole seconds within
    the message window's ``max_lifetime``. A bad value raises
    :class:`ConfigurationError`. One config can serve a request signer and a
    response signer alike.
    """

    key: Ed25519Key
    origin: Origin
    label: str = "sig1"
    lifetime: int = MAX_LIFETIME
    clock: Clock = system_clock

    def __post_init__(self) -> None:
        if not isinstance(self.key, Ed25519Key):
            raise ConfigurationError(f"key is an Ed25519Key, not {self.key!r}")
        if not isinstance(self.origin, Origin):
            raise ConfigurationError(f"origin is an Origin, not {self.origin!r}")
        MESSAGE_WINDOW.checked_lifetime(self.lifetime)
        _checked_label(self.label)


def _digest_lines(lines: HeaderLines, body: bytes) -> HeaderLines:
    """``lines`` with the body's ``Content-Digest``, added or checked."""
    if lines.get("content-type") is None:
        raise SigningError("a message with a body needs Content-Type, which the signature covers")
    if "content-digest" not in lines:
        return lines.with_added("Content-Digest", content_digest(body))
    try:
        check_content_digest(lines, body)
    except ContentDigestError as e:
        raise SigningError(f"the existing {e}; the profile requires sha-256") from e
    return lines


def _prepared(message: M, config: SignerConfig) -> M:
    """``message`` with the lines its signature adds: ``Content-Digest`` and ``Signature-Agent``."""
    lines = message.headers
    if lines.carries_signature_field() or "signature-agent" in lines:
        raise SigningError(
            "the message already carries a signature field; the profile signs once per message"
        )
    if message.body:
        lines = _digest_lines(lines, message.body)
    agent = f'{config.label}="{config.origin.directory_url}"'
    return replace(message, headers=lines.with_added("Signature-Agent", agent))


def _sign(
    message: M, config: SignerConfig, rules: Rules[M, N], *, now: UnixSeconds | None, nonce: N
) -> M:
    """``message`` signed under ``rules`` as ``config`` says: the one signing core."""
    created = config.clock() if now is None else now
    prepared = _prepared(message, config)
    expires = UnixSeconds(created + config.lifetime)
    stamp = Stamp(config.label, config.key.thumbprint, created, expires)
    params = rules.params_for(prepared, stamp, nonce)
    return _sig.signed(prepared, config.key, params, mode="replace")


@dataclass(frozen=True, slots=True)
class _Signer:
    """What both signers hold: one frozen :class:`SignerConfig`."""

    config: SignerConfig

    def __post_init__(self) -> None:
        if not isinstance(self.config, SignerConfig):
            raise ConfigurationError(f"config is a SignerConfig, not {self.config!r}")

    @classmethod
    def of(cls, key: Ed25519Key, origin: Origin | str) -> Self:
        """The signer of ``key`` as ``origin``, with the default label, lifetime, and clock.

        A string ``origin`` is read with :meth:`Origin.parse`.
        """
        identity = origin if isinstance(origin, Origin) else Origin.parse(origin)
        return cls(SignerConfig(key, identity))

    @property
    def origin(self) -> Origin:
        """The identity the signer signs as."""
        return self.config.origin

    @property
    def keyid(self) -> KeyId:
        """The key id the signer signs with: its key's thumbprint."""
        return self.config.key.thumbprint


@dataclass(frozen=True, slots=True)
class RequestSigner(_Signer):
    """Signs requests as ``config.origin`` with ``config.key``. It is immutable."""

    def sign(
        self, request: HTTPRequest, *, now: UnixSeconds | None = None, nonce: str | None = None
    ) -> HTTPRequest:
        """Returns ``request`` signed: its field lines followed by ``Content-Digest`` (with a
        body and none given), ``Signature-Agent``, ``Signature-Input``, and ``Signature``.

        ``nonce`` is a fresh 64-byte nonce by default; one given must be in a
        form the profile accepts. Raises :class:`SigningError` for a request
        the profile can't sign.
        """
        chosen = generate_nonce() if nonce is None else nonce
        if not validate_nonce(chosen):
            raise SigningError(NONCE_RULE)
        return _sign(request, self.config, REQUEST, now=now, nonce=chosen)


@dataclass(frozen=True, slots=True)
class ResponseSigner(_Signer):
    """Signs responses as ``config.origin`` with ``config.key``, bound to their requests.

    It is immutable.
    """

    def sign(self, response: HTTPResponse, *, now: UnixSeconds | None = None) -> HTTPResponse:
        """Returns ``response`` signed, bound to ``response.request``.

        ``response.request`` is the request the response answers, with its
        headers as received. When it carries a ``web-bot-auth`` signature, the
        response signature covers ``"signature";req;key=<its label>``.
        Raises :class:`SigningError` for a response the profile can't sign.
        """
        return _sign(response, self.config, RESPONSE, now=now, nonce=None)


__all__ = [
    "RequestSigner",
    "ResponseSigner",
    "SignerConfig",
    "generate_nonce",
]
