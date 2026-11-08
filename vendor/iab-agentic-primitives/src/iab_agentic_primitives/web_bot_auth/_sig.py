"""The RFC 9421 seam: signature base construction and Ed25519, from http-message-signatures.

The profile modules decide what to sign and what to accept. This module asks
``http_message_signatures`` to build the signature base and to sign or verify
it, so the base is the library's, not a copy of it. It takes and returns the
module's own types: a message goes in as :class:`HTTPRequest` or
:class:`HTTPResponse`, and every library error comes out as
:class:`SigningError` on sign or a refusal on verify.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, replace
from typing import Literal, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures import VerifyResult as _LibraryResult
from http_message_signatures.exceptions import HTTPMessageSignaturesException

from ._wire import ComponentId, SignatureMember, only_member, signature_values
from .errors import Refusal, SigningError, refuse
from .keys import Ed25519Key
from .message import HeaderLines, HTTPRequest, HTTPResponse
from .values import OMIT, KeyId, Omit, UnixSeconds

M = TypeVar("M", HTTPRequest, HTTPResponse)
#: Whether a signature replaces the message's signatures or joins them.
Mode = Literal["replace", "append"]

#: The library's identifier of the one algorithm the key signs with.
_ED25519: str = algorithms.ED25519.algorithm_id


@dataclass(frozen=True, slots=True)
class SignatureParams:
    """What one signature covers and the parameters it carries.

    ``alg`` is the value written to the ``alg`` parameter. The key always
    signs Ed25519, so any other value is a claim the profile refuses.
    """

    label: str
    components: tuple[ComponentId, ...]
    created: UnixSeconds
    keyid: KeyId
    expires: UnixSeconds | Literal[Omit.OMIT] = OMIT
    nonce: str | Literal[Omit.OMIT] = OMIT
    tag: str | Literal[Omit.OMIT] = OMIT
    alg: str | Literal[Omit.OMIT] = _ED25519


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """What the library authenticated for one signature.

    ``created``, ``expires``, ``nonce``, and ``keyid`` are the signed
    parameters, and ``components`` the covered component identifiers.
    ``body`` is the body bytes when a covered ``Content-Digest`` matched them,
    and ``None`` when the signature doesn't cover the body.
    ``signature_base`` is the base the signature signs (RFC 9421 section 2.5).
    """

    label: str
    keyid: KeyId
    created: UnixSeconds
    expires: UnixSeconds
    nonce: str | None
    components: tuple[ComponentId, ...]
    body: bytes | None
    signature_base: bytes


# ── the library's message protocol ────────────────────────────────────────


class _FieldLines:
    """The mutable field lines ``http_message_signatures`` reads and writes while it signs."""

    def __init__(self, lines: Iterable[tuple[str, str]]) -> None:
        self._lines = list(lines)

    def items(self) -> list[tuple[str, str]]:
        return list(self._lines)

    def __iter__(self) -> Iterator[str]:
        return iter(dict.fromkeys(name for name, _ in self._lines))

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and any(n.lower() == name.lower() for n, _ in self._lines)

    def __setitem__(self, name: str, value: str) -> None:
        self._lines.append((name, value))

    def __delitem__(self, name: str) -> None:
        self._lines = [(n, v) for n, v in self._lines if n.lower() != name.lower()]


@dataclass
class _RequestView:
    method: str
    url: str
    headers: _FieldLines


@dataclass
class _ResponseView:
    status_code: int
    headers: _FieldLines
    request: _RequestView


def _request_view(request: HTTPRequest) -> _RequestView:
    return _RequestView(request.method.upper(), request.url, _FieldLines(request.headers))


def _view(message: HTTPRequest | HTTPResponse) -> _RequestView | _ResponseView:
    if isinstance(message, HTTPResponse):
        return _ResponseView(
            message.status, _FieldLines(message.headers), _request_view(message.request)
        )
    return _request_view(message)


# ── signing ───────────────────────────────────────────────────────────────


def _algorithm(alg: str | Omit) -> type[algorithms.HTTPSignatureAlgorithm]:
    """Ed25519, labelled ``alg`` when the parameters claim another value."""
    if alg is OMIT or alg == _ED25519:
        return algorithms.ED25519
    return type("ClaimedAlgorithm", (algorithms.ED25519,), {"algorithm_id": alg})


def _utc(seconds: UnixSeconds) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.UTC)


def signed(message: M, key: Ed25519Key, params: SignatureParams, *, mode: Mode) -> M:
    """``message`` signed with ``key`` under ``params``: the one signing call.

    ``mode="append"`` keeps the signatures already on the message, and
    ``"replace"`` drops them. ``Signature-Input`` and ``Signature`` are placed
    last, as the library places them. The caller's message is unchanged.
    Raises :class:`SigningError` when the library can't sign the message, for
    example when a request URL isn't absolute or a covered field is absent.
    """
    view = _view(message)
    signer = HTTPMessageSigner(signature_algorithm=_algorithm(params.alg))
    try:
        prepared = signer.prepare(
            view,
            key_id=params.keyid,
            created=_utc(params.created),
            expires=None if params.expires is OMIT else _utc(params.expires),
            nonce=None if params.nonce is OMIT else params.nonce,
            label=params.label,
            tag=None if params.tag is OMIT else params.tag,
            include_alg=params.alg is not OMIT,
            covered_component_ids=[str(c) for c in params.components],
            # The profile adds Content-Digest itself; the library reuses it and never adds one.
            use_existing_digest="content-digest" in message.headers,
        )
        signer.apply(
            view,
            prepared,
            key.sign(prepared.signature_base),
            append_if_signature_exists=mode == "append",
        )
    except HTTPMessageSignaturesException as e:
        raise SigningError(f"the message can't be signed: {e}") from e
    signature_input, signature = signature_values(HeaderLines(view.headers.items()))
    lines = message.headers.with_replaced("Signature-Input", signature_input)
    return replace(message, headers=lines.with_replaced("Signature", signature))


def signed_by_each(message: M, signers: Sequence[tuple[Ed25519Key, SignatureParams]]) -> M:
    """``message`` signed once by each key, in order, each signature kept beside the others."""
    for i, (key, params) in enumerate(signers):
        message = signed(message, key, params, mode="append" if i else "replace")
    return message


# ── verifying ─────────────────────────────────────────────────────────────


class _ProfileClockVerifier(HTTPMessageVerifier):
    """The library verifier, with the time window left to the profile."""

    def validate_created_and_expires(self, sig_input: object, max_age: object = None) -> None:
        """Skips the library's wall-clock check.

        The profile checks ``created`` and ``expires`` against its injected
        clock before it calls :func:`verify`, so neither argument is read here.
        """


def _result(result: _LibraryResult, member: SignatureMember) -> VerifyResult:
    created, expires = result.parameters.get("created"), result.parameters.get("expires")
    keyid = result.parameters.get("keyid")
    if type(created) is not int or type(expires) is not int or not isinstance(keyid, str):
        raise refuse(
            Refusal.SIGNATURE_INVALID,
            f"signature {result.label} doesn't sign created, expires, and keyid",
        )
    # The library's covered components end with "@signature-params": they are the base's lines.
    base = "\n".join(f"{k}: {v}" for k, v in result.covered_components.items()).encode()
    return VerifyResult(
        result.label,
        KeyId(keyid),
        UnixSeconds(created),
        UnixSeconds(expires),
        result.nonce,
        member.components,
        result.body,
        base,
    )


def verify(
    message: HTTPRequest | HTTPResponse,
    member: SignatureMember,
    public_key: Ed25519PublicKey,
    *,
    require_components: Sequence[ComponentId],
    body: bytes | None,
) -> VerifyResult:
    """Verifies the signature ``member`` names, with ``public_key``.

    The library checks that the signature covers ``require_components`` and,
    given ``body``, that the signature covers ``Content-Digest`` and the digest
    matches ``body``. Pass ``body=None`` only when the signature doesn't cover
    the body. Raises a ``signature-invalid`` refusal on any failure.
    """
    if member.keyid is None or member.tag is None:
        raise refuse(Refusal.SIGNATURE_INVALID, f"signature {member.label} has no keyid or tag")
    verifier = _ProfileClockVerifier(
        signature_algorithm=algorithms.ED25519,
        key_resolver=MappingKeyResolver(public_keys={member.keyid: public_key}, private_keys={}),
    )
    try:
        alone = replace(message, headers=only_member(message.headers, member.label))
    except ValueError as e:
        raise refuse(Refusal.SIGNATURE_INVALID, f"signature {member.label}: {e}") from e
    try:
        results = verifier.verify(
            _view(alone),
            expect_tag=member.tag,
            expect_label=member.label,
            max_age=None,
            require_components=[str(c) for c in require_components],
            body=body,
        )
    except HTTPMessageSignaturesException as e:
        raise refuse(
            Refusal.SIGNATURE_INVALID, f"signature {member.label} does not verify: {e}"
        ) from e
    # Labels are unique, and the library raises when none matches: one result.
    return _result(results[0], member)
