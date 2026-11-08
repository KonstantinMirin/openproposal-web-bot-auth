"""Raw signing, for the conformance vectors and scenarios only.

The profile's signers sign what the profile requires, and nothing else: they
take no parameter that departs from it. A conformance vector has to sign what
the profile refuses, such as another ``alg``, a missing nonce, an uncovered
member, or a directory signed for another authority. This module signs a
message with a finished :class:`SignatureParams` and nothing checked, so a
verifier can be shown each of those.

Only :mod:`.conformance` imports it, and an import contract keeps it that
way. The package doesn't export it. A production signer never needs it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

from . import _sig
from ._sig import Mode, SignatureParams
from ._wire import content_digest, parse_signature_fields
from .keys import Ed25519Key
from .message import HTTPRequest, HTTPResponse

M = TypeVar("M", HTTPRequest, HTTPResponse)


def sign_unchecked(
    message: M, key: Ed25519Key, params: SignatureParams, *, mode: Mode = "replace"
) -> M:
    """``message`` signed by ``key`` under ``params``, whatever they are.

    The header lines the signature covers, such as ``Signature-Agent`` and
    ``Content-Digest``, must already be on ``message``. ``mode="append"``
    keeps the signatures already there.
    """
    return _sig.signed(message, key, params, mode=mode)


def sign_each_unchecked(message: M, signers: Sequence[tuple[Ed25519Key, SignatureParams]]) -> M:
    """``message`` signed once by each key under its own parameters, as a directory is."""
    return _sig.signed_by_each(message, signers)


def signature_base(message: HTTPRequest | HTTPResponse, label: str, key: Ed25519Key) -> bytes:
    """The signature base of the signature ``label`` on ``message`` (RFC 9421 section 2.5).

    The signature must verify with ``key``. The conformance vectors publish
    the base, so an implementation can compare its own before it compares
    signatures. Raises :class:`WebBotAuthError` when the signature doesn't
    parse or verify.
    """
    member = parse_signature_fields(message.headers)[label]
    return _sig.verify(
        message, member, key.public_key, require_components=(), body=None
    ).signature_base


__all__ = [
    "Mode",
    "SignatureParams",
    "content_digest",
    "sign_each_unchecked",
    "sign_unchecked",
    "signature_base",
]
