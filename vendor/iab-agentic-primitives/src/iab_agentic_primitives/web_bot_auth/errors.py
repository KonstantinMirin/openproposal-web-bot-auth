"""The refusal vocabulary, and the errors the module raises.

Every refusal a verifier sends is a member of :class:`Refusal`. A member
carries its reason code, its HTTP status, and how it is presented: ``403`` and
``429`` carry ``Accept-Signature``, and ``503`` carries ``Retry-After``. A
status outside ``{400, 403, 429, 503}`` can't be expressed.

:class:`WebBotAuthError` is a refusal on the wire. :class:`ConfigurationError`
is a deploy-time mistake, such as a malformed origin, and is never sent.
:class:`SigningError` is a message a signer refuses to sign.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Literal

#: The statuses a verifier answers with.
Status = Literal[400, 403, 429, 503]

#: The ``Retry-After`` a ``503`` refusal carries, in seconds.
RETRY_AFTER = 1


@dataclass(frozen=True)
class _Rule:
    code: str
    status: Status


class Refusal(enum.Enum):
    """Why a message is refused, with the status the refusal answers."""

    # 400: a signature field doesn't parse.
    PARSE = _Rule("parse", 400)

    # 403: the signature and its Signature-Agent member.
    SIGNATURE_MISSING = _Rule("signature-missing", 403)
    MULTIPLE_SIGNATURES = _Rule("multiple-signatures", 403)
    SIGNATURE_AGENT_MISSING = _Rule("signature-agent-missing", 403)
    MULTIPLE_SIGNATURE_AGENTS = _Rule("multiple-signature-agents", 403)
    SIGNATURE_AGENT_PARAMETERS = _Rule("signature-agent-parameters", 403)
    SIGNATURE_AGENT_NOT_COVERED = _Rule("signature-agent-not-covered", 403)
    SIGNATURE_AGENT_VALUE = _Rule("signature-agent-value", 403)

    # 403: the signature parameters and covered components.
    KEYID = _Rule("keyid", 403)
    ALG = _Rule("alg", 403)
    WINDOW = _Rule("window", 403)
    LIFETIME = _Rule("lifetime", 403)
    CREATED_IN_FUTURE = _Rule("created-in-future", 403)
    EXPIRED = _Rule("expired", 403)
    NONCE_MISSING = _Rule("nonce-missing", 403)
    NONCE_INVALID = _Rule("nonce-invalid", 403)
    COMPONENTS = _Rule("components", 403)
    CONTENT_DIGEST = _Rule("content-digest", 403)
    AUTHORITY = _Rule("authority", 403)

    # 403: the key and the signature itself.
    REJECTED_KEY = _Rule("rejected-key", 403)
    KEY_NOT_FOUND = _Rule("key-not-found", 403)
    SIGNATURE_INVALID = _Rule("signature-invalid", 403)

    # 403: a response and the request it answers.
    RESPONSE_NOT_BOUND = _Rule("response-not-bound", 403)
    ORIGIN_MISMATCH = _Rule("origin-mismatch", 403)

    # 403: the signed key directory and its fetch.
    DIRECTORY_UNAVAILABLE = _Rule("directory-unavailable", 403)
    DIRECTORY_STATUS = _Rule("directory-status", 403)
    DIRECTORY_ENCODING = _Rule("directory-encoding", 403)
    DIRECTORY_MEDIA_TYPE = _Rule("directory-media-type", 403)
    DIRECTORY_TOO_LARGE = _Rule("directory-too-large", 403)
    DIRECTORY_CONTENT_DIGEST = _Rule("directory-content-digest", 403)
    DIRECTORY_FORMAT = _Rule("directory-format", 403)
    DIRECTORY_TOO_MANY_KEYS = _Rule("directory-too-many-keys", 403)
    DIRECTORY_KID = _Rule("directory-kid", 403)
    DIRECTORY_NO_USABLE_KEY = _Rule("directory-no-usable-key", 403)
    DIRECTORY_SIGNATURE_PARSE = _Rule("directory-signature-parse", 403)
    DIRECTORY_ONE_SIGNATURE_PER_KEY = _Rule("directory-one-signature-per-key", 403)
    DIRECTORY_TAG = _Rule("directory-tag", 403)
    DIRECTORY_COMPONENTS = _Rule("directory-components", 403)
    DIRECTORY_WINDOW = _Rule("directory-window", 403)
    DIRECTORY_SIGNATURE = _Rule("directory-signature", 403)

    # 429: the nonce was seen before for this origin.
    NONCE_REPLAYED = _Rule("nonce-replayed", 429)

    # 503: the verifier can't record the nonce now.
    NONCE_STORE_UNAVAILABLE = _Rule("nonce-store-unavailable", 503)

    @classmethod
    def of(cls, code: str) -> Refusal:
        """The refusal whose reason code is ``code``; ``ValueError`` for an unknown code."""
        for refusal in cls:
            if refusal.code == code:
                return refusal
        raise ValueError(f"{code!r} is not a refusal reason")

    @property
    def code(self) -> str:
        """The machine-readable reason, such as ``"nonce-missing"``."""
        return self.value.code

    @property
    def status(self) -> Status:
        """The HTTP status the refusal answers."""
        return self.value.status

    @property
    def accept_signature(self) -> bool:
        """True when the refusal carries ``Accept-Signature``: on ``403`` and ``429``."""
        return self.status in (403, 429)

    @property
    def retry_after(self) -> int | None:
        """The ``Retry-After`` value in seconds, on ``503`` only."""
        return RETRY_AFTER if self.status == 503 else None


class WebBotAuthError(Exception):
    """A refusal under the profile.

    ``refusal`` says why. ``status`` and ``reason`` are its HTTP status and
    reason code, and ``str(error)`` is the detail for logs. A refusal that
    isn't a :class:`Refusal` member raises ``TypeError``. The error pickles and
    copies, so it crosses a process pool intact.
    """

    def __init__(self, refusal: Refusal, detail: str) -> None:
        if not isinstance(refusal, Refusal):
            raise TypeError(f"a refusal is a Refusal member, not {refusal!r}")
        super().__init__(refusal, detail)
        self.refusal = refusal
        self.detail = detail

    def __str__(self) -> str:
        return self.detail

    @property
    def status(self) -> Status:
        return self.refusal.status

    @property
    def reason(self) -> str:
        return self.refusal.code

    def __repr__(self) -> str:
        return f"WebBotAuthError({self.refusal}, {str(self)!r})"


class ConfigurationError(ValueError):
    """A deploy-time misconfiguration, such as a malformed origin or lifetime.

    It is raised when a value, policy, signer, verifier, resolver, store, or
    middleware is built, or used outside its contract, and is never sent on
    the wire.
    """


class SigningError(ValueError):
    """A message the profile can't sign, such as a body without ``Content-Type``
    or a request whose URL isn't absolute.

    The signers raise it, and only it, for a message they refuse; a library
    error during signing is translated to it.
    """


def refuse(refusal: Refusal, detail: str) -> WebBotAuthError:
    """Returns the refusal ``refusal`` with ``detail``, for the caller to raise."""
    return WebBotAuthError(refusal, detail)


__all__ = [
    "RETRY_AFTER",
    "ConfigurationError",
    "Refusal",
    "SigningError",
    "Status",
    "WebBotAuthError",
]
