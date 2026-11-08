"""The profile's rules, stated once (OpenProposal § 2.8.2 and § 2.8.3).

Each kind of signature has one rules object: :data:`REQUEST`,
:data:`RESPONSE`, and :data:`DIRECTORY`. Its facts are class constants: the
``tag``, the time window, and whether the signature carries a nonce. Its
:meth:`~Rules.components_for` names the components a signature on a given
message covers. The signers sign exactly those, and the verifiers require
exactly those, so a signer can't emit what a verifier refuses. The rules
classes are private: these three objects are the only rules there are, and
:class:`Rules` types a role by the message it takes, so a request can't be
signed under the response rules.

:data:`CACHE` states how long a verifier keeps a directory (OpenProposal §
2.8.3).
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Final

from ._sig import SignatureParams
from ._wire import ComponentId, ComponentParam, component_id, parse_signature_fields
from .errors import Refusal, WebBotAuthError, refuse
from .message import HeaderLines, Headers, HTTPRequest, HTTPResponse
from .values import OMIT, KeyId, Seconds, UnixSeconds, b64url_encode, whole_number

#: The ``tag`` of a request or response signature under the profile.
SIGNATURE_TAG: Final = "web-bot-auth"
#: The ``tag`` of a key directory response signature.
DIRECTORY_TAG: Final = "http-message-signatures-directory"
#: The one signature algorithm the profile uses.
ALGORITHM: Final = "ed25519"
#: The longest signature lifetime, ``expires - created``, in seconds.
MAX_LIFETIME: Final = 300
#: The clock skew a verifier allows, in seconds.
CLOCK_SKEW: Final = 60
#: The nonce length in bytes.
NONCE_BYTES: Final = 64
#: What the nonce rule requires, as a signer and a verifier say it.
NONCE_RULE: Final = "nonce must be 64 bytes as unpadded base64url or padded base64"
#: Media types whose responses stream: a server passes them through unsigned, so a
#: client takes one unsigned.
STREAMING_MEDIA_TYPES: Final = ("text/event-stream",)
#: The key ids of the published test keys, whose private keys ship in the
#: conformance vectors (``vectors/keys.json``). Web Bot Auth section 6.8 says
#: they "MUST NOT be used in production": a verifier always refuses them, unless
#: a conformance run makes it with ``verifier.CONFORMANCE_KEYS``.
TEST_KEY_IDS: Final = frozenset(
    {
        KeyId("T5rd7MzhvzHtrBDE04NVTnFpBFb63tjmy9o0JrtFH84"),
        KeyId("VR0Gby4SzMlU2nttpc8Ondksz1_VWMBzuycc-DzuQHc"),
        KeyId("-Rmj_GuEunGbO4x6GQSMCCi0P6oZ32paBkWMnvo3gDU"),
    }
)


def validate_nonce(nonce: object) -> bool:
    """True for 64 bytes as unpadded base64url or canonical padded base64.

    These are the two forms the Web Bot Auth drafts use, and the two that
    Cloudflare's ``validateNonce`` accepts.
    """
    if not isinstance(nonce, str) or not nonce.isascii():
        return False
    normalized = nonce.replace("-", "+").replace("_", "/")
    if len(normalized) % 4 == 1:
        return False
    try:
        decoded = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
    except ValueError:
        return False
    if len(decoded) != NONCE_BYTES:
        return False
    return base64.b64encode(decoded).decode() == nonce or b64url_encode(decoded) == nonce


@dataclass(frozen=True, slots=True)
class Window:
    """When a signature is valid: its ``created`` and ``expires`` against a clock.

    ``max_lifetime`` caps ``expires - created`` (``None``: no cap). ``skew``
    is allowed on ``created``, and on ``expires`` too when ``skew_on_expires``.
    ``refusal``, when set, is the one refusal every window failure raises;
    otherwise each rule raises its own.
    """

    max_lifetime: int | None
    skew: int
    skew_on_expires: bool
    refusal: Refusal | None = None

    def check(
        self, created: UnixSeconds | None, expires: UnixSeconds | None, now: UnixSeconds
    ) -> UnixSeconds:
        """Refuses a window that doesn't hold at ``now``; returns ``expires``."""
        if created is None or expires is None:
            raise self._refuse(Refusal.WINDOW, "created and expires are required Integers")
        if created > expires:
            raise self._refuse(Refusal.WINDOW, "created is after expires")
        if self.max_lifetime is not None and expires - created > self.max_lifetime:
            raise self._refuse(
                Refusal.LIFETIME, f"expires is more than {self.max_lifetime} s after created"
            )
        if created > now + self.skew:
            raise self._refuse(Refusal.CREATED_IN_FUTURE, "created is in the future")
        if expires < now - (self.skew if self.skew_on_expires else 0):
            raise self._refuse(Refusal.EXPIRED, "the signature has expired")
        return expires

    def checked_lifetime(self, lifetime: object) -> Seconds:
        """``lifetime`` when a signer may sign it: whole seconds, from 1 to ``max_lifetime``.

        This is the one lifetime check every signer's configuration runs.
        Raises :class:`ConfigurationError` for anything else.
        """
        checked = whole_number("lifetime", lifetime, minimum=1, maximum=self.max_lifetime)
        return Seconds(checked)

    def _refuse(self, refusal: Refusal, detail: str) -> WebBotAuthError:
        return refuse(self.refusal or refusal, detail)


#: The window of a request or response signature.
MESSAGE_WINDOW: Final = Window(max_lifetime=MAX_LIFETIME, skew=CLOCK_SKEW, skew_on_expires=True)


#: The component that covers the body, through its digest.
CONTENT_DIGEST: Final = component_id("content-digest")


def _body_components(has_body: bool) -> tuple[ComponentId, ...]:
    return (component_id("content-type"), CONTENT_DIGEST) if has_body else ()


def signature_agent_component(label: str) -> ComponentId:
    """The component that covers the ``Signature-Agent`` member ``label``."""
    return component_id("signature-agent", {"key": label})


@dataclass(frozen=True, slots=True)
class Stamp:
    """Who signs one signature and when: its label, its key id, and its window."""

    label: str
    keyid: KeyId
    created: UnixSeconds
    expires: UnixSeconds


def _checked_nonce(nonce: str | None) -> str | None:
    if nonce is not None and not validate_nonce(nonce):
        raise refuse(Refusal.NONCE_INVALID, NONCE_RULE)
    return nonce


class Rules[M: (HTTPRequest, HTTPResponse), N: (str, str | None)](ABC):
    """The rules of a signature on a message of type ``M``, whose nonce is an ``N``:
    a ``str`` on a request, and ``str | None`` on a response.

    ``tag``, ``window``, and ``nonce_required`` are class constants.
    """

    tag: ClassVar[str] = SIGNATURE_TAG
    window: ClassVar[Window] = MESSAGE_WINDOW
    nonce_required: ClassVar[bool]

    @abstractmethod
    def components_for(self, message: M, label: str) -> tuple[ComponentId, ...]:
        """The components the signature ``label`` on ``message`` covers, in signing order."""

    @abstractmethod
    def nonce_of(self, nonce: str | None) -> N:
        """The signed ``nonce`` under the nonce rule; refuses one the rule doesn't allow."""

    def missing(self, component: ComponentId) -> Refusal:
        """The refusal for a signature that doesn't cover ``component``."""
        return Refusal.COMPONENTS

    def params_for(self, message: M, stamp: Stamp, nonce: N) -> SignatureParams:
        """What the profile signs as the signature ``stamp.label`` on ``message``."""
        return SignatureParams(
            label=stamp.label,
            components=self.components_for(message, stamp.label),
            created=stamp.created,
            keyid=stamp.keyid,
            expires=stamp.expires,
            nonce=OMIT if nonce is None else nonce,
            tag=self.tag,
            alg=ALGORITHM,
        )


class _RequestRules(Rules[HTTPRequest, str]):
    """A request signature: ``@method``, ``@target-uri``, ``@authority``, the body
    fields when there is a body, and its ``Signature-Agent`` member, with a nonce."""

    nonce_required: ClassVar[bool] = True

    def nonce_of(self, nonce: str | None) -> str:
        """The nonce, which every signed request carries in one of the two forms."""
        checked = _checked_nonce(nonce)
        if checked is None:
            raise refuse(Refusal.NONCE_MISSING, "a nonce is required on every signed request")
        return checked

    def components(self, label: str, *, has_body: bool) -> tuple[ComponentId, ...]:
        """The components the signature ``label`` covers, in signing order."""
        derived = (
            component_id("@method"),
            component_id("@target-uri"),
            component_id("@authority"),
        )
        return (*derived, *_body_components(has_body), signature_agent_component(label))

    def components_for(self, message: HTTPRequest, label: str) -> tuple[ComponentId, ...]:
        return self.components(label, has_body=bool(message.body))


class _ResponseRules(Rules[HTTPResponse, str | None]):
    """A response signature: ``@status``, the request's ``@method`` and
    ``@target-uri``, the body fields when there is a body, its
    ``Signature-Agent`` member, and the binding to a signed request. No nonce:
    the binding gives freshness."""

    nonce_required: ClassVar[bool] = False

    def nonce_of(self, nonce: str | None) -> str | None:
        """No nonce, or one in one of the two forms."""
        return _checked_nonce(nonce)

    def binding(self, request_label: str) -> ComponentId:
        """The component that binds a response to the request signature ``request_label``."""
        return component_id("signature", {"req": True, "key": request_label})

    def components(
        self, label: str, *, has_body: bool, request_label: str | None = None
    ) -> tuple[ComponentId, ...]:
        """The components the signature ``label`` covers, in signing order.

        ``request_label`` is the label of the request's ``web-bot-auth``
        signature, when it carried one.
        """
        derived = (
            component_id("@status"),
            component_id("@method", {"req": True}),
            component_id("@target-uri", {"req": True}),
        )
        bound = () if request_label is None else (self.binding(request_label),)
        return (*derived, *_body_components(has_body), signature_agent_component(label), *bound)

    def components_for(self, message: HTTPResponse, label: str) -> tuple[ComponentId, ...]:
        """The components, bound to ``message.request``'s signature when it has one."""
        request_label = web_bot_auth_label(message.request.headers)
        return self.components(label, has_body=bool(message.body), request_label=request_label)

    def missing(self, component: ComponentId) -> Refusal:
        """``response-not-bound`` for the binding, ``components`` for anything else."""
        is_binding = component.name == "signature" and ("req", True) in component.params
        return Refusal.RESPONSE_NOT_BOUND if is_binding else Refusal.COMPONENTS


class _DirectoryRules:
    """A directory signature: ``"@authority";req`` and ``content-digest``, with
    no nonce. Its window has no lifetime cap and no skew on ``expires``, and
    every window failure is ``directory-window``."""

    tag: ClassVar[str] = DIRECTORY_TAG
    window: ClassVar[Window] = Window(
        max_lifetime=None,
        skew=CLOCK_SKEW,
        skew_on_expires=False,
        refusal=Refusal.DIRECTORY_WINDOW,
    )

    def components(self) -> tuple[ComponentId, ...]:
        """The components every directory signature covers."""
        return (component_id("@authority", {"req": True}), CONTENT_DIGEST)

    def params(self, stamp: Stamp) -> SignatureParams:
        """What the directory signature ``stamp.label`` signs."""
        return SignatureParams(
            label=stamp.label,
            components=self.components(),
            created=stamp.created,
            keyid=stamp.keyid,
            expires=stamp.expires,
            tag=self.tag,
            alg=ALGORITHM,
        )


#: The rules of a request signature.
REQUEST: Final = _RequestRules()
#: The rules of a response signature.
RESPONSE: Final = _ResponseRules()
#: The rules of a key directory response signature.
DIRECTORY: Final = _DirectoryRules()


@dataclass(frozen=True, slots=True)
class CacheRules:
    """How long a verifier keeps a directory (OpenProposal § 2.8.3).

    A fetched directory answers without a fetch for ``fresh_for`` seconds,
    and after a failed fetch the origin isn't fetched again for
    ``retry_after_failure`` seconds.
    """

    fresh_for: Seconds = Seconds(300)
    retry_after_failure: Seconds = Seconds(60)


#: The profile's cache rules.
CACHE: Final = CacheRules()


def web_bot_auth_label(headers: Headers | None) -> str | None:
    """Returns the label of the one complete ``web-bot-auth`` signature on a message, or ``None``.

    The signature is complete when ``Signature-Input`` has the one member tagged
    ``web-bot-auth`` and ``Signature`` has a Byte Sequence under the same label.
    Returns ``None`` when a signature field is absent or doesn't parse, when
    there is no such member, and when there is more than one. A response binds
    to the request's signature only when this returns a label.
    """
    try:
        fields = parse_signature_fields(HeaderLines(headers))
        return None if fields is None else fields.one_tagged(SIGNATURE_TAG).label
    except WebBotAuthError:
        return None


def accept_signature(label: str = "sig1", *, has_body: bool = True) -> str:
    """An ``Accept-Signature`` value naming what a request signature covers (RFC 9421 § 5.1)."""
    inner = " ".join(str(c) for c in REQUEST.components(label, has_body=has_body))
    nonce = ";nonce" if REQUEST.nonce_required else ""
    return f'{label}=({inner});created;expires{nonce};keyid;alg="{ALGORITHM}";tag="{REQUEST.tag}"'


__all__ = [
    "ALGORITHM",
    "CACHE",
    "CLOCK_SKEW",
    "CONTENT_DIGEST",
    "DIRECTORY",
    "DIRECTORY_TAG",
    "MAX_LIFETIME",
    "MESSAGE_WINDOW",
    "NONCE_BYTES",
    "NONCE_RULE",
    "REQUEST",
    "RESPONSE",
    "SIGNATURE_TAG",
    "STREAMING_MEDIA_TYPES",
    "TEST_KEY_IDS",
    "CacheRules",
    "ComponentId",
    "ComponentParam",
    "Rules",
    "SignatureParams",
    "Stamp",
    "Window",
    "accept_signature",
    "component_id",
    "signature_agent_component",
    "validate_nonce",
    "web_bot_auth_label",
]
