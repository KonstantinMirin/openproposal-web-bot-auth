"""The scenario interpreter: signs what ``scenarios.json`` describes.

A profile message is signed by :class:`RequestSigner` or :class:`ResponseSigner`,
and a profile directory by :func:`publish_directory`. A scenario can carry
what the profile refuses (another ``alg``, a missing nonce, an uncovered
member, a directory signed for another authority). Those are signed raw:
:class:`RawSigner` signs a request or a response as a :class:`SignerConfig`
would, departing as a :class:`MessageDeparture` says, and
:func:`sign_directory_body` signs a directory as a :class:`DirectoryDeparture`
says. Both go through the private raw signer, which only this package may
import. A scenario's ``after_signing`` edits are applied to the signed
message by the edits' own ``applied_to``, which signs nothing.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal, TypeVar
from urllib.parse import urlsplit

from .._unchecked import SignatureParams, content_digest, sign_each_unchecked, sign_unchecked
from ..directory import DEFAULT_PUBLISH, build_directory, publish_directory
from ..errors import ConfigurationError
from ..keys import Ed25519Key
from ..message import HeaderLines, HTTPRequest, HTTPResponse
from ..rules import (
    ALGORITHM,
    DIRECTORY,
    REQUEST,
    RESPONSE,
    ComponentId,
    Rules,
    Stamp,
    component_id,
)
from ..signer import SignerConfig
from ..values import (
    DIRECTORY_MEDIA_TYPE,
    DIRECTORY_PATH,
    OMIT,
    KeyId,
    Omit,
    Origin,
    UnixSeconds,
    b64url_encode,
)
from .models import (
    UNSET,
    DirectoryDoc,
    DirectoryScenario,
    NonceSpec,
    RequestDoc,
    RequestScenario,
    ResponseDoc,
    ResponseScenario,
    ScenariosDocument,
    SignatureParameters,
    Unset,
    passing,
)

M = TypeVar("M", HTTPRequest, HTTPResponse)
N = TypeVar("N", str, str | None)

#: Returns ``n`` random bytes; the vector generator passes a deterministic source.
RandomBytes = Callable[[int], bytes]


def parse_component_spec(spec: str) -> ComponentId:
    """A component as ``scenarios.json`` spells it.

    ``"signature-agent;key=sig1"`` is ``"signature-agent";key="sig1"``, and
    ``"@authority;req"`` is ``"@authority";req``.
    """
    name, *params = spec.split(";")
    parsed: dict[str, str | bool] = {}
    for param in params:
        key, has_value, value = param.partition("=")
        parsed[key] = value if has_value else True
    return component_id(name, parsed)


def component_spec(component: ComponentId) -> str:
    """``component`` as ``scenarios.json`` spells it, such as ``signature-agent;key=sig1``.

    It is the inverse of :func:`parse_component_spec`.
    """
    params = "".join(f";{k}" if v is True else f";{k}={v}" for k, v in component.params)
    return component.name + params


def specs(components: Sequence[ComponentId]) -> tuple[str, ...]:
    """``components`` as ``scenarios.json`` spells them."""
    return tuple(component_spec(c) for c in components)


def components_of(
    specs: Sequence[str], label: str, request_label: str = "sig1"
) -> tuple[ComponentId, ...]:
    """The components ``specs`` name, with ``{label}`` and ``{request_label}`` filled in."""
    filled = (s.replace("{label}", label).replace("{request_label}", request_label) for s in specs)
    return tuple(parse_component_spec(s) for s in filled)


_NONCE_ENCODINGS: dict[str, Callable[[bytes], str]] = {
    "base64url": b64url_encode,
    "base64": lambda b: base64.b64encode(b).decode(),
    "base64url-padded": lambda b: base64.urlsafe_b64encode(b).decode(),
}


def nonce_value(spec: NonceSpec, random_bytes: RandomBytes = secrets.token_bytes) -> str:
    """A nonce of ``spec.bytes`` random bytes in ``spec.encoding``."""
    for _ in range(1000):
        value = _NONCE_ENCODINGS[spec.encoding](random_bytes(spec.bytes))
        # Padded base64url with no '-' or '_' is also canonical padded base64, which the
        # profile accepts.
        if spec.encoding != "base64url-padded" or "-" in value or "_" in value:
            return value
    raise RuntimeError("no base64url-padded nonce with '-' or '_'")  # pragma: no cover


#: The nonce a request signature carries when a scenario names none.
PROFILE_NONCE = NonceSpec(bytes=64, encoding="base64url")


def _text_parameter(value: str | None | Unset, profile: str) -> str | Omit:
    """A text parameter: the profile's when unset, left out when ``null``."""
    if value is UNSET:
        return profile
    return OMIT if value is None else value


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageDeparture:
    """What a raw request or response signs differently from the profile.

    ``components`` replaces the covered components, and ``parameters`` moves
    the parameters (:class:`~.models.SignatureParameters`). ``signature_agent``
    is the ``Signature-Agent`` value to add (``OMIT`` adds none), and
    ``content_digest`` the ``Content-Digest`` to add, unchecked.
    ``keep_signatures`` signs beside the signatures already on the message.
    """

    components: tuple[ComponentId, ...] | None = None
    parameters: SignatureParameters = SignatureParameters()
    signature_agent: str | Omit | None = None
    content_digest: str | None = None
    keep_signatures: bool = False


#: The profile's own message signing, departing from nothing.
PROFILE_MESSAGE = MessageDeparture()


@dataclass(frozen=True, slots=True)
class RawSigner:
    """Signs requests and responses as ``config`` would, departing as ``departure`` says.

    With :data:`PROFILE_MESSAGE` it signs what the profile's signers sign.
    ``random_bytes`` is the nonce source; the vector generator passes a
    deterministic one.
    """

    config: SignerConfig
    departure: MessageDeparture = PROFILE_MESSAGE
    random_bytes: RandomBytes = secrets.token_bytes

    def request(self, request: HTTPRequest, now: UnixSeconds) -> HTTPRequest:
        """``request`` signed at ``now``."""
        return self._signed(request, REQUEST, now)

    def response(self, response: HTTPResponse, now: UnixSeconds) -> HTTPResponse:
        """``response`` signed at ``now``, bound to its request as the departure allows."""
        return self._signed(response, RESPONSE, now)

    def _signed(self, message: M, rules: Rules[M, N], now: UnixSeconds) -> M:
        prepared = replace(message, headers=self._covered_lines(message))
        mode: Literal["append", "replace"] = (
            "append" if self.departure.keep_signatures else "replace"
        )
        params = self._params(prepared, rules, now)
        return sign_unchecked(prepared, self.config.key, params, mode=mode)

    def _covered_lines(self, message: HTTPRequest | HTTPResponse) -> HeaderLines:
        """The message's lines with the ``Content-Digest`` and ``Signature-Agent`` it signs."""
        lines, departure = message.headers, self.departure
        if message.body and "content-digest" not in lines:
            lines = lines.with_added(
                "Content-Digest", departure.content_digest or content_digest(message.body)
            )
        agent = departure.signature_agent
        if agent is None:
            agent = f'{self.config.label}="{self.config.origin.directory_url}"'
        return lines if agent is OMIT else lines.with_added("Signature-Agent", agent)

    def _nonce(self, rules: Rules[M, N]) -> str | Omit:
        value = self.departure.parameters.nonce
        if value is UNSET:
            value = PROFILE_NONCE if rules.nonce_required else None
        if isinstance(value, NonceSpec):
            return nonce_value(value, self.random_bytes)
        return OMIT if value is None else value

    def _params(self, message: M, rules: Rules[M, N], now: UnixSeconds) -> SignatureParams:
        p, config = self.departure.parameters, self.config
        created = UnixSeconds(now + (0 if p.created is UNSET else p.created))
        expires: UnixSeconds | Omit = UnixSeconds(created + config.lifetime)
        if p.expires is not UNSET:
            expires = OMIT if p.expires is None else UnixSeconds(now + p.expires)
        components = self.departure.components or rules.components_for(message, config.label)
        return SignatureParams(
            label=config.label,
            components=components,
            created=created,
            keyid=config.key.thumbprint if p.keyid is UNSET else KeyId(p.keyid),
            expires=expires,
            nonce=self._nonce(rules),
            tag=_text_parameter(p.tag, rules.tag),
            alg=_text_parameter(p.alg, ALGORITHM),
        )


def _offset(value: int | None | Unset, default: int) -> int:
    """An offset in seconds; the default when it is unset or ``null``."""
    return default if value is UNSET or value is None else value


# ── requests ───────────────────────────────────────────────────────────────


def _config(key: Ed25519Key, origin: Origin, label: str) -> SignerConfig:
    return SignerConfig(key, origin, label=label)


def sign_request_scenario(
    doc: ScenariosDocument,
    scenario: RequestScenario,
    keys: Mapping[str, Ed25519Key],
    now: UnixSeconds,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> HTTPRequest:
    """Signs one request scenario at ``now`` and returns the request as the verifier sees it."""
    label = scenario.label
    departure = MessageDeparture(
        components=components_of(scenario.components or doc.components[scenario.base], label),
        parameters=doc.parameters.merged(scenario.parameters),
        signature_agent=scenario.signature_agent,
    )
    config = _config(keys[doc.signer.kid], doc.signer.identity, label)
    signed = RawSigner(config, departure, random_bytes).request(
        doc.requests[scenario.base].message(), now
    )
    if scenario.extra_signature is not None:
        extra = scenario.extra_signature
        second = MessageDeparture(
            components=components_of(extra.components, extra.label),
            parameters=extra.parameters,
            signature_agent=OMIT,
            keep_signatures=True,
        )
        config = _config(keys[extra.kid], doc.signer.identity, extra.label)
        signed = RawSigner(config, second, random_bytes).request(signed, now)
    return signed if scenario.after_signing is None else scenario.after_signing.applied_to(signed)


def baseline_request(
    doc: ScenariosDocument,
    keys: Mapping[str, Ed25519Key],
    now: UnixSeconds,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> HTTPRequest:
    """The ``post`` request, signed as the baseline scenario."""
    baseline = RequestScenario(id="R00", name="Baseline", basis="", expected=passing())
    return sign_request_scenario(doc, baseline, keys, now, random_bytes)


# ── responses ──────────────────────────────────────────────────────────────


def sign_response_scenario(
    doc: ScenariosDocument,
    scenario: ResponseScenario,
    keys: Mapping[str, Ed25519Key],
    now: UnixSeconds,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> tuple[RequestDoc, ResponseDoc]:
    """Signs one response scenario at ``now``.

    The request is the ``post`` request, signed as the baseline unless the
    scenario's ``request`` is ``unbound``. Returns the request and the
    response as the verifier is shown them.
    """
    if scenario.request == "bound":
        request = baseline_request(doc, keys, now, random_bytes)
    else:
        request = doc.requests["post"].message()
    label = scenario.label
    departure = MessageDeparture(
        components=components_of(
            scenario.components or doc.response_components[scenario.request], label
        ),
        parameters=doc.response_parameters.merged(scenario.parameters),
    )
    config = _config(keys[doc.responder.kid], doc.responder.identity, label)
    signed = RawSigner(config, departure, random_bytes).response(doc.response.message(request), now)
    edits = scenario.after_signing
    shown = signed if edits is None else edits.applied_to(signed)
    return RequestDoc.of(shown.request), ResponseDoc.of(shown)


# ── directories ────────────────────────────────────────────────────────────


def sign_directory(keys: Sequence[Ed25519Key], root: str, now: UnixSeconds) -> DirectoryDoc:
    """The directory served under ``root``, published with ``keys`` at ``now``.

    ``root`` is an origin, which the profile publishes. A scenario can also
    list a directory under a root that isn't one, such as ``http://`` or a
    port, which only a verifier that skips the origin rule fetches; that one
    is signed for the root's own authority.
    """
    try:
        origin = Origin.parse(root)
    except ConfigurationError:
        return sign_directory_body(build_directory(keys), keys, root, now)
    return DirectoryDoc.of(origin.directory_url, publish_directory(origin, keys, now=now))


@dataclass(frozen=True, slots=True, kw_only=True)
class DirectoryDeparture:
    """What a raw directory signs differently from the profile.

    ``created`` and ``expires`` are offsets in seconds from the clock, and
    ``expires`` defaults to the profile's lifetime. ``components``, ``alg``
    (``OMIT`` leaves it out), ``content_type``, and ``content_digest`` (sent
    as given, unchecked) replace the profile's. ``authority`` signs for
    another ``"@authority"`` than the origin's own.
    """

    components: tuple[ComponentId, ...] | None = None
    created: int = 0
    expires: int = DEFAULT_PUBLISH.lifetime
    alg: str | Omit = ALGORITHM
    content_type: str = DIRECTORY_MEDIA_TYPE
    content_digest: str | None = None
    authority: str | None = None

    def _params(self, i: int, key: Ed25519Key, now: UnixSeconds) -> SignatureParams:
        """What key number ``i`` signs, as the profile would with this departure."""
        created, expires = UnixSeconds(now + self.created), UnixSeconds(now + self.expires)
        params = DIRECTORY.params(Stamp(f"key{i}", key.thumbprint, created, expires))
        components = params.components if self.components is None else self.components
        return replace(params, components=components, alg=self.alg)


#: The profile's own directory signing, departing from nothing.
PROFILE_DIRECTORY = DirectoryDeparture()


def sign_directory_body(
    body: bytes,
    keys: Sequence[Ed25519Key],
    root: Origin | str,
    now: UnixSeconds,
    departure: DirectoryDeparture = PROFILE_DIRECTORY,
) -> DirectoryDoc:
    """``body`` served under ``root``, signed by each of ``keys`` as ``departure`` says.

    ``root`` is an origin, or a URL root such as ``https://host:8443``.

    ``body`` is any bytes, so a test can sign a JWK Set the keys don't match.
    This is the raw directory signer: :func:`~..directory.publish_directory`
    is the profile's.
    """
    lines = HeaderLines(
        [
            ("Content-Type", departure.content_type),
            ("Cache-Control", f"max-age={DEFAULT_PUBLISH.max_age}"),
            ("Content-Digest", departure.content_digest or content_digest(body)),
        ]
    )
    url = f"{root}{DIRECTORY_PATH}"
    authority = departure.authority or urlsplit(url).netloc
    request = HTTPRequest("GET", f"https://{authority}{DIRECTORY_PATH}")
    unsigned = HTTPResponse(200, lines, b"", request)
    signers = [(key, departure._params(i, key, now)) for i, key in enumerate(keys, start=1)]
    signed = sign_each_unchecked(unsigned, signers)
    return DirectoryDoc(url=url, status=200, headers=signed.headers, body=body)


def _departure(scenario: DirectoryScenario) -> DirectoryDeparture:
    parameters = scenario.parameters or SignatureParameters()
    return DirectoryDeparture(
        components=None if scenario.components is None else components_of(scenario.components, ""),
        created=_offset(parameters.created, 0),
        expires=_offset(parameters.expires, DEFAULT_PUBLISH.lifetime),
        content_type=scenario.content_type or DIRECTORY_MEDIA_TYPE,
        authority=scenario.authority,
    )


def sign_directory_scenario(
    doc: ScenariosDocument,
    scenario: DirectoryScenario,
    keys: Mapping[str, Ed25519Key],
    now: UnixSeconds,
) -> DirectoryDoc:
    """Signs one directory scenario at ``now``, as the signer's directory."""
    kids = (doc.signer.kid,) if scenario.keys is None else scenario.keys
    signing = [keys[kid] for kid in kids]
    body = build_directory([*signing, *(scenario.unsigned_keys or ())])
    signed = sign_directory_body(body, signing, doc.signer.identity, now, _departure(scenario))
    edits = scenario.after_signing
    return signed if edits is None else replace(signed, body=edits.applied_to(signed.body))


__all__ = [
    "PROFILE_DIRECTORY",
    "PROFILE_MESSAGE",
    "PROFILE_NONCE",
    "DirectoryDeparture",
    "MessageDeparture",
    "RandomBytes",
    "RawSigner",
    "baseline_request",
    "component_spec",
    "components_of",
    "nonce_value",
    "parse_component_spec",
    "sign_directory",
    "sign_directory_body",
    "sign_directory_scenario",
    "sign_request_scenario",
    "sign_response_scenario",
    "specs",
]
