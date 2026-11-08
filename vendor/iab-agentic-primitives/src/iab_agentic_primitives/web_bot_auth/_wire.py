"""The Structured Fields and Content-Digest seam, from http-sf and http-message-signatures.

The profile modules read ``Signature-Input``, ``Signature``, ``Signature-Agent``,
and ``Content-Digest`` only through this module, and get typed values back:

- :func:`is_signed` is the one test of whether a message is signed: it carries
  ``Signature-Input``, so the profile's verification steps apply to it.
- :func:`parse_signature_fields` parses the three signature fields of a signed
  message once, under one duplicate-key policy, into :class:`SignatureFields`.
- :func:`check_content_digest` checks a ``Content-Digest`` against the body.
- :class:`ComponentId` is a covered component identifier.

Only ``http_sf.StructuredFieldError`` and the library's digest error are
caught; anything else is a bug and propagates.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

import http_sf
from http_message_signatures import ContentDigest
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from http_sf.types import ParamsType

from .errors import Refusal, refuse
from .message import HeaderLines
from .values import KeyId, UnixSeconds

#: A component parameter value: ``req``, ``sf``, and ``bs`` are Booleans, and
#: ``key`` and ``name`` are Strings (RFC 9421 section 2.1).
ComponentParam = str | bool


@dataclass(frozen=True, slots=True, eq=False)
class ComponentId:
    """A covered component identifier, such as ``"signature-agent";key="sig1"``.

    ``params`` keeps the order the identifier was written in, which
    ``str(component)`` serializes. Two identifiers are equal when their names
    and parameters are, in any order (RFC 9421 section 2).
    """

    name: str
    params: tuple[tuple[str, ComponentParam], ...] = ()

    def _identity(self) -> tuple[str, frozenset[tuple[str, ComponentParam]]]:
        return self.name, frozenset(self.params)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ComponentId) and self._identity() == other._identity()

    def __hash__(self) -> int:
        return hash(self._identity())

    def __str__(self) -> str:
        params: ParamsType = dict(self.params)
        return http_sf.ser((self.name, params))


def component_id(name: str, params: Mapping[str, ComponentParam] | None = None) -> ComponentId:
    """The component identifier ``name`` with ``params``, in the order given."""
    return ComponentId(name, tuple((params or {}).items()))


@dataclass(frozen=True, slots=True)
class SignatureMember:
    """One ``Signature-Input`` member: its label, covered components, and parameters.

    A parameter the member doesn't carry is ``None``. The parser checks each
    parameter's type (RFC 9421 section 2.3); which parameters are required
    is the profile's rule, not the parser's.
    """

    label: str
    components: tuple[ComponentId, ...]
    created: UnixSeconds | None
    expires: UnixSeconds | None
    keyid: KeyId | None
    alg: str | None
    nonce: str | None
    tag: str | None


@dataclass(frozen=True, slots=True)
class SignatureAgentMember:
    """One ``Signature-Agent`` member. ``value`` is ``None`` when it isn't a String."""

    label: str
    value: str | None
    has_parameters: bool


class SignatureFields(Mapping[str, SignatureMember]):
    """The parsed signature fields of one message: an immutable mapping from label
    to :class:`SignatureMember`, in ``Signature-Input`` order.

    ``signatures`` maps each ``Signature`` label to its Byte Sequence, and
    ``agents`` maps each ``Signature-Agent`` label to its member. A label
    repeated in a field parses, and RFC 9651 keeps its last value:
    ``repeated`` holds the labels repeated in ``Signature-Input`` or
    ``Signature``, and ``repeated_agents`` those repeated in
    ``Signature-Agent``. Only a repeat of the member a verifier selects makes
    that member ambiguous, so the selection refuses it, not the parse.
    """

    __slots__ = ("_members", "agents", "repeated", "repeated_agents", "signatures")

    def __init__(
        self,
        members: Mapping[str, SignatureMember],
        signatures: Mapping[str, bytes],
        agents: Mapping[str, SignatureAgentMember],
        *,
        repeated: frozenset[str] = frozenset(),
        repeated_agents: frozenset[str] = frozenset(),
    ) -> None:
        self._members = MappingProxyType(dict(members))
        self.signatures: Mapping[str, bytes] = MappingProxyType(dict(signatures))
        self.agents: Mapping[str, SignatureAgentMember] = MappingProxyType(dict(agents))
        self.repeated = repeated
        self.repeated_agents = repeated_agents

    def __getitem__(self, label: str) -> SignatureMember:
        return self._members[label]

    def __iter__(self) -> Iterator[str]:
        return iter(self._members)

    def __len__(self) -> int:
        return len(self._members)

    def one_tagged(self, tag: str) -> SignatureMember:
        """The one member tagged ``tag``, which has a ``Signature`` member too.

        This is the one selection of a signature by its tag. Refuses
        ``signature-missing`` when there is no such member or its
        ``Signature`` member is absent, and ``multiple-signatures`` when there
        is more than one or its label is repeated. A repeated label on any
        other member is not this member's concern.
        """
        tagged = [m for m in self._members.values() if m.tag == tag]
        if not tagged:
            raise refuse(Refusal.SIGNATURE_MISSING, f"the message carries no {tag} signature")
        if len(tagged) > 1:
            raise refuse(
                Refusal.MULTIPLE_SIGNATURES,
                f"{len(tagged)} {tag} signatures; the profile takes one",
            )
        label = tagged[0].label
        if label in self.repeated:
            raise refuse(Refusal.MULTIPLE_SIGNATURES, f"signature member {label} is repeated")
        if label not in self.signatures:
            raise refuse(Refusal.SIGNATURE_MISSING, f"Signature has no member {label}")
        return tagged[0]


# ── parsing ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Dictionary:
    members: Mapping[str, object]
    repeated: tuple[str, ...]


def _parse_dictionary(value: str) -> _Dictionary:
    """Parses a Structured Field Dictionary.

    A repeated parameter is a parse failure. A repeated dictionary key is not:
    RFC 9651 keeps the last value, and the key is reported in ``repeated`` so
    the caller can refuse it under its own rule. Raises ``StructuredFieldError``.
    """
    repeated: list[str] = []

    def on_duplicate(key: str, context: str) -> None:
        if context != "dictionary":
            raise http_sf.StructuredFieldError(f"duplicate {context} key {key!r}")
        repeated.append(key)

    try:
        data = value.encode("ascii")
    except UnicodeEncodeError as e:
        raise http_sf.StructuredFieldError("the field is not ASCII") from e
    parsed = http_sf.parse(data, tltype="dictionary", on_duplicate_key=on_duplicate)
    if not isinstance(parsed, dict):  # pragma: no cover - tltype="dictionary" returns a dict
        raise http_sf.StructuredFieldError("the field is not a Dictionary")
    return _Dictionary(parsed, tuple(repeated))


def _field(lines: HeaderLines, name: str) -> _Dictionary:
    value = lines.get(name)
    if value is None:
        return _Dictionary({}, ())
    try:
        return _parse_dictionary(value)
    except http_sf.StructuredFieldError as e:
        raise refuse(Refusal.PARSE, f"{name} does not parse: {e}") from e


def _split(member: object) -> tuple[object, Mapping[str, object]]:
    """A parsed member's value and parameters."""
    if isinstance(member, tuple) and len(member) == 2 and isinstance(member[1], dict):
        return member[0], member[1]
    return member, {}


def _component(label: str, item: object) -> ComponentId:
    name, params = _split(item)
    if not isinstance(name, str):
        raise refuse(Refusal.PARSE, f"Signature-Input member {label} covers a non-String {name!r}")
    checked: list[tuple[str, ComponentParam]] = []
    for key, value in params.items():
        if not isinstance(value, (str, bool)):
            raise refuse(
                Refusal.PARSE,
                f"Signature-Input member {label}: component parameter {key} is {value!r}",
            )
        checked.append((key, value))
    return ComponentId(name, tuple(checked))


def _instant(label: str, params: Mapping[str, object], name: str) -> UnixSeconds | None:
    value = params.get(name)
    if value is None:
        return None
    if type(value) is not int:
        raise refuse(Refusal.PARSE, f"Signature-Input member {label}: {name} is not an Integer")
    return UnixSeconds(value)


def _string(label: str, params: Mapping[str, object], name: str) -> str | None:
    value = params.get(name)
    if value is not None and not isinstance(value, str):
        raise refuse(Refusal.PARSE, f"Signature-Input member {label}: {name} is not a String")
    return value


def _signature_member(label: str, member: object) -> SignatureMember:
    items, params = _split(member)
    # Every member's shape is checked whatever its tag (RFC 9421 sections 4.1 and 4.2).
    if not isinstance(items, list):
        raise refuse(Refusal.PARSE, f"Signature-Input member {label} is not an Inner List")
    keyid = _string(label, params, "keyid")
    return SignatureMember(
        label=label,
        components=tuple(_component(label, item) for item in items),
        created=_instant(label, params, "created"),
        expires=_instant(label, params, "expires"),
        keyid=None if keyid is None else KeyId(keyid),
        alg=_string(label, params, "alg"),
        nonce=_string(label, params, "nonce"),
        tag=_string(label, params, "tag"),
    )


def _signature(label: str, member: object) -> bytes:
    value, _ = _split(member)
    if not isinstance(value, bytes):
        raise refuse(Refusal.PARSE, f"Signature member {label} is not a Byte Sequence")
    return value


def _agent(label: str, member: object) -> SignatureAgentMember:
    value, params = _split(member)
    return SignatureAgentMember(label, value if isinstance(value, str) else None, bool(params))


def is_signed(lines: HeaderLines) -> bool:
    """True when the message carries ``Signature-Input``: the one test of whether it is signed.

    The profile's verification steps apply to a message that carries
    ``Signature-Input`` and to no other. A message with only a ``Signature``
    field, such as one from another signature scheme, is unsigned under the
    profile, and its ``Signature`` is never parsed.
    """
    return "signature-input" in lines


def parse_signature_fields(lines: HeaderLines) -> SignatureFields | None:
    """Parses ``Signature-Input``, ``Signature``, and ``Signature-Agent`` once.

    Returns ``None`` for a message that isn't signed (:func:`is_signed`), and
    parses nothing. A signed message gets the profile's step 1: every member's
    shape is checked, whatever its tag, and a failure refuses ``parse``
    (``400``): a field that doesn't parse as a Dictionary, a repeated
    parameter, a ``Signature-Input`` member that isn't an Inner List of
    Strings with parameters of their RFC 9421 types, or a ``Signature``
    member that isn't a Byte Sequence. The parse refuses nothing else: a
    repeated label is carried on the result for the selection to judge.
    """
    if not is_signed(lines):
        return None
    inputs = _field(lines, "signature-input")
    signatures = _field(lines, "signature")
    agents = _field(lines, "signature-agent")
    return SignatureFields(
        {label: _signature_member(label, m) for label, m in inputs.members.items()},
        {label: _signature(label, m) for label, m in signatures.members.items()},
        {label: _agent(label, m) for label, m in agents.members.items()},
        repeated=frozenset((*inputs.repeated, *signatures.repeated)),
        repeated_agents=frozenset(agents.repeated),
    )


def only_member(lines: HeaderLines, label: str) -> HeaderLines:
    """``lines`` with ``Signature-Input`` and ``Signature`` holding the member ``label`` alone.

    A signature is verified from its own member (RFC 9421 section 3.2), and the
    profile verifies no member with another tag. Left in, another signer's
    member could fail the library's own parse, as a repeated label or a label
    with no ``Signature`` member does, and refuse a valid signature. The
    member is serialized again from its parse; the library serializes it
    again for the signature base anyway. Lines with no other member are
    returned as they are. Raises ``ValueError`` when the fields don't parse
    or lack the member.
    """
    try:
        inputs = _parse_dictionary(lines["signature-input"])
        signatures = _parse_dictionary(lines["signature"])
    except (KeyError, http_sf.StructuredFieldError) as e:
        raise ValueError(f"the signature fields lack a member {label}: {e}") from e
    alone = (label,)
    if (tuple(inputs.members), tuple(signatures.members)) == (alone, alone) and not (
        inputs.repeated or signatures.repeated
    ):
        return lines
    if label not in inputs.members or label not in signatures.members:
        raise ValueError(f"the signature fields lack a member {label}")

    def member(field: _Dictionary) -> str:
        return http_sf.ser({label: field.members[label]})  # type: ignore[dict-item]

    return lines.with_replaced("Signature-Input", member(inputs)).with_replaced(
        "Signature", member(signatures)
    )


def signature_values(lines: HeaderLines) -> tuple[str, str]:
    """The ``Signature-Input`` and ``Signature`` values as serialized, unparsed.

    Raises ``ValueError`` when either is absent.
    """
    signature_input, signature = lines.get("signature-input"), lines.get("signature")
    if signature_input is None or signature is None:
        raise ValueError("the message carries no Signature-Input and Signature pair")
    return signature_input, signature


# ── Content-Digest ────────────────────────────────────────────────────────


class ContentDigestError(ValueError):
    """A ``Content-Digest`` that is absent, malformed, or doesn't match the body.

    Each caller maps it to its own refusal or :class:`SigningError`.
    """


def content_digest(body: bytes) -> str:
    """Returns the ``Content-Digest`` value for ``body`` (RFC 9530, ``sha-256``)."""
    return ContentDigest.create(body)


def check_content_digest(lines: HeaderLines, body: bytes) -> None:
    """Checks the message's ``Content-Digest`` against ``body``, as the profile requires.

    Every member must match the body (RFC 9530), a repeated algorithm fails,
    and a ``sha-256`` member must be among them. Raises
    :class:`ContentDigestError`.
    """
    value = lines.get("content-digest")
    if value is None:
        raise ContentDigestError("Content-Digest is absent")
    try:
        ContentDigest.verify(value, body)
    except HTTPMessageSignaturesException as e:
        raise ContentDigestError(f"Content-Digest does not match the body: {e}") from e
    # ContentDigest.verify parsed the same value, so this parse succeeds.
    member = _parse_dictionary(value).members.get("sha-256")
    digest, _ = _split(member)
    if not isinstance(digest, bytes):
        raise ContentDigestError("Content-Digest has no sha-256 member")


__all__ = [
    "ComponentId",
    "ComponentParam",
    "ContentDigestError",
    "SignatureAgentMember",
    "SignatureFields",
    "SignatureMember",
    "check_content_digest",
    "component_id",
    "content_digest",
    "is_signed",
    "only_member",
    "parse_signature_fields",
    "signature_values",
]
