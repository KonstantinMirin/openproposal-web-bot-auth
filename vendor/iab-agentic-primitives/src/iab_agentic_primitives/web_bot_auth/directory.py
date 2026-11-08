"""The signed key directory: publishing, signing, and verifying it. No I/O.

An identity, an :class:`~.values.Origin`, publishes its keys only at its
``directory_url``, ``https://<host>/.well-known/http-message-signatures-directory``,
as a JWK Set served with the media type
``application/http-message-signatures-directory+json``. Every function here
takes that origin, and derives the URL and the ``"@authority";req`` it signs
or checks from it.

:func:`publish_directory` is the one way to build and sign a directory: once
per Ed25519 key, each signature covering ``"@authority";req`` and
``content-digest`` and carrying ``created``, ``expires``, the key's thumbprint
as ``keyid``, ``alg="ed25519"``, and ``tag="http-message-signatures-directory"``.
:class:`DirectoryPublisher` publishes a key source that can rotate.

A fetched response is a :class:`DirectoryResponse`. :func:`verify_directory`
verifies it for the origin it was fetched for, in four pure steps, then checks
each key's signature:

1. :func:`check_fetch_rules`: the URL, status ``200``, no
   ``Content-Encoding``, the media type, and the size.
2. :func:`parse_jwk_set`: the body as a JWK Set, to a :class:`KeySet`.
3. The one signature by each key, with the directory tag and components.
4. The directory window, from :data:`rules.DIRECTORY`.

The result is a :class:`VerifiedDirectory` of that origin, which only this
module constructs. Keys of other types, and the signatures they make, are
ignored.
"""

from __future__ import annotations

import base64
import inspect
import json
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import InitVar, dataclass, field
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import _sig
from ._wire import (
    ContentDigestError,
    SignatureFields,
    SignatureMember,
    check_content_digest,
    content_digest,
    parse_signature_fields,
)
from .errors import ConfigurationError, Refusal, WebBotAuthError, refuse
from .keys import JWK, Ed25519Key, public_jwk_of, public_key_from_jwk, thumbprint
from .message import Answer, HeaderLines, Headers, HTTPRequest, HTTPResponse
from .presentation import no_keys_response
from .rules import DIRECTORY, Stamp
from .values import DIRECTORY_MEDIA_TYPE, KeyId, Origin, UnixSeconds, whole_number

#: The body cap for a directory response, in bytes.
MAX_DIRECTORY_BYTES = 256 * 1024
#: The most keys a directory may hold.
MAX_DIRECTORY_KEYS = 16
#: The default Cache-Control max-age of a directory response, in seconds.
DEFAULT_DIRECTORY_MAX_AGE = 300
#: The default lifetime of a directory signature, in seconds.
DEFAULT_DIRECTORY_LIFETIME = 86400


@dataclass(frozen=True, slots=True)
class PublishPolicy:
    """How a directory server signs its directory response. It checks itself.

    ``lifetime`` is how long each signature is valid, 86400 s by default: a
    whole number of seconds, 1 or more, as the directory window takes it.
    ``max_age`` is the response's ``Cache-Control`` ``max-age``, 300 s by
    default; ``0`` is allowed. A publisher that rotates a key waits at least
    ``max_age`` plus the verifiers' cache age before signing with the new key.
    A bad value raises :class:`ConfigurationError`.
    """

    lifetime: int = DEFAULT_DIRECTORY_LIFETIME
    max_age: int = DEFAULT_DIRECTORY_MAX_AGE

    def __post_init__(self) -> None:
        DIRECTORY.window.checked_lifetime(self.lifetime)
        whole_number("max_age", self.max_age, minimum=0)


#: The profile's defaults for publishing a directory.
DEFAULT_PUBLISH = PublishPolicy()


def _positive_seconds(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise ConfigurationError(f"{name} is a positive number of seconds, not {value!r}")
    return float(value)


@dataclass(frozen=True, slots=True)
class FetchLimits:
    """The profile's limits for a directory fetch. It checks itself.

    5 s to connect and 10 s in total, a 256 KiB body, and at most 16 keys. The
    resolver hands the one value to its fetcher, which applies the timeouts
    and reads at most ``max_bytes`` plus one byte, and to
    :func:`verify_directory`, which refuses what breaks a limit. A timeout
    that isn't a positive number of seconds, or a size that isn't a whole
    number, 1 or more, raises :class:`ConfigurationError`.
    """

    connect_timeout: float = 5.0
    total_timeout: float = 10.0
    max_bytes: int = MAX_DIRECTORY_BYTES
    max_keys: int = MAX_DIRECTORY_KEYS

    def __post_init__(self) -> None:
        _positive_seconds("connect_timeout", self.connect_timeout)
        _positive_seconds("total_timeout", self.total_timeout)
        whole_number("max_bytes", self.max_bytes, minimum=1)
        whole_number("max_keys", self.max_keys, minimum=1)


#: The profile's limits, as :class:`FetchLimits` defaults them.
DEFAULT_LIMITS = FetchLimits()


@dataclass(frozen=True, slots=True, init=False)
class DirectoryResponse:
    """A directory response as fetched: the URL, status, field lines, body, and time.

    ``body`` is the bytes on the wire, read under the body cap. ``fetched_at``
    is when it was fetched, in Unix seconds. ``headers`` may be given as a
    mapping, a sequence of pairs, or :class:`HeaderLines`; it is kept as
    :class:`HeaderLines`. A verified directory keeps its response as evidence
    (OpenProposal § 4.1.2 asks a party to keep the bytes of the key directory
    it verified against).
    """

    url: str
    status: int
    headers: HeaderLines
    body: bytes
    fetched_at: UnixSeconds

    def __init__(
        self, url: str, status: int, headers: Headers, body: bytes, fetched_at: UnixSeconds
    ) -> None:
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "headers", HeaderLines(headers))
        object.__setattr__(self, "body", body)
        object.__setattr__(self, "fetched_at", fetched_at)

    def document(self) -> dict[str, object]:
        """The response as JSON-ready data.

        The keys are ``url``, ``status``, ``headers`` (field lines in order, as
        ``[name, value]`` pairs), ``body`` (the bytes as text), ``body_base64``
        (the exact bytes, losslessly), and ``fetched_at``.
        """
        return {
            "url": self.url,
            "status": self.status,
            "headers": [list(line) for line in self.headers],
            "body": self.body.decode("utf-8", "replace"),
            "body_base64": base64.b64encode(self.body).decode("ascii"),
            "fetched_at": self.fetched_at,
        }


#: A key a :class:`KeySet` is built from.
KeyInput = Ed25519Key | Ed25519PublicKey | JWK


def _key_entry(key: KeyInput) -> tuple[KeyId, Ed25519PublicKey]:
    """The one kid normalizer: a key and its thumbprint, whatever form it is given in."""
    if isinstance(key, Ed25519Key):
        return key.thumbprint, key.public_key
    if isinstance(key, Ed25519PublicKey):
        return KeyId(public_jwk_of(key)["kid"]), key
    return thumbprint(key), public_key_from_jwk(key)


class KeySet:
    """An identity's Ed25519 public keys, by thumbprint. It is immutable.

    Iterating yields the key ids. :meth:`lookup` is the one key lookup, and it
    owns the ``key-not-found`` refusal.
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: Mapping[KeyId, Ed25519PublicKey]) -> None:
        self._keys: Mapping[KeyId, Ed25519PublicKey] = MappingProxyType(dict(keys))

    @classmethod
    def from_keys(cls, keys: Iterable[KeyInput]) -> KeySet:
        """The set of ``keys``: :class:`Ed25519Key`, public keys, or public JWKs."""
        return cls(dict(_key_entry(key) for key in keys))

    def lookup(self, kid: KeyId) -> Ed25519PublicKey:
        """The key ``kid``; a ``key-not-found`` refusal when the set doesn't hold it."""
        key = self._keys.get(kid)
        if key is None:
            raise refuse(Refusal.KEY_NOT_FOUND, f"key {kid} is not in the key set")
        return key

    def items(self) -> tuple[tuple[KeyId, Ed25519PublicKey], ...]:
        """The ``(kid, key)`` pairs, in the order the set was built."""
        return tuple(self._keys.items())

    def __iter__(self) -> Iterator[KeyId]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, kid: object) -> bool:
        return kid in self._keys

    def __repr__(self) -> str:
        return f"KeySet({list(self._keys)!r})"


class _Token:
    """Proof that this module verified a directory: it alone holds the instance."""

    __slots__ = ()


_OWNER = _Token()


@dataclass(frozen=True, slots=True)
class VerifiedDirectory:
    """The verified directory of ``origin``: its Ed25519 keys and the response they came from.

    ``expires`` is the earliest ``expires`` among the directory's signatures:
    the keys verify messages until then. ``evidence`` is the response, exactly
    as verified, fetched from ``origin.directory_url``. Only
    :func:`verify_directory` makes one: any other construction,
    ``dataclasses.replace``, a copy, or a pickle raises ``TypeError``.
    """

    origin: Origin
    keys: KeySet
    expires: UnixSeconds
    evidence: DirectoryResponse
    _token: InitVar[_Token | None] = field(default=None, kw_only=True)

    def __post_init__(self, _token: _Token | None) -> None:
        if _token is not _OWNER:
            raise TypeError("a VerifiedDirectory is made only by verifying a directory response")

    def __reduce_ex__(self, protocol: object) -> tuple[object, ...]:
        raise TypeError("a VerifiedDirectory can't be copied or pickled; verify again")

    def key(self, kid: KeyId) -> Ed25519PublicKey:
        """The key ``kid``; a ``key-not-found`` refusal when this origin doesn't publish it."""
        if kid not in self.keys:
            raise refuse(
                Refusal.KEY_NOT_FOUND, f"key {kid} is not in the directory of {self.origin}"
            )
        return self.keys.lookup(kid)


def build_directory(keys: Sequence[Ed25519Key | JWK]) -> bytes:
    """Returns the JWK Set body for ``keys``.

    Each entry is an :class:`Ed25519Key` or a public JWK. A public JWK of another
    type is published as given; the profile's verifiers ignore it.
    """
    published = [k.public_jwk() if isinstance(k, Ed25519Key) else dict(k) for k in keys]
    return json.dumps({"keys": published}, indent=2).encode()


#: The keys a directory publishes: a list, or a callable (sync or async) that
#: returns the current list, so a rotation shows on the next request.
KeySource = (
    Sequence[Ed25519Key] | Callable[[], Sequence[Ed25519Key] | Awaitable[Sequence[Ed25519Key]]]
)


async def current_keys(keys: KeySource) -> list[Ed25519Key]:
    """Returns the keys a :data:`KeySource` publishes now."""
    if callable(keys):
        value = keys()
        if inspect.isawaitable(value):
            value = await value
        return list(value)
    return list(keys)


def _directory_request(origin: Origin) -> HTTPRequest:
    """The request a verifier sends for ``origin``'s directory, whose ``@authority`` is signed."""
    return HTTPRequest("GET", origin.directory_url)


def publish_directory(
    origin: Origin,
    keys: Sequence[Ed25519Key],
    *,
    now: UnixSeconds,
    policy: PublishPolicy = DEFAULT_PUBLISH,
) -> Answer:
    """``origin``'s signed directory of ``keys``, signed at ``now``, as a ``200`` answer.

    ``origin`` is the server's own configured identity, never the ``Host`` a
    client sends: each signature covers ``"@authority";req``, which keeps
    another domain from serving the key set as its own. The headers are
    ``Content-Type``, ``Cache-Control`` (``max-age=<policy.max_age>``),
    ``Content-Digest``, ``Signature-Input``, and ``Signature``. Publishing no
    keys raises :class:`ConfigurationError`.
    """
    if not keys:
        raise ConfigurationError("a directory publishes at least one key")
    body = build_directory(keys)
    lines = HeaderLines(
        [
            ("Content-Type", DIRECTORY_MEDIA_TYPE),
            ("Cache-Control", f"max-age={policy.max_age}"),
            ("Content-Digest", content_digest(body)),
        ]
    )
    expires = UnixSeconds(now + policy.lifetime)
    signers = [
        (key, DIRECTORY.params(Stamp(f"key{i}", key.thumbprint, now, expires)))
        for i, key in enumerate(keys, start=1)
    ]
    unsigned = HTTPResponse(200, lines, b"", _directory_request(origin))
    return Answer(200, _sig.signed_by_each(unsigned, signers).headers, body)


@dataclass(frozen=True, slots=True)
class DirectoryPublisher:
    """Publishes ``origin``'s directory from a key source, signed afresh on each answer.

    ``keys`` is a list, or a callable (sync or async) that returns the current
    keys, so adding or removing a key takes effect on the next answer. A list
    with no keys raises :class:`ConfigurationError`; a callable that returns
    none answers ``503``. ``policy`` sets each signature's lifetime and the
    response's ``max-age``.
    """

    origin: Origin
    keys: KeySource
    policy: PublishPolicy = DEFAULT_PUBLISH

    def __post_init__(self) -> None:
        if not isinstance(self.origin, Origin):
            raise ConfigurationError(f"origin is an Origin, not {self.origin!r}")
        if not callable(self.keys):
            if not self.keys:
                raise ConfigurationError("a directory publishes at least one key")
            object.__setattr__(self, "keys", tuple(self.keys))

    async def answer(self, now: UnixSeconds) -> Answer:
        """The signed directory at ``now``, or ``503`` when the source has no keys now."""
        keys = await current_keys(self.keys)
        if not keys:
            return no_keys_response()
        return publish_directory(self.origin, keys, now=now, policy=self.policy)


# ── step 1: the fetch rules ───────────────────────────────────────────────


def check_fetch_rules(response: DirectoryResponse, origin: Origin, limits: FetchLimits) -> None:
    """Refuses a response that breaks a fetch rule.

    The rules are the URL (``origin.directory_url``, exactly), status ``200``
    (a redirect is never followed), the content as sent (``Content-Encoding``
    absent or ``identity``), the directory media type, and at most
    ``limits.max_bytes`` of body.
    """
    if response.url != origin.directory_url:
        raise refuse(
            Refusal.DIRECTORY_UNAVAILABLE,
            f"the response is from {response.url}, not {origin.directory_url}",
        )
    status = response.status
    if 300 <= status < 400:
        raise refuse(Refusal.DIRECTORY_STATUS, f"directory redirects ({status})")
    if status != 200:
        raise refuse(Refusal.DIRECTORY_STATUS, f"directory status {status}")
    encoding = (response.headers.get("content-encoding") or "identity").strip().lower()
    if encoding != "identity":
        raise refuse(Refusal.DIRECTORY_ENCODING, f"directory Content-Encoding {encoding}")
    media_type = response.headers.media_type()
    if media_type != DIRECTORY_MEDIA_TYPE:
        raise refuse(
            Refusal.DIRECTORY_MEDIA_TYPE, f"directory media type {media_type or 'missing'}"
        )
    if len(response.body) > limits.max_bytes:
        raise refuse(
            Refusal.DIRECTORY_TOO_LARGE, f"directory body exceeds {limits.max_bytes} bytes"
        )


def _check_digest(response: DirectoryResponse) -> None:
    try:
        check_content_digest(response.headers, response.body)
    except ContentDigestError as e:
        raise refuse(Refusal.DIRECTORY_CONTENT_DIGEST, f"directory {e}") from e


# ── step 2: the JWK Set ───────────────────────────────────────────────────


def _jwk_set_members(body: bytes) -> list[object]:
    """The ``keys`` array of a JWK Set body."""
    try:
        # RFC 8259 section 8.1: JSON exchanged between systems is UTF-8.
        document = json.loads(body.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise refuse(Refusal.DIRECTORY_FORMAT, "directory body is not UTF-8") from e
    except (ValueError, RecursionError) as e:
        raise refuse(Refusal.DIRECTORY_FORMAT, "directory body is not JSON") from e
    members = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(members, list):
        raise refuse(Refusal.DIRECTORY_FORMAT, "directory body is not a JWK Set")
    return members


def _directory_key(jwk: object) -> tuple[KeyId, Ed25519PublicKey] | None:
    """The thumbprint and key of an Ed25519 JWK; ``None`` for a key the profile doesn't use."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None  # a key the profile does not use (RFC 7517 section 5)
    try:
        kid, public_key = _key_entry(jwk)
    except ValueError as e:
        raise refuse(Refusal.DIRECTORY_FORMAT, f"directory Ed25519 key: {e}") from e
    if jwk.get("kid", kid) != kid:
        raise refuse(
            Refusal.DIRECTORY_KID, f"directory kid {jwk['kid']!r} is not the key's thumbprint"
        )
    return kid, public_key


def parse_jwk_set(body: bytes, max_keys: int) -> KeySet:
    """The Ed25519 keys of a JWK Set body, by thumbprint.

    Refuses a body that isn't a UTF-8 JWK Set, holds more than ``max_keys``
    keys, holds an Ed25519 key whose ``kid`` isn't its thumbprint, or holds no
    Ed25519 key. Keys of other types are skipped.
    """
    members = _jwk_set_members(body)
    if len(members) > max_keys:
        raise refuse(Refusal.DIRECTORY_TOO_MANY_KEYS, f"directory holds more than {max_keys} keys")
    keys = dict(entry for entry in map(_directory_key, members) if entry is not None)
    if not keys:
        raise refuse(Refusal.DIRECTORY_NO_USABLE_KEY, "the directory holds no Ed25519 key")
    return KeySet(keys)


# ── step 3: the signature by each key ─────────────────────────────────────


def _directory_fields(lines: HeaderLines) -> SignatureFields:
    """The directory's signature fields; an unsigned response has none."""
    if not lines.is_signed():
        return SignatureFields({}, {}, {})
    try:
        return parse_signature_fields(lines)
    except WebBotAuthError as e:
        raise refuse(Refusal.DIRECTORY_SIGNATURE_PARSE, f"directory signature fields: {e}") from e


def _select_directory_signature(fields: SignatureFields, kid: KeyId) -> SignatureMember:
    """The one directory signature by the key ``kid``, with the directory tag and components."""
    members = [m for m in fields.values() if m.keyid == kid]
    if len(members) != 1:
        raise refuse(
            Refusal.DIRECTORY_ONE_SIGNATURE_PER_KEY, f"{len(members)} directory signatures by {kid}"
        )
    member = members[0]
    if member.tag != DIRECTORY.tag:
        raise refuse(Refusal.DIRECTORY_TAG, f"directory signature by {kid} has tag {member.tag!r}")
    if not set(DIRECTORY.components()) <= set(member.components):
        covered = sorted(c.name for c in member.components)
        raise refuse(Refusal.DIRECTORY_COMPONENTS, f"directory signature by {kid} covers {covered}")
    return member


# ── step 4 and the signature check ────────────────────────────────────────


def _verify_key(
    message: HTTPResponse, member: SignatureMember, public_key: Ed25519PublicKey, now: UnixSeconds
) -> UnixSeconds:
    """Checks one key's signature, window first; returns its ``expires``."""
    try:
        expires = DIRECTORY.window.check(member.created, member.expires, now)
    except WebBotAuthError as e:
        raise refuse(e.refusal, f"directory signature by {member.keyid}: {e}") from e
    try:
        _sig.verify(
            message,
            member,
            public_key,
            require_components=DIRECTORY.components(),
            body=message.body,
        )
    except WebBotAuthError as e:
        raise refuse(Refusal.DIRECTORY_SIGNATURE, str(e)) from e
    return expires


def verify_directory(
    response: DirectoryResponse,
    origin: Origin,
    now: UnixSeconds,
    limits: FetchLimits = DEFAULT_LIMITS,
) -> VerifiedDirectory:
    """Verifies ``origin``'s signed directory response and returns its keys, with the evidence.

    Raises a ``403`` :class:`WebBotAuthError` when the response breaks a rule:
    a fetch rule (the URL among them), ``Content-Digest``, the JWK Set, or the
    signature of any Ed25519 key.
    """
    check_fetch_rules(response, origin, limits)
    _check_digest(response)
    keys = parse_jwk_set(response.body, limits.max_keys)
    message = HTTPResponse(
        response.status, response.headers, response.body, _directory_request(origin)
    )
    fields = _directory_fields(response.headers)
    expires = min(
        _verify_key(message, _select_directory_signature(fields, kid), public_key, now)
        for kid, public_key in keys.items()
    )
    return VerifiedDirectory(origin, keys, UnixSeconds(expires), response, _token=_OWNER)


__all__ = [
    "DEFAULT_DIRECTORY_LIFETIME",
    "DEFAULT_DIRECTORY_MAX_AGE",
    "DEFAULT_LIMITS",
    "DEFAULT_PUBLISH",
    "MAX_DIRECTORY_BYTES",
    "MAX_DIRECTORY_KEYS",
    "DirectoryPublisher",
    "DirectoryResponse",
    "FetchLimits",
    "KeyInput",
    "KeySet",
    "KeySource",
    "PublishPolicy",
    "VerifiedDirectory",
    "build_directory",
    "check_fetch_rules",
    "current_keys",
    "parse_jwk_set",
    "publish_directory",
    "verify_directory",
]
