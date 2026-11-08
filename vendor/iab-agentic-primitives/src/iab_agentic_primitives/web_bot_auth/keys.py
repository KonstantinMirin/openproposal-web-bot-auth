"""Ed25519 signing keys, their public JWKs, and JWK thumbprints.

Every signing key under the profile is an Ed25519 key (``kty`` ``OKP``, ``crv``
``Ed25519``), and its ``kid`` is its JWK thumbprint (RFC 7638; RFC 8037
Appendix A.3). ``joserfc`` imports and exports the JWKs and computes the
thumbprints; this module adds only the profile's rules: Ed25519 only, ``kid``
equal to the thumbprint, and ``use`` ``sig``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, NotRequired, TypedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

from .values import KeyId

#: A JWK as JSON gives it, before it is checked: member names to values of any JSON type.
JWK = Mapping[str, object]


class PublicJwk(TypedDict):
    """An Ed25519 public JWK as a directory publishes it."""

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    kid: str
    x: str
    use: Literal["sig"]


class PrivateJwk(TypedDict):
    """An Ed25519 private JWK: the public members, which ``kid`` and ``use`` may join,
    and the private ``d``."""

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str
    d: str
    kid: NotRequired[str]
    use: NotRequired[Literal["sig"]]


def _members(jwk: JWK, *, private: bool) -> dict[str, str]:
    """The members ``joserfc`` reads, checked to be an Ed25519 JWK of the right kind."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("not an Ed25519 JWK")
    names = ("kty", "crv", "x", "d") if private else ("kty", "crv", "x")
    members: dict[str, str] = {}
    for name in names:
        value = jwk.get(name)
        if isinstance(value, str):
            members[name] = value
        elif value is not None:
            raise ValueError(f"the JWK member {name} is not a string")
    if private and "d" not in members:
        raise ValueError("not an Ed25519 private JWK")
    if not private and "x" not in members:
        raise ValueError("not an Ed25519 public JWK")
    return members


def _okp(key: JWK | Ed25519PrivateKey | Ed25519PublicKey, *, private: bool) -> OKPKey:
    try:
        if isinstance(key, Mapping):
            members: dict[str, str | list[str]] = dict(_members(key, private=private))
            return OKPKey.import_key(members)
        return OKPKey.import_key(key)
    except JoseError as e:  # a member joserfc requires is missing or malformed
        raise ValueError(f"not a valid Ed25519 JWK: {e}") from e


def thumbprint(jwk: JWK) -> KeyId:
    """Returns the RFC 7638 thumbprint of an Ed25519 public JWK."""
    return KeyId(_okp(jwk, private=False).thumbprint())


def public_key_from_jwk(jwk: JWK) -> Ed25519PublicKey:
    """Loads an Ed25519 public key from a JWK; raises ``ValueError`` for any other key."""
    key = _okp(jwk, private=False).public_key
    if not isinstance(key, Ed25519PublicKey):  # pragma: no cover - crv is checked above
        raise ValueError("not an Ed25519 public JWK")
    return key


def _member(okp: OKPKey, name: str, *, private: bool) -> str:
    value = okp.as_dict(private=private)[name]
    if not isinstance(value, str):  # pragma: no cover - an OKP key's x and d are strings
        raise ValueError(f"the JWK member {name} is not a string")
    return value


def _publish(okp: OKPKey) -> PublicJwk:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": okp.thumbprint(),
        "x": _member(okp, "x", private=False),
        "use": "sig",
    }


def public_jwk_of(public_key: Ed25519PublicKey) -> PublicJwk:
    """Returns the public JWK of ``public_key``, with ``kid`` set to its thumbprint."""
    return _publish(_okp(public_key, private=False))


@dataclass(frozen=True, slots=True, eq=False, init=False)
class Ed25519Key:
    """An Ed25519 private key with its thumbprint. It is immutable.

    Create one with :meth:`generate`, :meth:`from_seed`, or :meth:`from_jwk`;
    :func:`~.keyfile.load_or_create` keeps one in a file. The private key
    isn't an attribute; :meth:`sign` uses it, and :meth:`private_jwk` exports
    it. The thumbprint and the public key derive from it once, when the key is
    made.
    """

    public_key: Ed25519PublicKey
    _private_key: Ed25519PrivateKey = field(repr=False)  # gitleaks:allow
    _okp: OKPKey = field(repr=False)
    _public_jwk: PublicJwk = field(repr=False)

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        okp = _okp(private_key, private=True)
        object.__setattr__(self, "_private_key", private_key)
        object.__setattr__(self, "_okp", okp)
        object.__setattr__(self, "public_key", private_key.public_key())
        object.__setattr__(self, "_public_jwk", _publish(okp))

    @classmethod
    def generate(cls) -> Ed25519Key:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Ed25519Key:
        """Loads the key whose 32-byte private seed is ``seed`` (the JWK ``d`` value)."""
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_jwk(cls, jwk: JWK) -> Ed25519Key:
        """Loads a private JWK. When ``x`` is present, it must match ``d``."""
        private_key = _okp(jwk, private=True).private_key
        if not isinstance(private_key, Ed25519PrivateKey):  # pragma: no cover - crv is checked
            raise ValueError("not an Ed25519 private JWK")
        key = cls(private_key)
        if "x" in jwk and jwk["x"] != key._public_jwk["x"]:
            raise ValueError("the JWK's x does not match its d")
        return key

    @property
    def thumbprint(self) -> KeyId:
        """The RFC 7638 thumbprint, used as ``kid`` and ``keyid``."""
        return KeyId(self._public_jwk["kid"])

    def public_jwk(self) -> PublicJwk:
        """Returns the public JWK as a directory publishes it."""
        return PublicJwk(**self._public_jwk)

    def private_jwk(self) -> PrivateJwk:
        """Returns the private JWK, including ``d``. Keep it secret."""
        public = self._public_jwk
        d = _member(self._okp, "d", private=True)
        return PrivateJwk(
            kty="OKP", crv="Ed25519", kid=public["kid"], x=public["x"], use="sig", d=d
        )

    def sign(self, data: bytes) -> bytes:
        """Signs ``data`` with the private key."""
        return self._private_key.sign(data)

    def __repr__(self) -> str:
        return f"Ed25519Key(kid={self.thumbprint!r})"


__all__ = [
    "JWK",
    "Ed25519Key",
    "PrivateJwk",
    "PublicJwk",
    "public_jwk_of",
    "public_key_from_jwk",
    "thumbprint",
]
