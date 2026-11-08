"""The values a party keeps and names its counterparties by: pure, so every layer can hold them.

The module imports pydantic, `idna`, the standard library, and protocol.values,
and nothing that reaches the Web Bot Auth library, HTTP, or storage (an
import-linter contract keeps it so). The offer logic, the control plane, and
the stores hold these values without loading any of them; transport/wba.py
converts them to and from the library's own types.

- `Origin`: an identity, `https://<host>`, under the rules of the library's
  `Origin.parse`.
- `AuthMethod`: how a caller authenticated.
- `KeptRequest`, `KeptResponse`, `DirectoryFetch`: a signed message and a key
  directory response as exact field lines and bytes (§ 4.1.2, Signed messages).
- `Signer`, `SignedRequest`, `SignedResponse`: who signed a kept message, with
  which key, and the directory fetch that key came from.
- `Provenance`: who wrote an assent entry and how that was proven, which the
  seller keeps with the entry.
"""

from __future__ import annotations

import ipaddress
from typing import Literal, Self

import idna
from pydantic import GetJsonSchemaHandler, model_serializer, model_validator
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from protocol.values import Value

#: A Web Bot Auth signature.
SignatureMethod = Literal["web_bot_auth"]
#: A bearer token the seller issued.
BearerMethod = Literal["bearer"]
#: How a caller authenticated.
AuthMethod = Literal[SignatureMethod, BearerMethod]

#: Where an origin publishes its signed key directory.
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
_SCHEME = "https://"


class NotAnOriginError(ValueError):
    """Text that is not exactly `https://<host>` with a canonical host."""

    def __init__(self, value: object) -> None:
        super().__init__(f"{value!r} is not an origin https://<host>")


def _canonical_host(host: str) -> bool:
    """True when `host` is already in canonical form, with no port.

    A name is canonical when IDNA-2008 (UTS #46, non-transitional) encodes it to
    itself: lowercase ASCII A-labels, no trailing dot, and a last label that
    isn't a number (a URL parser reads `127.1` or `0x7f.0.0.1` as an IPv4
    address). An IPv4 address in dotted-decimal form, or an IPv6 address in
    brackets with no zone, is canonical in its compressed form.
    """
    if not host or host.endswith(".") or "%" in host:
        return False
    literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        pass
    else:
        return host == (f"[{ip}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip))
    last = host.rsplit(".", 1)[-1]
    if last.isdigit() or last[:2].lower() == "0x":
        return False
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii") == host
    except (idna.IDNAError, UnicodeError):
        return False


class Origin(Value):
    """An identity origin, `https://<host>`, validated from and serialized as that text.

    It accepts exactly what the library's `Origin.parse` accepts: `https://` and
    a canonical host, with no port (`:443` included), path, trailing `/`, query,
    fragment, or userinfo. `str(origin)` is its serialization.
    """

    host: str

    @model_validator(mode="before")
    @classmethod
    def _from_text(cls, value: object) -> object:
        """Reads the text form, `https://<host>`; a mapping is read as the fields."""
        if not isinstance(value, str):
            return value
        if not value.isascii() or not value.startswith(_SCHEME):
            raise NotAnOriginError(value)
        return {"host": value[len(_SCHEME) :]}

    @model_validator(mode="after")
    def _canonical(self) -> Self:
        if not _canonical_host(self.host):
            raise NotAnOriginError(f"{_SCHEME}{self.host}")
        return self

    @model_serializer
    def _text(self) -> str:
        return str(self)

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        del core_schema, handler
        return {"type": "string", "title": "Origin", "description": "https://<host>"}

    @classmethod
    def parse(cls, text: str) -> Origin:
        """The origin `text` names; raises pydantic's `ValidationError` for anything else."""
        return cls.model_validate(text)

    @property
    def directory_url(self) -> str:
        """The URL of the origin's signed key directory."""
        return f"{self}{DIRECTORY_PATH}"

    def __str__(self) -> str:
        return f"{_SCHEME}{self.host}"


#: One field line: its name and value as text, each byte on the wire one character
#: (transport/wba.py decodes them), so the bytes come back exactly. The name keeps its case.
HeaderLine = tuple[str, str]


class KeptRequest(Value):
    """A request as exact field lines and bytes: as received, or as sent."""

    method: str
    url: str
    #: Every field line, in order and with its own case.
    lines: tuple[HeaderLine, ...]
    body: bytes
    #: Its row, once kept.
    id: int | None = None


class KeptResponse(Value):
    """A response as exact field lines and bytes, bound to the request it answers."""

    status: int
    lines: tuple[HeaderLine, ...]
    body: bytes
    request: KeptRequest
    #: Its row, once kept.
    id: int | None = None


class DirectoryFetch(Value):
    """A key directory response as fetched: what § 4.1.2 asks a party to keep."""

    url: str
    status: int
    #: Every field line, with the fetch's own directory signatures.
    lines: tuple[HeaderLine, ...]
    #: The exact bytes the keys were read from.
    body: bytes
    #: When it was fetched, in Unix seconds: what its signatures' expiry is checked against.
    fetched_at: int


class Signer(Value):
    """Who sent a kept message: its origin, the key that signed it, and that key's directory."""

    origin: Origin
    #: None for a request that carried a bearer token instead of a signature.
    keyid: str | None
    #: The directory fetch the key came from; None for a party's own request.
    directory: DirectoryFetch | None = None


class SignedRequest(Value):
    """A kept request and who signed it."""

    request: KeptRequest
    signer: Signer


class SignedResponse(Value):
    """A kept response, who signed it, and who sent the request it is bound to."""

    response: KeptResponse
    signer: Signer
    request_signer: Signer


class IllegalProvenanceError(ValueError):
    """A provenance whose signed request doesn't match how the caller authenticated."""

    def __init__(self) -> None:
        super().__init__(
            "a provenance carries a signed request exactly when the caller signed,"
            " and only a signature attributes"
        )


class Provenance(Value):
    """Who wrote an assent entry and how the boundary confirmed it: what storage keeps with it.

    The identity boundary builds it once, from the caller it confirmed. The
    offer logic reads only `principal_id` and hands the rest to storage
    unread. `signed` is present exactly when `method` is the signature method,
    and only a signature attributes, so no other combination constructs.
    """

    principal_id: str
    method: AuthMethod
    #: § 4.1.2: the signature attributes the body's entries to the principal.
    attributed: bool
    #: The verified request that carried the entry, with who signed it.
    signed: SignedRequest | None

    @model_validator(mode="after")
    def _signed_exactly_for_a_signature(self) -> Self:
        signature = self.method == "web_bot_auth"
        if signature != (self.signed is not None) or (self.attributed and not signature):
            raise IllegalProvenanceError
        return self
