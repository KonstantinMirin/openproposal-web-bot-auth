"""Who is calling: the frozen values the identity boundary (seller/boundary.py) returns.

A leaf module. It imports pydantic and the credential method names, nothing
that reaches HTTP, storage, or the Web Bot Auth library, so the offer logic can
take a `Caller` without loading any of them.

The types allow no illegal state. Each is strict, so nothing is coerced
(`body_covered="yes"` fails); frozen, with unknown members refused; and
`model_copy` raises, so nothing amends an identity the boundary confirmed. A
credential is either a `SignatureCredential` or a `BearerCredential`, told
apart by `method`: a bearer credential can't carry an origin, and a
`PublicCaller` can carry only a signature, the identity a verified origin
establishes without a principal.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field

from shared.auth import BearerMethod, SignatureMethod


class AmendedIdentityError(TypeError):
    """An identity value was asked for an amended copy. The boundary builds a new one instead."""

    def __init__(self, kind: str) -> None:
        super().__init__(f"{kind} is never amended; only the identity boundary builds one")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    def model_copy(
        self, *, update: Mapping[str, object] | None = None, deep: bool = False
    ) -> NoReturn:
        """Refused: a copy with `update` would skip validation."""
        del update, deep
        raise AmendedIdentityError(type(self).__name__)


class Principal(_Frozen):
    """A party this seller knows, as its own database records it."""

    id: str
    kind: Literal["buyer"]
    legal_name: str
    domain: str


class DirectoryResponse(_Frozen):
    """The key directory response a signature verified against, as fetched (§ 4.1.2)."""

    url: str | None
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    fetched_at: int | None


class SignedMessage(_Frozen):
    """A verified request as exact bytes: the evidence § 4.1.2 asks the seller to keep.

    It is a value, not a row: storage keeps it with the entry it carried, in
    the same transaction, and only when it writes that entry.
    """

    method: str
    url: str
    #: Every header line as received, in order and with its own case.
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes
    #: The directory the key came from, when the resolver provides it.
    directory: DirectoryResponse | None


class SignatureCredential(_Frozen):
    """A verified Web Bot Auth signature: the origin it establishes and the key that signed."""

    method: SignatureMethod
    #: The verified origin, `https://<host>`.
    origin: str
    keyid: str
    #: True when the signature covers the body through `Content-Digest`.
    body_covered: bool
    #: The request itself, kept with the entry it carries; not part of the caller's view.
    message: SignedMessage = Field(exclude=True)


class BearerCredential(_Frozen):
    """A bearer token this seller issued, confirmed by its hash. It names no origin."""

    method: BearerMethod


#: How the caller authenticated, told apart by `method`.
Credential = Annotated[SignatureCredential | BearerCredential, Field(discriminator="method")]


class ResolvedCaller(_Frozen):
    """A confirmed credential that names a principal in this seller's records."""

    kind: Literal["resolved"] = "resolved"
    principal: Principal
    credential: Credential
    #: § 4.1.2: the signature attributes the body's entries to the principal: it covers
    #: the body, and the signing host is the principal's domain or a subdomain of it.
    attributed: bool


class PublicCaller(_Frozen):
    """No principal: no credential, or a verified origin this seller has no row for."""

    kind: Literal["public"] = "public"
    signature: SignatureCredential | None = None


#: The caller the boundary returns, told apart by `kind`.
Caller = Annotated[ResolvedCaller | PublicCaller, Field(discriminator="kind")]
