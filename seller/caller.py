"""Who is calling: the frozen values the identity boundary (seller/boundary.py) returns.

It imports pydantic, the pure values of protocol/values.py and
persistence/values.py, and the `Principal` of seller/ports.py, which the store
builds from its row: nothing that reaches HTTP, storage, or the Web Bot Auth
library. The offer logic never takes a `Caller`: the seller's HTTP seam
(seller/http.py) hands it the caller's `Provenance` instead.

The types allow no illegal state. Each is a `Value`: strict, so nothing is
coerced (`body_covered="yes"` fails); frozen, with unknown members refused; and
`model_copy` raises, so nothing amends an identity the boundary confirmed. A
credential is either a `SignatureCredential` or a `BearerCredential`, told
apart by `method`: a bearer credential can't carry an origin, and a
`PublicCaller` can carry only a signature, the identity a verified origin
establishes without a principal. A `ResolvedCaller` carries the `Provenance`
storage keeps with an entry it writes, which names the same principal, method,
and attribution.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal, NoReturn, Self

from pydantic import Field, model_validator

from persistence.values import BearerMethod, Origin, Provenance, SignatureMethod
from protocol.values import AmendedValueError, Value

from .ports import Principal


class AmendedIdentityError(AmendedValueError):
    """An identity value was asked for an amended copy. The boundary builds a new one instead."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind, "only the identity boundary builds one")


class ProvenanceMismatchError(ValueError):
    """A caller whose provenance names another principal, method, or attribution."""

    def __init__(self) -> None:
        super().__init__("the provenance names another principal, method, or attribution")


class _Frozen(Value):
    def model_copy(
        self, *, update: Mapping[str, object] | None = None, deep: bool = False
    ) -> NoReturn:
        """Refused: a copy with `update` would skip validation."""
        del update, deep
        raise AmendedIdentityError(type(self).__name__)


class SignatureCredential(_Frozen):
    """A verified Web Bot Auth signature: the origin it establishes and the key that signed."""

    method: SignatureMethod
    #: The verified origin.
    origin: Origin
    keyid: str
    #: True when the signature covers the body through `Content-Digest`.
    body_covered: bool


class BearerCredential(_Frozen):
    """A bearer token this seller issued, confirmed by its hash. It names no origin."""

    method: BearerMethod


#: How the caller authenticated, told apart by `method`.
Credential = Annotated[SignatureCredential | BearerCredential, Field(discriminator="method")]


class ResolvedCaller(_Frozen):
    """A confirmed credential that names a principal in this seller's records, as the store
    read it."""

    kind: Literal["resolved"] = "resolved"
    principal: Principal
    credential: Credential
    #: § 4.1.2: the signature attributes the body's entries to the principal: it covers
    #: the body, and the signing host is the principal's domain or a subdomain of it.
    attributed: bool
    #: What storage keeps with an entry this caller writes, the signed request included;
    #: not part of the caller's view.
    provenance: Provenance = Field(exclude=True)

    @model_validator(mode="after")
    def _provenance_matches(self) -> Self:
        p = self.provenance
        if (p.principal_id, p.method, p.attributed) != (
            self.principal.id,
            self.credential.method,
            self.attributed,
        ):
            raise ProvenanceMismatchError
        return self


class PublicCaller(_Frozen):
    """No principal: no credential, or a verified origin this seller has no row for."""

    kind: Literal["public"] = "public"
    signature: SignatureCredential | None = None


#: The caller the boundary returns, told apart by `kind`.
Caller = Annotated[ResolvedCaller | PublicCaller, Field(discriminator="kind")]
