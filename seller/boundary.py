"""The seller's one identity boundary.

`IdentityBoundary.resolve` is the only code that reads a caller's protocol
credential. It treats a Web Bot Auth signature and a bearer token the same way:

1. Read the credential the caller presented: a `web-bot-auth` signature, an
   `Authorization: Bearer` token, or nothing. Both at once is refused.
2. Confirm it: the library's `RequestVerifier` for a signature, which also
   proves the body is covered through `Content-Digest`; the token's hash for a
   bearer token. A credential that fails confirmation is refused here, never
   downgraded to no credential.
3. Resolve it to the principal stored in this seller's own database: by the
   verified origin, or by the token hash. A verified origin with no row is an
   established identity with no principal.
4. Return one frozen value (seller/caller.py). Handlers receive it and never
   read a header, and nothing amends it afterwards.

The boundary writes nothing. A signature's request travels in the credential
as a `KeptRequest`, with the directory fetch it verified against, and storage
keeps them only with an entry they carried.

`create_app` (seller/app.py) builds the boundary from its collaborators, and
seller/http.py binds it to `CallerDep`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from iab_agentic_primitives.web_bot_auth import (
    Refusal,
    RequestVerifier,
    ServerIdentity,
    VerifiedRequest,
    WebBotAuthError,
    refusal_response,
)
from starlette.requests import Request

from persistence.values import KeptRequest, Origin
from protocol.attribution import attributes
from transport.wba import fetch_of, is_signed, origin_of, request_of, to_library

from .caller import (
    BearerCredential,
    Caller,
    Principal,
    PublicCaller,
    ResolvedCaller,
    SignatureCredential,
)
from .ports import PrincipalRecord

#: The boundary's own refusals, beside the library's `Refusal` for a signature.
BoundaryReason = Literal["invalid-authorization", "two-credentials", "invalid-token"]
#: The statuses a refusal answers with: the library's, and 401 for a bearer token.
RefusalStatus = Literal[400, 401, 403, 429, 503]


class Refused(Exception):
    """The boundary refused the credential. The handler never runs."""

    def __init__(
        self,
        status: RefusalStatus,
        error: Refusal | BoundaryReason,
        detail: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status, self.error, self.detail = status, error, detail
        self.headers: Mapping[str, str] = headers or {}

    @property
    def reason(self) -> str:
        """The machine-readable reason: the library's code, or the boundary's own."""
        return self.error.code if isinstance(self.error, Refusal) else self.error


class PrincipalDirectory(Protocol):
    """The boundary's lookups: a principal by its verified origin, or by its token."""

    def for_origin(self, origin: Origin) -> PrincipalRecord | None: ...
    def for_token(self, token: str) -> PrincipalRecord | None: ...


@dataclass(frozen=True)
class _PresentedSignature:
    """The request carries signature fields."""


@dataclass(frozen=True)
class _PresentedBearer:
    token: str


def _presented(
    request: KeptRequest, authorization: str | None
) -> _PresentedSignature | _PresentedBearer | None:
    """The credential the caller presented, before anything confirms it."""
    signed = is_signed(request.lines)
    token = _bearer(authorization)
    if signed and token is not None:
        raise Refused(400, "two-credentials", "present a signature or a bearer token, not both")
    if signed:
        return _PresentedSignature()
    return None if token is None else _PresentedBearer(token)


def _bearer(value: str | None) -> str | None:
    if value is None:
        return None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise Refused(
            401,
            "invalid-authorization",
            "Authorization is not a Bearer token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_request"'},
        )
    return token.strip()


def _signature_refused(error: WebBotAuthError, *, has_body: bool) -> Refused:
    """The library's refusal of a signature: its status, and the hint it presents with it
    (`Accept-Signature` on 403 and 429, `Retry-After` on 503)."""
    _status, lines, _body = refusal_response(error, has_body=has_body)
    hint = {name: value for name, value in lines if name.lower() != "content-type"}
    return Refused(error.status, error.refusal, str(error), headers=hint)


def _principal(record: PrincipalRecord) -> Principal:
    return Principal(id=record.id, kind="buyer", legal_name=record.legal_name, domain=record.domain)


class IdentityBoundary:
    """Confirms the presented credential and resolves it to this seller's principal."""

    def __init__(
        self, directory: PrincipalDirectory, verifier: RequestVerifier, identity: ServerIdentity
    ) -> None:
        self._directory, self._verifier, self._identity = directory, verifier, identity

    async def resolve(self, request: Request, body: bytes) -> Caller:
        """The caller of `request`, whose body is `body`; raises `Refused`.

        The body is read before the credential is confirmed, because the
        signature covers it through `Content-Digest`. Nothing parses it here.
        """
        kept = request_of(request.scope, self._identity, body)
        presented = _presented(kept, request.headers.get("authorization"))
        if presented is None:
            return PublicCaller()
        if isinstance(presented, _PresentedBearer):
            return self._resolve_bearer(presented.token)
        return self._resolve_signed(await self._confirm_signature(kept))

    async def _confirm_signature(self, request: KeptRequest) -> SignatureCredential:
        """The verified signature; the library fetches the origin's directory as needed."""
        try:
            verified = await self._verifier.verify(to_library(request))
        except WebBotAuthError as e:
            raise _signature_refused(e, has_body=bool(request.body)) from e
        return _credential(verified, request)

    def _resolve_signed(self, credential: SignatureCredential) -> ResolvedCaller | PublicCaller:
        record = self._directory.for_origin(credential.origin)
        if record is None:
            return PublicCaller(signature=credential)
        attributed = attributes(
            credential.origin.host, record.domain, body_covered=credential.body_covered
        )
        return ResolvedCaller(
            principal=_principal(record), credential=credential, attributed=attributed
        )

    def _resolve_bearer(self, token: str) -> ResolvedCaller:
        # A token is confirmed and resolved by the same lookup.
        record = self._directory.for_token(token)
        if record is None:
            raise Refused(
                401,
                "invalid-token",
                "the bearer token is not valid",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        return ResolvedCaller(
            principal=_principal(record),
            credential=BearerCredential(method="bearer"),
            attributed=False,
        )


def _credential(verified: VerifiedRequest, request: KeptRequest) -> SignatureCredential:
    directory = verified.directory
    return SignatureCredential(
        method="web_bot_auth",
        origin=origin_of(verified.origin),
        keyid=str(verified.keyid),
        body_covered=verified.body_covered,
        request=request,
        directory=None if directory is None else fetch_of(directory.evidence),
    )
