"""The seller's one identity boundary.

`IdentityBoundary.resolve` is the only code that reads a caller's protocol
credential. It treats a Web Bot Auth signature and a bearer token the same way:

1. Read the credential the caller presented: a `web-bot-auth` signature, one
   `Authorization: Bearer` line, or nothing. Both at once, or more than one
   `Authorization` line, is refused as two credentials.
2. Confirm it: the library's `RequestVerifier` for a signature, which also
   proves the body is covered through `Content-Digest`; the token's hash for a
   bearer token. A credential that fails confirmation is refused here, never
   downgraded to no credential.
3. Resolve it to the principal stored in this seller's own database: by the
   verified origin, or by the token hash. A verified origin with no row is an
   established identity with no principal.
4. Return one frozen value (seller/caller.py). Handlers receive it and never
   read a header, and nothing amends it afterwards.

The boundary writes nothing, and yields confirmed facts only. A resolved
caller carries its `Provenance`: the principal, how it authenticated, and, for
a signature, the verified request as a `SignedRequest` (its signer names the
signing origin, with the directory fetch it verified against and the instant
it verified at) and whether the signature covers the body. Whether a signature
attributes an entry (§ 4.1.2) depends on the record the entry is about, so the
boundary never decides it: the seller does, when it writes the entry. Storage
keeps the provenance only with an entry the request carried.

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
    UnixSeconds,
    VerifiedRequest,
    WebBotAuthError,
    refusal_response,
)
from iab_agentic_primitives.web_bot_auth.asgi import ServerEdge
from starlette.requests import Request

from persistence.values import HeaderLine, KeptRequest, Origin, Provenance, SignedRequest, Signer
from transport.control import BoundaryReason, RefusalBody
from transport.wba import fetch_of, is_signed, origin_of, request_of, to_library

from .caller import (
    BearerCredential,
    Caller,
    PublicCaller,
    ResolvedCaller,
    SignatureCredential,
)
from .ports import Principal

#: The statuses a refusal answers with: the library's, and 401 for a bearer token.
RefusalStatus = Literal[400, 401, 403, 429, 503]


class Refused(Exception):
    """The boundary refused the credential. The handler never runs.

    `body` is what the refusal answers with: for a signature, the body the
    library's `refusal_response` renders; for the boundary's own reasons, the
    same form, a `RefusalBody` (transport/control.py). `detail` stays in the
    seller's log.
    """

    def __init__(
        self,
        status: RefusalStatus,
        reason: Refusal | BoundaryReason,
        detail: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> None:
        super().__init__(detail)
        self.status, self.reason, self.detail = status, reason, detail
        self.headers: Mapping[str, str] = headers or {}
        self.body = (
            RefusalBody(error=reason, status=status).model_dump_json().encode()
            if body is None
            else body
        )


class PrincipalDirectory(Protocol):
    """The boundary's lookups: a principal by its verified origin, or by its token."""

    def for_origin(self, origin: Origin) -> Principal | None: ...
    def for_token(self, token: str) -> Principal | None: ...


@dataclass(frozen=True)
class _PresentedSignature:
    """The request carries signature fields."""


@dataclass(frozen=True)
class _PresentedBearer:
    token: str


def _authorization(lines: tuple[HeaderLine, ...]) -> str | None:
    """The one `Authorization` line's value, or None without one. Two or more lines are two
    credentials, whichever of them would confirm: a server that read only one would let the
    order of the lines decide."""
    values = [value for name, value in lines if name.lower() == "authorization"]
    if len(values) > 1:
        raise Refused(400, "two-credentials", "present one Authorization line, not several")
    return values[0] if values else None


def _presented(request: KeptRequest) -> _PresentedSignature | _PresentedBearer | None:
    """The credential the caller presented, before anything confirms it."""
    signed = is_signed(request.lines)
    token = _bearer(_authorization(request.lines))
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
    _status, lines, body = refusal_response(error, has_body=has_body)
    hint = {name: value for name, value in lines if name.lower() != "content-type"}
    return Refused(error.status, error.refusal, str(error), headers=hint, body=body)


class IdentityBoundary:
    """Confirms the presented credential and resolves it to this seller's principal."""

    def __init__(
        self, directory: PrincipalDirectory, verifier: RequestVerifier, edge: ServerEdge
    ) -> None:
        """`edge` is the seller's one identity, whose base URL every request is rebuilt on; the
        verifier verifies for the same identity."""
        self._directory, self._verifier, self._edge = directory, verifier, edge

    async def resolve(self, request: Request, body: bytes) -> Caller:
        """The caller of `request`, whose body is `body`; raises `Refused`.

        The body is read before the credential is confirmed, because the
        signature covers it through `Content-Digest`. Nothing parses it here.
        """
        kept = request_of(request.scope, self._edge, body)
        presented = _presented(kept)
        if presented is None:
            return PublicCaller()
        if isinstance(presented, _PresentedBearer):
            return self._resolve_bearer(presented.token)
        at = self._verifier.clock()
        return self._resolve_signed(await self._confirm_signature(kept, at), kept, at)

    async def _confirm_signature(self, request: KeptRequest, at: UnixSeconds) -> VerifiedRequest:
        """The signature, verified at `at`; the library fetches the origin's directory as
        needed."""
        try:
            return await self._verifier.verify(to_library(request), now=at)
        except WebBotAuthError as e:
            raise _signature_refused(e, has_body=bool(request.body)) from e

    def _resolve_signed(
        self, verified: VerifiedRequest, request: KeptRequest, at: UnixSeconds
    ) -> ResolvedCaller | PublicCaller:
        credential = _credential(verified)
        principal = self._directory.for_origin(credential.origin)
        if principal is None:
            return PublicCaller(signature=credential)
        provenance = Provenance(
            principal_id=principal.id,
            method=credential.method,
            signed=_signed(credential, verified, request, at),
            body_covered=credential.body_covered,
        )
        return ResolvedCaller(principal=principal, credential=credential, provenance=provenance)

    def _resolve_bearer(self, token: str) -> ResolvedCaller:
        # A token is confirmed and resolved by the same lookup.
        principal = self._directory.for_token(token)
        if principal is None:
            raise Refused(
                401,
                "invalid-token",
                "the bearer token is not valid",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        provenance = Provenance(principal_id=principal.id, method="bearer", signed=None)
        return ResolvedCaller(
            principal=principal, credential=BearerCredential(method="bearer"), provenance=provenance
        )


def _credential(verified: VerifiedRequest) -> SignatureCredential:
    return SignatureCredential(
        method="web_bot_auth",
        origin=origin_of(verified.origin),
        keyid=str(verified.keyid),
        body_covered=verified.body_covered,
    )


def _signed(
    credential: SignatureCredential,
    verified: VerifiedRequest,
    request: KeptRequest,
    at: UnixSeconds,
) -> SignedRequest:
    """The verified request, with its signer, the directory fetch it verified against
    (§ 4.1.2) when the resolver provides it, and `at`, the instant it verified at."""
    directory = verified.directory
    signer = Signer(
        origin=credential.origin,
        keyid=credential.keyid,
        directory=None if directory is None else fetch_of(directory.evidence),
    )
    return SignedRequest(request=request, signer=signer, verified_at=at)
