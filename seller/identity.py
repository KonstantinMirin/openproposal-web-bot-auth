"""The seller's one identity boundary.

`resolve_caller` is the only code that reads a credential. It treats a Web Bot
Auth signature and a bearer token the same way:

1. Read the credential the caller presented: a `web-bot-auth` signature, an
   `Authorization: Bearer` token, or nothing.
2. Confirm it: the library's `RequestVerifier` for a signature, which also
   proves the body is covered through `Content-Digest`; the token's hash for a
   bearer token. A credential that fails confirmation is refused here, never
   downgraded to no credential.
3. Resolve it to the principal stored in this seller's own database: by the
   verified origin, or by the token hash. A verified origin with no row is an
   established identity with no principal.
4. Return one frozen value. Handlers receive it and never read a header, and
   nothing amends it afterwards.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import Depends, Request
from iab_agentic_primitives.web_bot_auth import WebBotAuthError, accept_signature
from iab_agentic_primitives.web_bot_auth.asgi import request_url
from pydantic import BaseModel, ConfigDict

from .errors import Refused


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Principal(Frozen):
    """A party this seller knows, as its own database records it."""

    id: str
    kind: Literal["buyer"]
    legal_name: str
    domain: str


class ResolvedCaller(Frozen):
    """A confirmed credential that names a principal in this seller's records."""

    kind: Literal["resolved"] = "resolved"
    principal: Principal
    authentication_method: Literal["web_bot_auth", "bearer"]
    #: The verified origin and its host, for a signed request.
    origin: str | None = None
    host: str | None = None
    #: True when the signature covers the body through `Content-Digest`.
    body_covered: bool = False
    #: The stored signed request, for a signed request.
    evidence_id: int | None = None


class PublicCaller(Frozen):
    """No principal: either no credential, or a verified origin this seller has no row for."""

    kind: Literal["public"] = "public"
    authentication_method: Literal["web_bot_auth"] | None = None
    origin: str | None = None
    host: str | None = None
    body_covered: bool = False
    evidence_id: int | None = None


Caller = ResolvedCaller | PublicCaller


def _bearer(value: str | None) -> str | None:
    if value is None:
        return None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise Refused(401, "invalid-authorization", "Authorization is not a Bearer token",
                      headers={"WWW-Authenticate": 'Bearer error="invalid_request"'})
    return token.strip()


async def resolve_caller(request: Request) -> ResolvedCaller | PublicCaller:
    """Confirms the presented credential and resolves it to this seller's principal."""
    store, verifier, origin = (
        request.app.state.store,
        request.app.state.verifier,
        request.app.state.origin,
    )
    headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
    body = await request.body()

    # 1. Read the presented credential.
    signed = "signature-input" in request.headers or "signature" in request.headers
    token = _bearer(request.headers.get("authorization"))
    if signed and token is not None:
        raise Refused(400, "two-credentials", "present a signature or a bearer token, not both")

    if signed:
        # 2. Confirm the signature. The library fetches the origin's directory as needed.
        url = request_url(request.scope, origin)
        try:
            verified = await verifier.verify(request.method, url, headers, body)
        except WebBotAuthError as e:
            hint = {} if e.status == 400 else {"Accept-Signature": accept_signature(has_body=bool(body))}
            raise Refused(e.status, e.reason, str(e), headers=hint) from e
        evidence_id = store.record_evidence(
            origin=verified.origin, keyid=verified.keyid, method=request.method, url=url,
            headers=headers, body=body, directory=verified.directory,
        )
        identity = {
            "authentication_method": "web_bot_auth",
            "origin": verified.origin,
            "host": verified.host,
            "body_covered": verified.body_covered,
            "evidence_id": evidence_id,
        }
        # 3. Resolve it in this seller's own records.
        principal = store.principal_for_origin(verified.origin)
        if principal is None:
            return PublicCaller(**identity)
        return ResolvedCaller(principal=Principal(**principal), **identity)

    if token is not None:
        # 2 and 3. A token is confirmed and resolved by the same lookup.
        principal = store.principal_for_token(token)
        if principal is None:
            raise Refused(401, "invalid-token", "the bearer token is not valid",
                          headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        return ResolvedCaller(principal=Principal(**principal), authentication_method="bearer")

    return PublicCaller()


#: How a route asks for its caller: `caller: CallerDep`.
CallerDep = Annotated[ResolvedCaller | PublicCaller, Depends(resolve_caller)]
