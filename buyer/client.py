"""How the buyer calls a seller, and how it confirms who answered.

The request carries one credential: a Web Bot Auth signature, through the
library's `WebBotAuth`, or the bearer token the seller issued. Either way the
seller signs its response, and the buyer verifies that signature and, for a
signed request, its binding to the request. A response that fails is refused.

Every call goes through the client the buyer's lifespan owns (buyer/app.py).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from iab_agentic_primitives.web_bot_auth import (
    HTTPRequest,
    KeyResolver,
    Origin,
    Refusal,
    RequestSigner,
    ResponseVerifier,
    VerifiedResponse,
    WebBotAuthError,
)
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth, verified_response

from shared.auth import AuthMethod

#: How the buyer authenticates a request to a seller.
Credential = AuthMethod

#: The client every call goes through. The rest of the buyer holds one and passes it
#: here; only this module sends requests with it.
HTTPClient = httpx.AsyncClient


@dataclass(frozen=True)
class Exchange:
    """One request and the verified response to it, as sent and received."""

    #: The request as sent, which the response is bound to. A bearer token is left out.
    request: HTTPRequest
    status: int
    #: The response's header lines as received, in order and with their own case.
    headers: list[tuple[str, str]]
    body: bytes
    verified: VerifiedResponse
    #: The key that signed the request, or None for a bearer request.
    keyid: str | None


def _lines(headers: httpx.Headers) -> list[tuple[str, str]]:
    """Header lines exactly as sent or received: `raw` keeps each name's case."""
    return [(k.decode("latin-1"), v.decode("latin-1")) for k, v in headers.raw]


async def call_seller(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    seller_origin: str,
    resolver: KeyResolver,
    signer: RequestSigner | None,
    token: str | None = None,
    body: bytes = b"",
) -> Exchange:
    """Sends one request to the seller and verifies the signed response; raises `WebBotAuthError`.

    With `signer`, the request is signed with Web Bot Auth; without it, it carries `token`.
    """
    headers = {"Content-Type": "application/json"} if body else {}
    verifier = ResponseVerifier(resolver)
    if signer is not None:
        # Signs the request, then verifies the response and its binding to it.
        auth = WebBotAuth(signer, verifier, expect=Origin.parse(seller_origin))
    else:
        if token is None:
            raise ValueError(f"no bearer token is configured for {seller_origin}")
        headers["Authorization"] = f"Bearer {token}"
        # Sends the request unsigned, and still verifies the seller's signed answer.
        auth = WebBotAuth.verify_only(verifier, expect=Origin.parse(seller_origin))
    response = await client.request(method, url, content=body, headers=headers, auth=auth)
    verified = verified_response(response)
    if verified is None:  # the auth refuses an unsigned answer, so this can't happen
        raise WebBotAuthError(Refusal.SIGNATURE_MISSING, "the answer carries no verified signature")
    sent = [(k, v) for k, v in _lines(response.request.headers) if k.lower() != "authorization"]
    return Exchange(
        request=HTTPRequest(method, url, sent, body),
        status=response.status_code,
        headers=_lines(response.headers),
        body=response.content,
        verified=verified,
        keyid=signer.key.thumbprint if signer else None,
    )


async def call_signed(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    signer: RequestSigner,
    body: bytes = b"",
) -> httpx.Response:
    """A signed request to a peer that doesn't sign its responses, such as cfbot."""
    headers = {"Content-Type": "application/json"} if body else {}
    return await client.request(method, url, content=body, headers=headers, auth=WebBotAuth(signer))
