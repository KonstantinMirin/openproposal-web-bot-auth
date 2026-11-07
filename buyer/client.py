"""How the buyer calls a seller, and how it confirms who answered.

The request carries one credential: a Web Bot Auth signature, through the
library's `WebBotAuth`, or the bearer token the seller issued. Either way the
seller signs its response, and the buyer verifies that signature and, for a
signed request, its binding to the request. A response that fails is refused.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import httpx
from iab_agentic_primitives.web_bot_auth import (
    DirectoryResolver,
    RequestSigner,
    ResponseVerifier,
    VerifiedSignature,
)
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth

from shared.wba import http_client

Credential = Literal["web_bot_auth", "bearer"]


@dataclass(frozen=True)
class Exchange:
    """One request and the verified response to it, as sent and received."""

    method: str
    url: str
    request_headers: list[tuple[str, str]]
    request_body: bytes
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    verified: VerifiedSignature
    #: The key that signed the request, or None for a bearer request.
    keyid: str | None

    def request_record(self) -> tuple[str, str, list[tuple[str, str]], bytes]:
        """The request as sent, which the response is bound to. A bearer token is left out."""
        headers = [(k, v) for k, v in self.request_headers if k.lower() != "authorization"]
        return self.method, self.url, headers, self.request_body


async def call_seller(
    method: str,
    url: str,
    *,
    seller_origin: str,
    resolver: DirectoryResolver,
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
        auth = WebBotAuth(signer, verifier, expected_origin=seller_origin)
    else:
        if token is None:
            raise ValueError(f"no bearer token is configured for {seller_origin}")
        headers["Authorization"] = f"Bearer {token}"
        # Sends the request unsigned, and still verifies the seller's signed answer.
        auth = WebBotAuth.verify_only(verifier, expected_origin=seller_origin)
    async with http_client() as client:
        response = await client.request(method, url, content=body, headers=headers, auth=auth)
    verified = response.extensions["web_bot_auth"]
    return Exchange(
        method=method,
        url=url,
        request_headers=response.request.headers.multi_items(),
        request_body=body,
        status=response.status_code,
        headers=response.headers.multi_items(),
        body=response.content,
        verified=verified,
        keyid=signer.key.kid if signer else None,
    )


async def call_signed(
    method: str,
    url: str,
    *,
    signer: RequestSigner,
    body: bytes = b"",
) -> httpx.Response:
    """A signed request to a peer that doesn't sign its responses, such as cfbot."""
    headers = {"Content-Type": "application/json"} if body else {}
    async with http_client() as client:
        return await client.request(
            method, url, content=body, headers=headers, auth=WebBotAuth(signer)
        )
