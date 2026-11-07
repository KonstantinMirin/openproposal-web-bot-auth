"""How the buyer authenticates a request to a seller: one credential, as a type.

A request carries exactly one credential. `SignWith` signs it with Web Bot
Auth; `Bearer` carries the token the seller issued. Either way the seller signs
its answer, and the auth each credential builds verifies that signature against
the seller's origin, and, for a signed request, its binding to the request.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from iab_agentic_primitives.web_bot_auth import Origin, RequestSigner, ResponseVerifier
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth
from pydantic import SecretStr

from transport.auth import BearerMethod, SignatureMethod


@dataclass(frozen=True)
class SignWith:
    """A Web Bot Auth signature, by the buyer's active key."""

    signer: RequestSigner
    method: SignatureMethod = "web_bot_auth"

    @property
    def keyid(self) -> str:
        return self.signer.key.thumbprint

    def headers(self) -> dict[str, str]:
        return {}

    def auth(self, verifier: ResponseVerifier, seller: Origin) -> httpx.Auth:
        """Signs the request, then verifies the answer and its binding to the request."""
        return WebBotAuth(self.signer, verifier, expect=seller)


@dataclass(frozen=True)
class Bearer:
    """The token the seller issued this buyer."""

    token: SecretStr = field(repr=False)
    method: BearerMethod = "bearer"

    @property
    def keyid(self) -> None:
        return None

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token.get_secret_value()}"}

    def auth(self, verifier: ResponseVerifier, seller: Origin) -> httpx.Auth:
        """Sends the request unsigned, and still verifies the seller's signed answer."""
        return WebBotAuth.verify_only(verifier, expect=seller)


#: The one credential a request carries.
BuyerCredential = SignWith | Bearer
