"""How the buyer authenticates a request to a seller, and verifies the answer: one factory.

A request carries exactly one credential. `SignWith` holds the signer of the
buyer's active key; `Bearer` holds the token the seller issued. Neither builds
an auth: `seller_call` does, and it is the only builder of one for a seller.
It requires the response verifier and the seller's origin, so every call to a
seller verifies the signed answer against that origin and, for a signed
request, its binding to the request. The credential adds only what it carries:
the signer, or the token's header.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import httpx
from iab_agentic_primitives.web_bot_auth import RequestSigner, ResponseVerifier
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth
from pydantic import SecretStr

from persistence.values import BearerMethod, Origin, SignatureMethod
from transport.wba import library_origin


@dataclass(frozen=True)
class SignWith:
    """A Web Bot Auth signature, by the buyer's active key."""

    signer: RequestSigner
    method: SignatureMethod = "web_bot_auth"

    @property
    def keyid(self) -> str:
        return self.signer.key.thumbprint


@dataclass(frozen=True)
class Bearer:
    """The token the seller issued this buyer."""

    token: SecretStr = field(repr=False)
    method: BearerMethod = "bearer"

    @property
    def keyid(self) -> None:
        return None


#: The one credential a request carries.
BuyerCredential = SignWith | Bearer


@dataclass(frozen=True)
class SellerCall:
    """How one request to a seller goes out: the auth, and the header lines the credential
    adds."""

    #: Signs the request with a signature credential; always verifies the signed answer.
    auth: httpx.Auth
    headers: Mapping[str, str]


def seller_call(
    credential: BuyerCredential, verifier: ResponseVerifier, seller: Origin
) -> SellerCall:
    """The auth and headers of a request to `seller`: the answer must carry `seller`'s
    verified signature, bound to the request when the request is signed."""
    if isinstance(credential, SignWith):
        signer, headers = credential.signer, {}
    else:
        signer = None
        headers = {"Authorization": f"Bearer {credential.token.get_secret_value()}"}
    auth = WebBotAuth(signer, verifier, expect=library_origin(seller))
    return SellerCall(auth, headers)
