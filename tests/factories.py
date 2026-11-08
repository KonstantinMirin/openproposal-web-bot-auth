"""The one test module that builds identity values (seller/caller.py) directly.

Everything else gets a caller from the identity boundary, through the app. The
ast-grep rule identity-built-only-by-the-boundary exempts this file and
seller/boundary.py only. Each builder takes the fields to set, so a test can
also ask for a value the types must refuse.
"""

from __future__ import annotations

from persistence.values import KeptRequest, Provenance, SignedRequest, Signer
from seller.caller import (
    BearerCredential,
    Principal,
    PublicCaller,
    ResolvedCaller,
    SignatureCredential,
)


def principal(**fields: object) -> Principal:
    values: dict[str, object] = {
        "id": "buyer-wba",
        "kind": "buyer",
        "legal_name": "Demo Buyer Agency LLC",
        "domain": "buyer.example",
    }
    return Principal.model_validate(values | fields)


def signed_request() -> SignedRequest:
    request = KeptRequest(method="GET", url="https://seller.example/whoami", lines=(), body=b"")
    signer = Signer.model_validate({"origin": "https://buyer.example", "keyid": "kid-1"})
    return SignedRequest(request=request, signer=signer)


def provenance(**fields: object) -> Provenance:
    values: dict[str, object] = {
        "principal_id": "buyer-wba",
        "method": "web_bot_auth",
        "attributed": False,
        "signed": signed_request(),
    }
    return Provenance.model_validate(values | fields)


def signature_credential(**fields: object) -> SignatureCredential:
    values: dict[str, object] = {
        "method": "web_bot_auth",
        "origin": "https://buyer.example",
        "keyid": "kid-1",
        "body_covered": False,
    }
    return SignatureCredential.model_validate(values | fields)


def bearer_credential(**fields: object) -> BearerCredential:
    return BearerCredential.model_validate({"method": "bearer"} | fields)


def resolved_caller(**fields: object) -> ResolvedCaller:
    values: dict[str, object] = {
        "principal": principal(),
        "credential": signature_credential(),
        "attributed": False,
        "provenance": provenance(),
    }
    return ResolvedCaller.model_validate(values | fields)


def public_caller(**fields: object) -> PublicCaller:
    return PublicCaller.model_validate(fields)
