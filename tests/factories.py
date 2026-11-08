"""The one test module that builds identity values (seller/caller.py) directly.

Everything else gets a caller from the identity boundary, through the app. The
ast-grep rule identity-built-only-by-the-boundary exempts this file and
seller/boundary.py only. Each builder takes the fields to set, so a test can
also ask for a value the types must refuse.
"""

from __future__ import annotations

from persistence.values import KeptRequest
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


def kept_request() -> KeptRequest:
    return KeptRequest(method="GET", url="https://seller.example/whoami", lines=(), body=b"")


def signature_credential(**fields: object) -> SignatureCredential:
    values: dict[str, object] = {
        "method": "web_bot_auth",
        "origin": "https://buyer.example",
        "keyid": "kid-1",
        "body_covered": False,
        "request": kept_request(),
        "directory": None,
    }
    return SignatureCredential.model_validate(values | fields)


def bearer_credential(**fields: object) -> BearerCredential:
    return BearerCredential.model_validate({"method": "bearer"} | fields)


def resolved_caller(**fields: object) -> ResolvedCaller:
    values: dict[str, object] = {
        "principal": principal(),
        "credential": signature_credential(),
        "attributed": False,
    }
    return ResolvedCaller.model_validate(values | fields)


def public_caller(**fields: object) -> PublicCaller:
    return PublicCaller.model_validate(fields)
