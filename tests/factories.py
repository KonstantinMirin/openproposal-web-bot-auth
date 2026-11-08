"""The one test module that builds identity values (seller/caller.py) directly.

Everything else gets a caller from the identity boundary, through the app.
Each builder takes the fields to set, so a test can also ask for a value the
types must refuse.
"""

from __future__ import annotations

from seller.caller import (
    BearerCredential,
    Principal,
    PublicCaller,
    ResolvedCaller,
    SignatureCredential,
    SignedMessage,
)


def principal(**fields: object) -> Principal:
    values: dict[str, object] = {
        "id": "buyer-wba",
        "kind": "buyer",
        "legal_name": "Demo Buyer Agency LLC",
        "domain": "buyer.example",
    }
    return Principal.model_validate(values | fields)


def signed_message() -> SignedMessage:
    return SignedMessage(
        method="GET", url="https://seller.example/whoami", headers=(), body=b"", directory=None
    )


def signature_credential(**fields: object) -> SignatureCredential:
    values: dict[str, object] = {
        "method": "web_bot_auth",
        "origin": "https://buyer.example",
        "keyid": "kid-1",
        "body_covered": False,
        "message": signed_message(),
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
