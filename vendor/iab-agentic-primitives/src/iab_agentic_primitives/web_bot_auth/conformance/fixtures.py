"""The fixed world of the conformance vectors: seeds, keys, origins, clock, and bodies.

Every key comes from a published seed and every nonce from a seeded byte
stream, so the generator writes the same bytes on every run.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric import ec

from ..keys import Ed25519Key
from ..values import DIRECTORY_PATH, UnixSeconds, b64url_encode

#: The fixed clock: 2026-11-07T12:00:00Z.
T0 = UnixSeconds(1794052800)
SEED_PREFIX = "aamp-wba-test/"


def at(offset: int) -> UnixSeconds:
    """The instant ``offset`` seconds after the fixed clock."""
    return UnixSeconds(T0 + offset)


BUYER = "https://buyer.example.com"
SELLER = "https://seller.example.com"
OTHER = "https://other.example.com"
SELLER_AUTHORITY = "seller.example.com"
COMMIT_URL = f"{SELLER}/proposals/prop_7/commit"
BUYER_KEYS = f"{BUYER}{DIRECTORY_PATH}"
SELLER_KEYS = f"{SELLER}{DIRECTORY_PATH}"
OTHER_KEYS = f"{OTHER}{DIRECTORY_PATH}"
#: The specification the vectors grade.
SPEC = "OpenProposal 3.0 § 2.8"
#: Where the profile's rules are stated; each vector links a heading.
DOC_URL = "https://github.com/IABTechLab/iab-agentic-primitives/blob/main/WEB_BOT_AUTH.md"
JSON = {"Content-Type": "application/json"}

KEY_SPECS = (
    ("buyer-request", BUYER),
    ("other-request", OTHER),
    ("seller-response", SELLER),
)


def seed(name: str) -> bytes:
    return hashlib.sha256(f"{SEED_PREFIX}{name}".encode()).digest()


def key(name: str) -> Ed25519Key:
    return Ed25519Key.from_seed(seed(name))


def byte_stream(name: str) -> Callable[[int], bytes]:
    """A deterministic source of bytes for nonces, one stream per name."""
    counter = 0

    def take(n: int) -> bytes:
        nonlocal counter
        out = b""
        while len(out) < n:
            out += hashlib.sha512(f"{SEED_PREFIX}nonce/{name}/{counter}".encode()).digest()
            counter += 1
        return out[:n]

    return take


def nonce(stream: str) -> str:
    """The first 64 bytes of the stream ``stream``, as unpadded base64url."""
    return b64url_encode(byte_stream(stream)(64))


def compact(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


RECORD_DIGEST = "sha256:" + hashlib.sha256(f"{SEED_PREFIX}record".encode()).hexdigest()
COMMITMENT_ENTRY = {
    "role": "commitment",
    "version": 3,
    "record_digest": RECORD_DIGEST,
    "line_item_ids": ["li_1"],
    "at": "2026-11-07T12:00:00Z",
    "idempotency_key": "ba1fd8f3-d695-4e8d-8629-ee4073b4f184",  # gitleaks:allow
}
COMMIT = {
    "entry": COMMITMENT_ENTRY,
    "writes": {
        "li_1": {
            "commitment": {
                "flight": {"start": "2026-12-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"}
            }
        }
    },
}
ACCEPTANCE_ENTRY = {
    "role": "acceptance",
    "version": 3,
    "record_digest": RECORD_DIGEST,
    "line_item_ids": ["li_1"],
    "at": "2026-11-07T12:00:01Z",
}
COMMIT_BODY = compact(COMMIT)
COMMIT_RESULT_BODY = compact({"entries": [COMMITMENT_ENTRY, ACCEPTANCE_ENTRY]})


def p256_public_jwk() -> dict[str, str]:
    """A P-256 public JWK that the profile doesn't use, for the directory scenarios."""
    private = ec.derive_private_key(int.from_bytes(seed("p256-unused"), "big"), ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    x = b64url_encode(numbers.x.to_bytes(32, "big"))
    y = b64url_encode(numbers.y.to_bytes(32, "big"))
    canonical = json.dumps({"crv": "P-256", "kty": "EC", "x": x, "y": y}, separators=(",", ":"))
    kid = b64url_encode(hashlib.sha256(canonical.encode()).digest())
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "use": "sig"}


__all__ = [
    "ACCEPTANCE_ENTRY",
    "BUYER",
    "BUYER_KEYS",
    "COMMIT",
    "COMMITMENT_ENTRY",
    "COMMIT_BODY",
    "COMMIT_RESULT_BODY",
    "COMMIT_URL",
    "DOC_URL",
    "JSON",
    "KEY_SPECS",
    "OTHER",
    "OTHER_KEYS",
    "RECORD_DIGEST",
    "SEED_PREFIX",
    "SELLER",
    "SELLER_AUTHORITY",
    "SELLER_KEYS",
    "SPEC",
    "T0",
    "at",
    "byte_stream",
    "compact",
    "key",
    "nonce",
    "p256_public_jwk",
    "seed",
]
