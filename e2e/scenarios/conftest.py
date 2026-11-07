"""What every scenario uses.

The stack's addresses, a signer that holds the buyer's key, and each party's records.

The runner reads the buyer's key files and both databases from read-only
volume mounts. Holding the buyer's key lets a scenario send what the buyer
never would: a tampered body, a replay, a key the directory doesn't list.
"""

from __future__ import annotations

import json
import sqlite3
import ssl
import uuid
from pathlib import Path

import httpx
import pytest
from iab_agentic_primitives.web_bot_auth import (
    Ed25519Key,
    HTTPRequest,
    Origin,
    RequestSigner,
    StaticKeyResolver,
    parse_directory_response,
)
from settings import BUYER, CFBOT, OPERATOR_KEY, SELLER

from shared.keyring import Keyring

__all__ = ["BUYER", "CFBOT", "SELLER"]  # the stack's addresses, re-exported for the scenarios
# Operator and test controls, reached inside the network, not through the TLS front.
BUYER_OPERATOR = "http://buyer:8000/operator"
SELLER_FAULTS = "http://seller:8000/test/fault"
CFBOT_RUN = "http://cfbot:8000/run"

#: The buyer's keyring, read through its own API from a read-only mount. The waits
#: only govern rotation steps, which the scenarios ask the buyer for, never this copy.
BUYER_KEYS = Keyring(Path("/buyer-data/keys"), rotation_wait=0, signature_lifetime=0)


def buyer_key(kid: str | None = None) -> Ed25519Key:
    """The buyer's active key, or its key `kid`, published or retired (shared/keyring.py)."""
    return BUYER_KEYS.active() if kid is None else BUYER_KEYS.key(kid, include_retired=True)


def signed(
    method: str, url: str, body: bytes = b"", *, key: Ed25519Key | None = None, origin: str = BUYER
) -> dict[str, str]:
    """Headers for a request signed as `origin` with `key` (by default, the buyer's active key)."""
    headers = {"Content-Type": "application/json"} if body else {}
    request = HTTPRequest(method, url, headers, body)
    return dict(RequestSigner(key or buyer_key(), origin).sign(request).headers.items())


def commit_body(amount: float) -> bytes:
    """A well-formed Commit on demo-wba-2's weather-app-ctv, which the buyer would never send."""
    return json.dumps(
        {
            "entry": {
                "role": "commitment",
                "version": 1,
                "record_digest": "sha256:" + "0" * 64,
                "line_item_ids": ["weather-app-ctv"],
                "at": "2029-01-01T00:00:00Z",
                "idempotency_key": str(uuid.uuid4()),
            },
            "writes": {
                "weather-app-ctv": {
                    "commitment": {
                        "basis": "spend",
                        "amount": amount,
                        "advertisers": [{"domain": "brand-a.example"}],
                        "flight": {"start": "2029-11-02T00:00:00Z", "end": "2029-12-21T23:59:59Z"},
                    }
                }
            },
        }
    ).encode()


def _operator_key(request: httpx.Request) -> None:
    """Adds the operator key to the agents' controls, which the runner reaches over plain http."""
    if request.url.scheme == "http":
        request.headers["X-Operator-Key"] = OPERATOR_KEY


@pytest.fixture
def web():
    """A client that trusts the public roots plus the demo CA, as every container does."""
    with httpx.Client(
        verify=ssl.create_default_context(), timeout=30, event_hooks={"request": [_operator_key]}
    ) as client:
        yield client


def stored_keys(db: sqlite3.Connection, digest: str, origin: str) -> StaticKeyResolver:
    """The keys of a stored directory, after the library verifies the stored bytes again."""
    row = db.execute("SELECT * FROM directories WHERE digest = ?", (digest,)).fetchone()
    headers = [tuple(line) for line in json.loads(row["headers"])]
    directory = parse_directory_response(
        row["status"], headers, row["body"], Origin.parse(origin).host, int(row["fetched_at"])
    )
    return StaticKeyResolver({origin: list(directory.values())})


def database(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


@pytest.fixture
def seller_db():
    db = database("/seller-data/seller.db")
    yield db
    db.close()


@pytest.fixture
def buyer_db():
    db = database("/buyer-data/buyer.db")
    yield db
    db.close()
