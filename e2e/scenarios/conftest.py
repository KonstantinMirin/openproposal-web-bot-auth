"""What every scenario uses: the stack's addresses, a signer that holds the buyer's key, and each party's records.

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
    RequestSigner,
    StaticKeyResolver,
    parse_directory_response,
)

SELLER = "https://seller.wba-demo.noetis.dev"
BUYER = "https://buyer.wba-demo.noetis.dev"
CFBOT = "https://cfbot.wba-demo.noetis.dev"
# Operator and test controls, reached inside the network, not through the TLS front.
BUYER_OPERATOR = "http://buyer:8000/operator"
SELLER_FAULTS = "http://seller:8000/test/fault"
CFBOT_RUN = "http://cfbot:8000/run"

BUYER_KEYS = Path("/buyer-data/keys")


def active_key_file() -> str:
    """The file name of the buyer's active key (buyer/keyring.py)."""
    return json.loads((BUYER_KEYS / "state.json").read_text())["active"]


def buyer_key(name: str | None = None) -> Ed25519Key:
    """The buyer's active key, or the key file `name` (published or retired)."""
    if name is None:
        return Ed25519Key.load_or_create(BUYER_KEYS / active_key_file())
    path = BUYER_KEYS / name
    return Ed25519Key.load_or_create(path if path.exists() else BUYER_KEYS / "retired" / name)


def signed(method: str, url: str, body: bytes = b"", *, key: Ed25519Key | None = None,
           origin: str = BUYER) -> dict[str, str]:
    """Headers for a request signed as `origin` with `key` (by default, the buyer's active key)."""
    headers = {"Content-Type": "application/json"} if body else {}
    return headers | RequestSigner(key or buyer_key(), origin).sign(method, url, headers, body)


def commit_body(amount: float) -> bytes:
    """A well-formed Commit on demo-wba-2's weather-app-ctv, for requests the buyer would never send."""
    return json.dumps({
        "entry": {"role": "commitment", "version": 1, "record_digest": "sha256:" + "0" * 64,
                  "line_item_ids": ["weather-app-ctv"], "at": "2029-01-01T00:00:00Z",
                  "idempotency_key": str(uuid.uuid4())},
        "writes": {"weather-app-ctv": {"commitment": {
            "basis": "spend", "amount": amount, "advertisers": [{"domain": "brand-a.example"}],
            "flight": {"start": "2029-11-02T00:00:00Z", "end": "2029-12-21T23:59:59Z"}}}},
    }).encode()


@pytest.fixture
def web():
    """A client that trusts the public roots plus the demo CA, as every container does."""
    with httpx.Client(verify=ssl.create_default_context(), timeout=30) as client:
        yield client


def stored_keys(db: sqlite3.Connection, digest: str, origin: str) -> StaticKeyResolver:
    """The keys of a stored directory, after the library verifies the stored bytes again."""
    row = db.execute("SELECT * FROM directories WHERE digest = ?", (digest,)).fetchone()
    headers = [tuple(line) for line in json.loads(row["headers"])]
    directory = parse_directory_response(row["status"], headers, row["body"],
                                         origin.removeprefix("https://"), int(row["fetched_at"]))
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
