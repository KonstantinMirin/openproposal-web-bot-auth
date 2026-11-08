"""What every scenario uses.

The stack's addresses, each agent's controls (`ControlClient`, with that
agent's own operator key), a signer that holds the buyer's key, and each
party's records.

The scenarios service (e2e/docker-compose.yml) reads the buyer's key volume and
both parties' database volumes from read-only mounts. Holding the buyer's key
lets a scenario send what the buyer never would: a tampered body, a replay, a
key the directory doesn't list. It reads each party's records through their
read models (persistence/observe.py), never with its own SQL.
"""

from __future__ import annotations

import json
import ssl
import uuid
from collections.abc import Iterator

import httpx
import pytest
from iab_agentic_primitives.web_bot_auth import Ed25519Key, HTTPRequest, RequestSigner
from settings import (
    BUYER,
    BUYER_CONTROL,
    BUYER_DB,
    BUYER_KEYS,
    CFBOT,
    CFBOT_CONTROL,
    OPERATOR_KEYS,
    SELLER,
    SELLER_CONTROL,
    SELLER_DB,
)

from persistence.observe import BuyerRecords, SellerRecords
from shared.keyring import KeyStore
from transport.client import ControlClient

__all__ = ["BUYER", "CFBOT", "SELLER"]  # the stack's addresses, re-exported for the scenarios


def buyer_key(kid: str | None = None) -> Ed25519Key:
    """The buyer's active key, or its key `kid`, published or retired, as its key directory
    holds them now. The read-only store reads them (shared/keyring.py) and never writes."""
    keys = KeyStore.open(BUYER_KEYS)
    return keys.active() if kid is None else keys.key(kid, include_retired=True)


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


@pytest.fixture
def web() -> Iterator[httpx.Client]:
    """A client that trusts the public roots plus the demo CA, as every container does."""
    with httpx.Client(verify=ssl.create_default_context(), timeout=30) as client:
        yield client


def control(web: httpx.Client, base: httpx.URL) -> ControlClient:
    """One agent's controls, reached inside the network over plain http, with its own
    operator key."""
    return ControlClient(web, base, OPERATOR_KEYS[base.host])


@pytest.fixture
def seller_control(web: httpx.Client) -> ControlClient:
    return control(web, SELLER_CONTROL)


@pytest.fixture
def buyer_control(web: httpx.Client) -> ControlClient:
    return control(web, BUYER_CONTROL)


@pytest.fixture
def cfbot_control(web: httpx.Client) -> ControlClient:
    return control(web, CFBOT_CONTROL)


@pytest.fixture
def seller_records() -> Iterator[SellerRecords]:
    """The seller's records, read-only."""
    with SellerRecords.open(SELLER_DB) as records:
        yield records


@pytest.fixture
def buyer_records() -> Iterator[BuyerRecords]:
    """The buyer's records, read-only."""
    with BuyerRecords.open(BUYER_DB) as records:
        yield records
