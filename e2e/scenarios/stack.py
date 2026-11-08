"""What every scenario uses: the stack's settings, its addresses, and a signer that holds
the buyer's key.

The scenarios observe the stack from inside its network, as the live runner
does, so they read the runner's settings (runner/settings.py): the agents'
origins, their controls, both parties' databases, and each agent's own operator
key. With the same readers (shared/settings.py) they read what only they use:
cfbot's controls and key, the buyer's key directory, the bearer token, and the
timing the agents run with. e2e/docker-compose.yml passes the scenarios service
the values the agents run with, so no scenario restates a value the stack
configures.

The scenarios service reads the buyer's key volume and both parties' database
volumes from read-only mounts. Holding the buyer's key lets a scenario send
what the buyer never would: a tampered body, a replay, a key the directory
doesn't list. It reads each party's records through their read models
(persistence/observe.py), never with its own SQL.
"""

from __future__ import annotations

import json
import uuid

import httpx
from iab_agentic_primitives.web_bot_auth import Ed25519Key, HTTPRequest, RequestSigner

from persistence.observe import KeptPrincipal, SellerRecords
from persistence.values import Origin
from runner.settings import RunnerSettings
from shared import settings as read
from shared.keyring import KeyStore, rotation_wait
from transport.client import ControlClient

RUNNER = RunnerSettings.from_env()
_ENV = read.environment(None)

SELLER = str(RUNNER.peer_seller_origin)
BUYER = str(RUNNER.peer_buyer_origin)
CFBOT = str(RUNNER.peer_cfbot_origin)

#: Each agent's own controls, inside the network.
SELLER_CONTROL = RUNNER.seller_control
BUYER_CONTROL = RUNNER.buyer_control
CFBOT_CONTROL = read.url(_ENV, "CFBOT_CONTROL", "http://cfbot:8000")
#: What each agent's own controls require (transport/operator.py), one key per party, by
#: the host its controls answer on.
OPERATOR_KEYS = {
    SELLER_CONTROL.host: RUNNER.seller_operator_key,
    BUYER_CONTROL.host: RUNNER.buyer_operator_key,
    CFBOT_CONTROL.host: read.required_secret(_ENV, "CFBOT_OPERATOR_KEY"),
}

#: Both parties' databases, and the buyer's key directory, mounted read-only.
SELLER_DB = RUNNER.seller_db
BUYER_DB = RUNNER.buyer_db
BUYER_KEYS = read.path(_ENV, "BUYER_KEYS_DIR", "/buyer-keys")

#: The token the seller issued its buyer, beside the origin it knows the buyer by.
BEARER_TOKEN = read.required_secret(_ENV, "DEMO_BEARER_TOKEN").get_secret_value()

# The timing the agents run with, with the agents' own defaults.
#: How long the seller answers from a cached buyer directory (`WBA_MAX_CACHE_AGE`).
MAX_CACHE_AGE = read.integer(_ENV, "WBA_MAX_CACHE_AGE", 300)
#: How long a published buyer key waits before it may sign: derived, as the buyer derives
#: it, from its directory's max-age (`WBA_DIRECTORY_MAX_AGE`).
ROTATION_WAIT = rotation_wait(read.integer(_ENV, "WBA_DIRECTORY_MAX_AGE", 300))
#: How long the buyer's signatures last (`WBA_SIGNATURE_LIFETIME`).
SIGNATURE_LIFETIME = read.integer(_ENV, "WBA_SIGNATURE_LIFETIME", 300)


def buyer_principal(records: SellerRecords) -> KeptPrincipal:
    """The buyer's one principal in the seller's records, found as an observer finds it: by
    the credential that points at it, the buyer's origin."""
    principal = records.principal_with_origin(Origin.parse(BUYER))
    assert principal is not None, f"the seller has no principal for {BUYER}"
    return principal


def control(web: httpx.Client, base: httpx.URL) -> ControlClient:
    """One agent's controls, reached inside the network over plain http, with its own
    operator key."""
    return ControlClient(web, base, OPERATOR_KEYS[base.host])


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
    return dict(RequestSigner.of(key or buyer_key(), origin).sign(request).headers.items())


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
