"""The identity boundary, through the seller app: every credential, refused or resolved.

Each test builds the seller with `create_app` over a real SQLite file, the
library's real verifier, and its real `DirectoryResolver`, fetching the buyer's
signed directory from an in-process transport. A request goes in through the
app's ASGI interface; what comes out is the answer and the rows the seller
kept.

- One table covers every presented credential. A credential that fails is
  refused with its status, reason, and hint; none of them comes back as a
  public caller.
- The boundary writes nothing. Only a commit that writes an entry keeps the
  signed request, with its header lines as received, in the same transaction.
- The offer logic is credential-blind: the same principal committing the same
  commit by signature and by token gets the same result.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    Ed25519Key,
    KeyResolver,
    NonceStore,
    NonceStoreUnavailable,
    accept_signature,
)
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from pydantic import SecretStr
from starlette.types import ASGIApp

from persistence.observe import KeptEntry, SellerRecords
from persistence.values import Origin
from protocol.operations import parse_errors
from protocol.values import JsonObject, read_json
from seller.caller import WHOAMI, BearerCredential, ResolvedView
from seller.seed import onboard
from seller.sqlite_store import SqliteSellerStore
from tests._tools import commit_body, seed_issuer
from tests.stack import (
    ELSEWHERE,
    TOKEN,
    Directories,
    Recorder,
    seller_app,
    seller_settings,
    signed_headers,
)
from transport.control import ErrorBody

#: The seller alone, and the buyer it deals with, under origins other than the demo's. The
#: buyer's is under a public suffix, so a signature can attribute an entry to it (§ 4.1.2).
SELLER, BUYER = str(ELSEWHERE.seller), str(ELSEWHERE.buyer)
#: An origin that publishes a directory, and that the seller has no principal for.
STRANGER = "https://stranger.example.com"
#: The line item the buyer commits to.
DISPLAY = "business-daily-display"


@dataclass(frozen=True)
class Parties:
    """The signing keys of the buyer and the stranger, each published in its directory."""

    buyer: Ed25519Key
    stranger: Ed25519Key

    def resolver(self) -> KeyResolver:
        """The library's resolver, fetching each origin's signed directory in process."""
        published = {
            Origin.parse(BUYER).host: self.buyer,
            Origin.parse(STRANGER).host: self.stranger,
        }
        return Directories(published).resolver()


@pytest.fixture
def parties() -> Parties:
    return Parties(Ed25519Key.generate(), Ed25519Key.generate())


def _app(data_dir: Path, parties: Parties, nonces: NonceStore | None = None) -> ASGIApp:
    settings = seller_settings(data_dir, origins=ELSEWHERE)
    return seller_app(settings, resolver=parties.resolver(), nonces=nonces)


@pytest.fixture
def seller(tmp_path: Path, parties: Parties) -> Iterator[TestClient]:
    with TestClient(_app(tmp_path, parties), base_url=SELLER) as client:
        yield client


def signed(
    method: str, path: str, key: Ed25519Key, *, origin: str = BUYER, body: bytes = b""
) -> dict[str, str]:
    """Headers for a request to the seller's `path`, signed as `origin` with `key`."""
    return signed_headers(method, f"{SELLER}{path}", key, origin=origin, body=body)


def _kept(data_dir: Path) -> tuple[int, int]:
    """How many signed requests and directory fetches the seller kept."""
    with SellerRecords.open(data_dir / "seller.db") as seller:
        requests = sum(seller.requests_from(Origin.parse(o)) for o in (BUYER, STRANGER))
        return requests, seller.directories()


class DownNonceStore:
    """A shared nonce store that is down: it can't record any nonce."""

    async def check_and_record(self, origin: LibraryOrigin, nonce: str, ttl: int) -> bool:
        detail = f"can't record {nonce} for {origin} ({ttl} s)"
        raise NonceStoreUnavailable(detail)


# ── Every presented credential ────────────────────────────────────────────

Headers = Callable[[Parties], dict[str, str]]


@dataclass(frozen=True)
class Refusing:
    """A credential the boundary refuses, and how: the status, the reason, and the hint
    headers the refusal carries (name -> value, or None for a header that must be absent)."""

    name: str
    headers: Headers
    status: int
    reason: str
    hint: dict[str, str | None]


REFUSALS = [
    Refusing(
        "an unknown token",
        lambda _: {"Authorization": "Bearer not-a-token"},
        401,
        "invalid-token",
        {"WWW-Authenticate": 'Bearer error="invalid_token"'},
    ),
    Refusing(
        "Basic x",
        lambda _: {"Authorization": "Basic x"},
        401,
        "invalid-authorization",
        {"WWW-Authenticate": 'Bearer error="invalid_request"'},
    ),
    Refusing(
        "an empty Bearer token",
        lambda _: {"Authorization": "Bearer "},
        401,
        "invalid-authorization",
        {"WWW-Authenticate": 'Bearer error="invalid_request"'},
    ),
    Refusing(
        "a signature and a token",
        lambda p: signed("GET", "/whoami", p.buyer) | {"Authorization": f"Bearer {TOKEN}"},
        400,
        "two-credentials",
        {"Accept-Signature": None, "Retry-After": None},
    ),
    Refusing(
        "a signature that doesn't parse (400)",
        lambda _: {"Signature-Input": "garbage(", "Signature": "sig1=:AAAA:"},
        400,
        "parse",
        {"Accept-Signature": None, "Retry-After": None},
    ),
    Refusing(
        "a key the buyer's directory doesn't list (403)",
        lambda _: signed("GET", "/whoami", Ed25519Key.generate()),
        403,
        "key-not-found",
        {"Accept-Signature": accept_signature(has_body=False), "Retry-After": None},
    ),
]


@pytest.mark.parametrize("row", REFUSALS, ids=lambda row: row.name)
def test_a_failing_credential_is_refused_never_downgraded(
    seller: TestClient, parties: Parties, row: Refusing
) -> None:
    response = seller.get("/whoami", headers=row.headers(parties))
    assert response.status_code == row.status
    # The library's refusal body, whose error is its reason or the boundary's own.
    assert ErrorBody.model_validate_json(response.content).code == row.reason
    assert {name: response.headers.get(name) for name in row.hint} == row.hint


def test_a_replayed_signature_is_refused_with_429_and_asked_to_sign_again(
    seller: TestClient, parties: Parties
) -> None:
    headers = signed("GET", "/whoami", parties.buyer)
    assert WHOAMI.validate_json(seller.get("/whoami", headers=headers).content).kind == "resolved"
    again = seller.get("/whoami", headers=headers)
    assert again.status_code == 429
    assert ErrorBody.model_validate_json(again.content).code == "nonce-replayed"
    assert again.headers["accept-signature"] == accept_signature(has_body=False)


def test_a_nonce_store_that_is_down_is_refused_with_503_and_retry_after(
    tmp_path: Path, parties: Parties
) -> None:
    with TestClient(_app(tmp_path, parties, DownNonceStore()), base_url=SELLER) as client:
        response = client.get("/whoami", headers=signed("GET", "/whoami", parties.buyer))
    assert response.status_code == 503
    assert ErrorBody.model_validate_json(response.content).code == "nonce-store-unavailable"
    assert response.headers["retry-after"] == "1"
    assert "accept-signature" not in response.headers


def test_no_credential_is_a_public_caller(seller: TestClient) -> None:
    assert seller.get("/whoami").json() == {"kind": "public", "signature": None}


def test_a_token_resolves_its_principal(seller: TestClient) -> None:
    response = seller.get("/whoami", headers={"Authorization": f"Bearer {TOKEN}"})
    caller = WHOAMI.validate_json(response.content)
    assert isinstance(caller, ResolvedView) and caller.principal.id == "buyer-bearer"
    assert isinstance(caller.credential, BearerCredential)  # no origin, no evidence
    assert caller.attributed is False


def test_a_verified_origin_with_a_principal_resolves_it(
    seller: TestClient, parties: Parties
) -> None:
    caller = seller.get("/whoami", headers=signed("GET", "/whoami", parties.buyer)).json()
    assert caller == {
        "kind": "resolved",
        "principal": {
            "id": "buyer-wba",
            "kind": "buyer",
            "legal_name": "Demo Buyer Agency LLC",
            "domain": ELSEWHERE.buyer.host,
        },
        "credential": {
            "method": "web_bot_auth",
            "origin": BUYER,
            "keyid": parties.buyer.thumbprint,
            "body_covered": False,
        },
        "attributed": False,  # a GET has no body to attribute
    }


def test_a_verified_origin_without_a_principal_is_public_and_writes_nothing(
    seller: TestClient, parties: Parties, tmp_path: Path
) -> None:
    """A signed request from an origin with a directory and no principal keeps nothing."""
    headers = signed("GET", "/whoami", parties.stranger, origin=STRANGER)
    assert seller.get("/whoami", headers=headers).json() == {
        "kind": "public",
        "signature": {
            "method": "web_bot_auth",
            "origin": STRANGER,
            "keyid": parties.stranger.thumbprint,
            "body_covered": False,
        },
    }
    assert (
        seller.get(
            "/proposals/demo-wba-1",
            headers=signed("GET", "/proposals/demo-wba-1", parties.stranger, origin=STRANGER),
        ).status_code
        == 404
    )
    assert _kept(tmp_path) == (0, 0)


# ── Evidence is kept with the entry, and only then ────────────────────────


def _issued(client: TestClient, headers: dict[str, str]) -> JsonObject:
    response = client.get("/proposals/demo-wba-1", headers=headers)
    assert response.status_code == 200, response.text
    return read_json(response.content)


def _assent(data_dir: Path) -> list[KeptEntry]:
    """The seller's assent log of demo-wba-1, as its read model reads it."""
    with SellerRecords.open(data_dir / "seller.db") as records:
        return records.entries("demo-wba-1")


def test_a_signed_commit_keeps_its_request_with_the_entry(parties: Parties, tmp_path: Path) -> None:
    path = "/proposals/demo-wba-1/commit"
    app = Recorder(_app(tmp_path, parties))
    with TestClient(app, base_url=SELLER) as seller:
        document = _issued(seller, signed("GET", "/proposals/demo-wba-1", parties.buyer))
        assert _kept(tmp_path)[0] == 0  # reading kept nothing

        body = commit_body(document, DISPLAY, key=str(uuid.uuid4()))
        headers = signed("POST", path, parties.buyer, body=body)
        answer = seller.post(path, content=body, headers=headers)
    assert answer.status_code == 200, answer.text

    commitment, acceptance = _assent(tmp_path)
    assert (commitment.principal_id, commitment.authentication_method) == (
        "buyer-wba",
        "web_bot_auth",
    )
    assert commitment.attributed is True  # the body is covered, and the host is the domain
    assert acceptance.evidence_id is None and acceptance.authentication_method is None
    assert commitment.evidence_id is not None
    with SellerRecords.open(tmp_path / "seller.db") as records:
        kept_request = records.request(commitment.evidence_id)
    kept, directory = kept_request.request, kept_request.signer.directory
    assert (kept.method, kept.url, kept.body) == ("POST", f"{SELLER}{path}", body)
    # The header lines exactly as the app received them: in order, in case, and every line.
    (received,) = [r for r in app.received if r.method == "POST"]
    assert list(kept.lines) == received.headers
    assert directory is not None and directory.url == f"{BUYER}{DIRECTORY_PATH}"


def test_a_rejected_commit_keeps_no_evidence(
    seller: TestClient, parties: Parties, tmp_path: Path
) -> None:
    path = "/proposals/demo-wba-1/commit"
    document = _issued(seller, signed("GET", "/proposals/demo-wba-1", parties.buyer))
    commit = json.loads(commit_body(document, DISPLAY))
    commit["entry"]["record_digest"] = "sha256:" + "0" * 64  # not the seller's record
    body = json.dumps(commit).encode()
    answer = seller.post(path, content=body, headers=signed("POST", path, parties.buyer, body=body))
    assert answer.status_code == 409
    assert [e.code for e in parse_errors(answer.content)] == ["record_mismatch"]
    with SellerRecords.open(tmp_path / "seller.db") as records:
        assert records.entries("demo-wba-1") == []
    assert _kept(tmp_path) == (0, 0)


# ── The offer logic is credential-blind ───────────────────────────────────


def _seeded_with_a_token_for_the_signing_buyer(data_dir: Path) -> None:
    """The first-boot records, plus a token for buyer-wba, so one principal has both."""
    data_dir.mkdir()
    store = SqliteSellerStore(data_dir / "seller.db")
    try:
        onboard(
            store, seed_issuer(), buyer_origin=Origin.parse(BUYER), bearer_token=SecretStr(TOKEN)
        )
        with store.transaction():
            store.set_token_credential("buyer-wba", "buyer-wba-token")
    finally:
        store.close()


def _without_acceptance_time(result: JsonObject) -> JsonObject:
    entries = result["entries"]
    assert isinstance(entries, list)
    return {
        **result,
        "entries": [
            {**e, "at": None} if e["role"] == "acceptance" else e
            for e in entries
            if isinstance(e, dict)
        ],
    }


def test_a_signature_and_a_token_get_the_same_result_for_the_same_commit(
    tmp_path: Path, parties: Parties
) -> None:
    """Differential: one principal, one document, one commit, two credentials."""
    path = "/proposals/demo-wba-1/commit"
    at, key = datetime.now(UTC), str(uuid.uuid4())
    by_token = {"Authorization": "Bearer buyer-wba-token"}
    results, rows = [], []
    for credential in ("signature", "token"):
        data_dir = tmp_path / credential
        _seeded_with_a_token_for_the_signing_buyer(data_dir)
        with TestClient(_app(data_dir, parties), base_url=SELLER) as client:
            read = signed("GET", "/proposals/demo-wba-1", parties.buyer)
            document = _issued(client, read if credential == "signature" else by_token)
            body = commit_body(document, DISPLAY, key=key, at=at)
            headers = (
                signed("POST", path, parties.buyer, body=body)
                if credential == "signature"
                else by_token | {"Content-Type": "application/json"}
            )
            answer = client.post(path, content=body, headers=headers)
            assert answer.status_code == 200, answer.text
            results.append(_without_acceptance_time(read_json(answer.content)))
        rows.append([(e.role, e.principal_id) for e in _assent(data_dir)])
    assert results[0] == results[1]
    assert rows[0] == rows[1] == [("commitment", "buyer-wba"), ("acceptance", None)]
    # Only the stored provenance differs.
    methods = [_assent(tmp_path / c)[0].authentication_method for c in ("signature", "token")]
    assert methods == ["web_bot_auth", "bearer"]
