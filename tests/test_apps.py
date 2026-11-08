"""Each agent's composition root: built from settings over tmp_path, never from /data.

The lifespan opens the store and the one client and closes both on shutdown,
and an agent that fails to start, on a CA bundle it can't read, leaves no store
open. The fault switch belongs to one app instance. The buyer's flow is in
tests/test_buyer.py.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    Ed25519Key,
    HTTPRequest,
    HTTPResponse,
    MemoryNonceStore,
    RequestSigner,
    ResponseVerifier,
    StaticKeyResolver,
    WebBotAuthError,
    keyfile,
)
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from iab_agentic_primitives.web_bot_auth.sync import SyncResponseVerifier
from starlette.types import ASGIApp

from buyer.app import create_app as create_buyer
from buyer.resources import BuyerResources
from buyer.settings import BuyerSettings
from persistence.values import Origin
from seller.app import create_app as create_seller
from seller.resources import SellerResources
from seller.settings import SellerSettings
from tests import stack
from tests.stack import BUYER_OPERATOR, SELLER_OPERATOR, TOKEN, Origins

SELLER = "https://seller.example"
BUYER = "https://buyer.example"
#: Each agent alone, under origins of its own.
EXAMPLE = Origins(seller=Origin.parse(SELLER), buyer=Origin.parse(BUYER))


def seller_settings(data_dir: Path, *, faults: bool = False) -> SellerSettings:
    return stack.seller_settings(data_dir, origins=EXAMPLE, faults=faults)


def buyer_settings(data_dir: Path) -> BuyerSettings:
    return stack.buyer_settings(data_dir, origins=EXAMPLE)


def seller_app(data_dir: Path, *, faults: bool = False, key: Ed25519Key | None = None) -> ASGIApp:
    keys: dict[LibraryOrigin | str, list[Ed25519Key]] = {BUYER: [key]} if key else {}
    return create_seller(
        seller_settings(data_dir, faults=faults),
        nonces=MemoryNonceStore(),
        resolver=StaticKeyResolver(keys),
    )


@pytest.fixture
def buyer_key(tmp_path: Path) -> Ed25519Key:
    return keyfile.load_or_create(tmp_path / "buyer-key.jwk")


@pytest.fixture
def seller(tmp_path: Path, buyer_key: Ed25519Key) -> Iterator[TestClient]:
    with TestClient(seller_app(tmp_path / "seller", key=buyer_key), base_url=SELLER) as client:
        yield client


def signed(method: str, url: str, key: Ed25519Key) -> dict[str, str]:
    return dict(RequestSigner(key, BUYER).sign(HTTPRequest(method, url, {}, b"")).headers.items())


# The seller


def test_the_seller_keeps_its_key_and_records_under_its_data_dir(tmp_path: Path) -> None:
    with TestClient(seller_app(tmp_path), base_url=SELLER) as client:
        assert client.get("/health").json() == {"ok": True}
    assert {p.name for p in tmp_path.iterdir()} == {"wba-key.jwk", "seller.db"}


def test_the_seller_signs_every_answer_and_serves_its_directory(seller: TestClient) -> None:
    health = seller.get("/health")
    assert "signature" in health.headers and "signature-input" in health.headers
    directory = seller.get(DIRECTORY_PATH)
    assert directory.status_code == 200 and len(directory.json()["keys"]) == 1


def test_the_seller_resolves_each_credential_through_its_injected_resources(
    seller: TestClient, buyer_key: Ed25519Key
) -> None:
    assert seller.get("/whoami").json() == {"kind": "public", "signature": None}

    by_token = seller.get("/whoami", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert by_token["principal"]["id"] == "buyer-bearer"

    url = f"{SELLER}/whoami"
    by_signature = seller.get("/whoami", headers=signed("GET", url, buyer_key)).json()
    assert by_signature["kind"] == "resolved"
    assert by_signature["principal"] == {
        "id": "buyer-wba",
        "kind": "buyer",
        "legal_name": "Demo Buyer Agency LLC",
        "domain": "buyer.example",  # the configured buyer origin's host
    }


def test_the_seller_operator_controls_take_the_key_from_settings(seller: TestClient) -> None:
    body = {"principal_id": "buyer-wba"}
    assert seller.post("/operator/issue", json=body).status_code == 403
    wrong = {"X-Operator-Key": "not-the-operator-key"}
    assert seller.post("/operator/issue", json=body, headers=wrong).status_code == 403
    issued = seller.post("/operator/issue", json=body, headers=SELLER_OPERATOR)
    assert issued.status_code == 200, issued.text
    assert issued.json()["proposal_id"].startswith("live-buyer-wba-")
    unknown = seller.post(
        "/operator/issue", json={"principal_id": "nobody"}, headers=SELLER_OPERATOR
    )
    assert unknown.status_code == 404


def test_a_seller_without_an_operator_key_refuses_every_operator_call(tmp_path: Path) -> None:
    settings = replace(seller_settings(tmp_path), operator_key=None)
    with TestClient(create_seller(settings, resolver=StaticKeyResolver({}))) as client:
        response = client.post(
            "/operator/issue", json={"principal_id": "buyer-wba"}, headers=SELLER_OPERATOR
        )
        assert response.status_code == 403


def test_the_seller_lifespan_closes_the_client_and_the_store(tmp_path: Path) -> None:
    with TestClient(seller_app(tmp_path), base_url=SELLER) as client:
        resources = client.app_state["resources"]
        assert isinstance(resources, SellerResources)
        assert not resources.client.is_closed and not resources.store.is_closed
    assert resources.client.is_closed and resources.store.is_closed


def _open_handles(path: Path) -> int:
    """How many of this process's file descriptors have `path` open."""
    target = path.stat()
    count = 0
    for entry in Path("/dev/fd").iterdir():
        try:
            held = os.fstat(int(entry.name))
        except OSError:  # the descriptor listdir itself used, closed by now
            continue
        count += (held.st_dev, held.st_ino) == (target.st_dev, target.st_ino)
    return count


@pytest.mark.parametrize("agent", ["seller", "buyer"])
def test_an_agent_that_cant_read_its_ca_bundle_fails_to_start_and_closes_its_store(
    tmp_path: Path, agent: str
) -> None:
    """The lifespan opens the store before the client, so the client's failure closes it."""
    missing = tmp_path / "no-such-bundle.pem"
    if agent == "seller":
        app = create_seller(replace(seller_settings(tmp_path), ca_bundle=missing))
    else:
        app = create_buyer(replace(buyer_settings(tmp_path), ca_bundle=missing))
    with pytest.raises(FileNotFoundError), TestClient(app):
        pass
    database = tmp_path / f"{agent}.db"
    assert database.exists()  # the store opened before the client failed
    assert _open_handles(database) == 0


def test_the_store_refuses_a_thread_other_than_the_one_that_opened_it(tmp_path: Path) -> None:
    """The concurrency model (persistence/sqlite.py): one connection, on the loop's thread."""
    with TestClient(seller_app(tmp_path), base_url=SELLER) as client:
        resources = client.app_state["resources"]
        assert isinstance(resources, SellerResources)
        with pytest.raises(sqlite3.ProgrammingError, match="same thread"):
            resources.store.is_empty()


def test_a_restart_keeps_the_seeded_records(tmp_path: Path) -> None:
    for _ in range(2):  # the second start finds the records and seeds nothing
        with TestClient(seller_app(tmp_path), base_url=SELLER) as client:
            caller = client.get("/whoami", headers={"Authorization": f"Bearer {TOKEN}"}).json()
            assert caller["principal"]["id"] == "buyer-bearer"


# The fault switch (TEST ONLY)


def _commit_signed(client: TestClient) -> bool:
    """Whether the seller's answer to a commit carries a signature."""
    return "signature" in client.post("/proposals/demo-wba-1/commit", content=b"{}").headers


def test_the_fault_mode_belongs_to_one_app(tmp_path: Path) -> None:
    one = TestClient(seller_app(tmp_path / "one", faults=True), base_url=SELLER)
    other = TestClient(seller_app(tmp_path / "other", faults=True), base_url=SELLER)
    with one, other:
        assert _commit_signed(one) and _commit_signed(other)
        fault = one.put("/test/fault", json={"mode": "strip"}).json()
        assert fault == {"mode": "strip", "on": "commit"}
        assert not _commit_signed(one)
        assert _commit_signed(other)
        assert one.put("/test/fault", json={"mode": "none"}).status_code == 200
        assert _commit_signed(one)


@pytest.mark.parametrize(
    ("mode", "refusal"),
    [
        ("none", None),
        ("strip", "signature-missing"),
        ("unbound", "response-not-bound"),
        ("rebound", "signature-invalid"),
    ],
)
def test_each_fault_mode_breaks_the_answer_the_way_it_names(
    tmp_path: Path, buyer_key: Ed25519Key, mode: str, refusal: str | None
) -> None:
    """The buyer's own verifier, over the seller's key, judges the seller's answer to a
    signed commit in each mode."""
    url = f"{SELLER}/proposals/demo-wba-1/commit"
    body = b"{}"
    request = RequestSigner(buyer_key, BUYER).sign(
        HTTPRequest("POST", url, {"Content-Type": "application/json"}, body)
    )
    with TestClient(seller_app(tmp_path, faults=True, key=buyer_key), base_url=SELLER) as client:
        assert client.put("/test/fault", json={"mode": mode}).status_code == 200
        answer = client.post(url, content=body, headers=dict(request.headers.items()))
    seller_key = keyfile.load_or_create(tmp_path / "wba-key.jwk")
    verifier = ResponseVerifier(StaticKeyResolver({SELLER: [seller_key]}))
    lines = [(k, v) for k, v in answer.headers.multi_items()]
    response = HTTPResponse(answer.status_code, lines, answer.content, request)
    with SyncResponseVerifier(verifier) as sync:
        if refusal is None:
            assert sync.verify(response, expected_origin=LibraryOrigin.parse(SELLER)).bound
        else:
            with pytest.raises(WebBotAuthError) as e:
                sync.verify(response, expected_origin=LibraryOrigin.parse(SELLER))
            assert e.value.reason == refusal


def test_a_bad_fault_mode_is_a_control_error_not_an_offer_error(tmp_path: Path) -> None:
    with TestClient(seller_app(tmp_path, faults=True), base_url=SELLER) as client:
        response = client.put("/test/fault", json={"mode": "bogus"})
    assert response.status_code == 422
    body = response.json()
    assert body.keys() == {"error", "detail"} and body["error"] == "validation"
    assert body["detail"].startswith("body/mode: ")


def test_the_fault_switch_is_absent_unless_the_settings_turn_it_on(seller: TestClient) -> None:
    assert seller.put("/test/fault", json={"mode": "strip"}).status_code == 404


# The buyer


@pytest.fixture
def buyer(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_buyer(buyer_settings(tmp_path))) as client:
        yield client


def test_a_trigger_that_omits_the_seller_targets_the_configured_seller(tmp_path: Path) -> None:
    """A trigger without a seller goes to the seller the buyer's settings name."""
    sent: list[str] = []

    def network(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(503)  # unsigned, so the buyer refuses it

    app = create_buyer(buyer_settings(tmp_path), transport=httpx.MockTransport(network))
    with TestClient(app) as client:
        outcome = client.post(
            "/operator/read", json={"proposal_id": "p-1"}, headers=BUYER_OPERATOR
        ).json()
    assert sent == [f"{SELLER}/proposals/p-1"]  # https://seller.example, as configured
    assert (outcome["state"], outcome["reason"]) == ("refused", "signature-missing")


def test_the_buyer_lifespan_closes_the_client_and_the_store(tmp_path: Path) -> None:
    with TestClient(create_buyer(buyer_settings(tmp_path))) as client:
        assert client.get("/health").json() == {"ok": True}
        resources = client.app_state["resources"]
        assert isinstance(resources, BuyerResources)
        assert not resources.client.is_closed and not resources.store.is_closed
    assert resources.client.is_closed and resources.store.is_closed
    assert {p.name for p in tmp_path.iterdir()} == {"keys", "buyer.db"}
