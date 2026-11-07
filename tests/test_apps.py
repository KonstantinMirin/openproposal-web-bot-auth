"""Each agent's composition root: built from settings over tmp_path, never from /data.

The lifespan opens the store and the one client and closes both on shutdown.
The fault switch belongs to one app instance. The buyer's trigger follows its
configured seller (defect 7a).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    Ed25519Key,
    HTTPRequest,
    MemoryNonceStore,
    Origin,
    RequestSigner,
    StaticKeyResolver,
)
from pydantic import SecretStr
from starlette.types import ASGIApp

from buyer.app import create_app as create_buyer
from buyer.resources import BuyerResources
from buyer.settings import BuyerSettings
from seller.app import create_app as create_seller
from seller.resources import SellerResources
from seller.settings import SellerSettings

SELLER = "https://seller.example"
BUYER = "https://buyer.example"
OPERATOR = {"X-Operator-Key": "operator-key-for-tests"}
TOKEN = "bearer-token-for-tests"  # noqa: S105 -- a test value, not a deployed secret


def seller_settings(data_dir: Path, *, faults: bool = False) -> SellerSettings:
    return SellerSettings(
        self_origin=Origin.parse(SELLER),
        peer_buyer_origin=Origin.parse(BUYER),
        data_dir=data_dir,
        operator_key=SecretStr(OPERATOR["X-Operator-Key"]),
        bearer_token=SecretStr(TOKEN),
        faults=faults,
    )


def buyer_settings(data_dir: Path) -> BuyerSettings:
    return BuyerSettings(
        self_origin=Origin.parse(BUYER),
        peer_seller_origin=Origin.parse(SELLER),
        peer_cfbot_origin=Origin.parse("https://cfbot.example"),
        data_dir=data_dir,
        operator_key=SecretStr(OPERATOR["X-Operator-Key"]),
        bearer_token=SecretStr(TOKEN),
    )


def seller_app(data_dir: Path, *, faults: bool = False, key: Ed25519Key | None = None) -> ASGIApp:
    keys: dict[Origin | str, list[Ed25519Key]] = {BUYER: [key]} if key else {}
    return create_seller(
        seller_settings(data_dir, faults=faults),
        nonces=MemoryNonceStore(),
        resolver=StaticKeyResolver(keys),
    )


@pytest.fixture
def buyer_key(tmp_path: Path) -> Ed25519Key:
    return Ed25519Key.load_or_create(tmp_path / "buyer-key.jwk")


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
    assert seller.get("/whoami").json() == {"kind": "public", "credential": None}

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
    issued = seller.post("/operator/issue", json=body, headers=OPERATOR)
    assert issued.status_code == 200, issued.text
    assert issued.json()["proposal_id"].startswith("live-buyer-wba-")
    unknown = seller.post("/operator/issue", json={"principal_id": "nobody"}, headers=OPERATOR)
    assert unknown.status_code == 404


def test_a_seller_without_an_operator_key_refuses_every_operator_call(tmp_path: Path) -> None:
    settings = SellerSettings(
        self_origin=Origin.parse(SELLER), peer_buyer_origin=Origin.parse(BUYER), data_dir=tmp_path
    )
    with TestClient(create_seller(settings, resolver=StaticKeyResolver({}))) as client:
        response = client.post(
            "/operator/issue", json={"principal_id": "buyer-wba"}, headers=OPERATOR
        )
        assert response.status_code == 403


def _closed(db: sqlite3.Connection) -> bool:
    """Whether `db` is closed. Readable from any thread, unlike a query on the connection."""
    try:
        _ = db.total_changes
    except sqlite3.ProgrammingError:
        return True
    return False


def test_the_seller_lifespan_closes_the_client_and_the_store(tmp_path: Path) -> None:
    with TestClient(seller_app(tmp_path), base_url=SELLER) as client:
        resources = client.app_state["resources"]
        assert isinstance(resources, SellerResources)
        assert not resources.client.is_closed and not _closed(resources.store.db)
    assert resources.client.is_closed and _closed(resources.store.db)


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
        assert one.put("/test/fault", json={"mode": "strip"}).json() == {"mode": "strip"}
        assert not _commit_signed(one)
        assert _commit_signed(other)
        assert one.put("/test/fault", json={"mode": "none"}).status_code == 200
        assert _commit_signed(one)


def test_a_bad_fault_mode_gets_fastapis_422_not_an_offer_error(tmp_path: Path) -> None:
    with TestClient(seller_app(tmp_path, faults=True), base_url=SELLER) as client:
        response = client.put("/test/fault", json={"mode": "bogus"})
    assert response.status_code == 422
    assert "errors" not in response.json()
    assert response.json()["detail"][0]["loc"] == ["body", "mode"]


def test_the_fault_switch_is_absent_unless_the_settings_turn_it_on(seller: TestClient) -> None:
    assert seller.put("/test/fault", json={"mode": "strip"}).status_code == 404


# The buyer


class Network:
    """Answers the buyer's calls in place of the network, and records them."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/verify":
            return httpx.Response(200, json={"ok": True, "identity": BUYER})
        return httpx.Response(503, json={"down": True})  # unsigned, so the buyer refuses it


@pytest.fixture
def network() -> Network:
    return Network()


@pytest.fixture
def buyer(tmp_path: Path, network: Network) -> Iterator[TestClient]:
    app = create_buyer(buyer_settings(tmp_path), transport=httpx.MockTransport(network))
    with TestClient(app) as client:
        yield client


def test_a_trigger_that_omits_the_seller_targets_the_configured_seller(
    buyer: TestClient, network: Network
) -> None:
    """Defect 7a: the default used to be a literal, so this trigger was refused unsent."""
    outcome = buyer.post("/operator/read", json={"proposal_id": "p-1"}, headers=OPERATOR).json()
    assert [str(r.url) for r in network.requests] == [f"{SELLER}/proposals/p-1"]
    assert outcome["state"] == "refused"
    assert "signature-missing" in outcome["detail"]


def test_a_commit_trigger_that_omits_the_seller_targets_the_configured_seller(
    buyer: TestClient, network: Network
) -> None:
    trigger = {"proposal_id": "p-1", "line_item_ids": ["business-daily-display"]}
    outcome = buyer.post("/operator/commit", json=trigger, headers=OPERATOR).json()
    assert [str(r.url) for r in network.requests] == [f"{SELLER}/proposals/p-1"]
    assert outcome["state"] == "refused"


def test_a_commit_trigger_names_its_line_items(buyer: TestClient, network: Network) -> None:
    response = buyer.post("/operator/commit", json={"proposal_id": "p-1"}, headers=OPERATOR)
    assert response.status_code == 400
    assert network.requests == []


def test_a_trigger_for_another_seller_is_refused_unsent(
    buyer: TestClient, network: Network
) -> None:
    trigger = {"seller": "https://other.example", "proposal_id": "p-1"}
    outcome = buyer.post("/operator/read", json=trigger, headers=OPERATOR).json()
    assert outcome["state"] == "refused"
    assert network.requests == []


def test_the_buyer_signs_for_cfbot_at_its_configured_origin(
    buyer: TestClient, network: Network
) -> None:
    check = buyer.post("/operator/cloudflare-check", headers=OPERATOR).json()
    assert check == {"status": 200, "verdict": {"ok": True, "identity": BUYER}}
    (sent,) = network.requests
    assert str(sent.url) == "https://cfbot.example/verify"
    assert f'"{BUYER}' in sent.headers["signature-agent"]


def test_the_buyer_rotates_its_keys_through_its_operator_routes(buyer: TestClient) -> None:
    assert buyer.get("/operator/keys").status_code == 403
    keys = buyer.get("/operator/keys", headers=OPERATOR).json()
    published = buyer.post("/operator/keys", headers=OPERATOR).json()
    assert published["active"] == keys["active"]
    assert set(published["published"]) == {keys["active"], published["published_kid"]}
    # The production wait (600 s) hasn't passed, and the active key can't be retired.
    new, old = published["published_kid"], keys["active"]
    assert buyer.post(f"/operator/keys/{new}/activate", headers=OPERATOR).status_code == 409
    assert buyer.delete(f"/operator/keys/{old}", headers=OPERATOR).status_code == 409


def test_the_buyer_serves_its_keyring_as_its_directory(buyer: TestClient) -> None:
    active = buyer.get("/operator/keys", headers=OPERATOR).json()["active"]
    directory = buyer.get(DIRECTORY_PATH)
    assert directory.status_code == 200
    assert [k["kid"] for k in directory.json()["keys"]] == [active]


def test_the_buyer_lifespan_closes_the_client_and_the_store(tmp_path: Path) -> None:
    with TestClient(create_buyer(buyer_settings(tmp_path))) as client:
        assert client.get("/health").json() == {"ok": True}
        resources = client.app_state["resources"]
        assert isinstance(resources, BuyerResources)
        assert not resources.client.is_closed and not _closed(resources.store.db)
    assert resources.client.is_closed and _closed(resources.store.db)
    assert {p.name for p in tmp_path.iterdir()} == {"keys", "buyer.db"}
