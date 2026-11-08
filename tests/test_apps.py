"""Each agent's composition root: built from settings over tmp_path, never from /data.

The lifespan opens the store and the one client and closes both on shutdown,
and an agent that fails to start, on a CA bundle it can't read, leaves no store
open, and a buyer whose signature lifetime the library won't sign with stops at
boot. The fault switch belongs to one app instance. The buyer's flow is in
tests/test_buyer.py.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    Ed25519Key,
    HTTPResponse,
    ResponseVerifier,
    StaticKeyResolver,
    WebBotAuthError,
    keyfile,
)
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from iab_agentic_primitives.web_bot_auth.sync import SyncResponseVerifier, SyncRuntime
from pydantic import SecretStr
from starlette.types import ASGIApp

from buyer.app import create_app as create_buyer
from buyer.resources import BuyerResources
from buyer.settings import BuyerSettings
from persistence.observe import (
    KeptOriginCredential,
    KeptPrincipal,
    KeptTokenCredential,
    SellerRecords,
)
from persistence.values import Origin
from protocol.record import sha256_hex
from protocol.values import objects, read_json
from seller.caller import WHOAMI, ResolvedView
from seller.errors import IdentityChanged
from seller.faults import FAULT_REASONS
from seller.resources import SellerResources
from seller.settings import SellerSettings
from shared.settings import SettingsError
from tests.stack import (
    BUYER_KEY,
    ELSEWHERE,
    SELLER_KEY,
    TOKEN,
    as_state,
    buyer_settings,
    seller_app,
    seller_settings,
    signed_headers,
    signed_request,
)
from transport.client import ControlClient, ControlFailed
from transport.control import (
    FAULT,
    HEALTH,
    ISSUE,
    READ,
    ErrorBody,
    FaultMode,
    FaultName,
    Health,
    IssueRequest,
    ReadTrigger,
    Refused,
)

#: Each agent alone, under origins other than the demo's.
SELLER, BUYER = str(ELSEWHERE.seller), str(ELSEWHERE.buyer)


def _seller(data_dir: Path, *, faults: bool = False, key: Ed25519Key | None = None) -> ASGIApp:
    """The seller alone, knowing the buyer's `key` when one is given."""
    keys: dict[LibraryOrigin | str, list[Ed25519Key]] = {BUYER: [key]} if key else {}
    settings = seller_settings(data_dir, origins=ELSEWHERE, faults=faults)
    return seller_app(settings, resolver=StaticKeyResolver(keys))


def _buyer_settings(data_dir: Path) -> BuyerSettings:
    return buyer_settings(data_dir, origins=ELSEWHERE)


@pytest.fixture
def buyer_key(tmp_path: Path) -> Ed25519Key:
    return keyfile.load_or_create(tmp_path / "buyer-key.jwk")


@pytest.fixture
def seller(tmp_path: Path, buyer_key: Ed25519Key) -> Iterator[TestClient]:
    with TestClient(_seller(tmp_path / "seller", key=buyer_key), base_url=SELLER) as client:
        yield client


def _buyer_principal(data_dir: Path) -> KeptPrincipal:
    """The principal the buyer's origin points at, as the seller's read model reads it."""
    with SellerRecords.open(data_dir / "seller.db") as records:
        principal = records.principal_with_origin(ELSEWHERE.buyer)
    assert principal is not None
    return principal


def _resolved(client: TestClient, headers: dict[str, str]) -> ResolvedView:
    """The caller `/whoami` resolves for a request with `headers`, as it answers it."""
    caller = WHOAMI.validate_json(client.get("/whoami", headers=headers).content)
    assert isinstance(caller, ResolvedView), caller
    return caller


def _healthy(client: TestClient) -> bool:
    return ControlClient(client).call(HEALTH, None) == Health(ok=True)


# The seller


def test_the_seller_keeps_its_key_and_records_under_its_data_dir(tmp_path: Path) -> None:
    with TestClient(_seller(tmp_path), base_url=SELLER) as client:
        assert _healthy(client)
    assert {p.name for p in tmp_path.iterdir()} == {"wba-key.jwk", "seller.db"}


def test_the_seller_signs_every_answer_and_serves_its_directory(seller: TestClient) -> None:
    health = seller.get(HEALTH.path)
    assert "signature" in health.headers and "signature-input" in health.headers
    directory = seller.get(DIRECTORY_PATH)
    assert directory.status_code == 200
    assert len(objects(read_json(directory.content).get("keys"))) == 1


def test_the_seller_resolves_each_credential_to_the_buyers_one_principal(
    seller: TestClient, buyer_key: Ed25519Key, tmp_path: Path
) -> None:
    assert seller.get("/whoami").json() == {"kind": "public", "signature": None}

    by_token = _resolved(seller, {"Authorization": f"Bearer {TOKEN}"})
    by_signature = _resolved(
        seller, signed_headers("GET", f"{SELLER}/whoami", buyer_key, origin=BUYER)
    )
    assert by_token.principal == by_signature.principal
    principal = by_signature.principal
    assert principal.model_dump() == _buyer_principal(tmp_path / "seller").model_dump()
    assert (principal.kind, principal.legal_name) == ("buyer", "Demo Buyer Agency LLC")
    assert principal.domain == ELSEWHERE.buyer.host  # the configured buyer origin's host


def _issue_status(seller: TestClient, key: SecretStr | None, principal_id: str) -> int:
    """The status a call to issue answers, with `key` as the operator key."""
    try:
        ControlClient(seller, operator_key=key).call(ISSUE, IssueRequest(principal_id=principal_id))
    except ControlFailed as e:
        return e.status
    return 200


def test_the_seller_operator_controls_take_the_key_from_settings(
    seller: TestClient, tmp_path: Path
) -> None:
    buyer = _buyer_principal(tmp_path / "seller").id
    assert _issue_status(seller, None, buyer) == 403
    assert _issue_status(seller, SecretStr("not-the-operator-key"), buyer) == 403
    issued = ControlClient(seller, operator_key=SELLER_KEY).call(
        ISSUE, IssueRequest(principal_id=buyer)
    )
    assert issued.principal_id == buyer
    assert issued.proposal_id.startswith(f"live-{buyer}-")
    assert _issue_status(seller, SELLER_KEY, "nobody") == 404


def test_a_seller_without_an_operator_key_refuses_every_operator_call(tmp_path: Path) -> None:
    settings = replace(seller_settings(tmp_path, origins=ELSEWHERE), operator_key=None)
    with TestClient(seller_app(settings)) as client:
        assert _issue_status(client, SELLER_KEY, _buyer_principal(tmp_path).id) == 403


def test_the_seller_lifespan_closes_the_client_and_the_store(tmp_path: Path) -> None:
    with TestClient(_seller(tmp_path), base_url=SELLER) as client:
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
        app = seller_app(replace(seller_settings(tmp_path, origins=ELSEWHERE), ca_bundle=missing))
    else:
        app = create_buyer(replace(_buyer_settings(tmp_path), ca_bundle=missing))
    with pytest.raises(FileNotFoundError), TestClient(app):
        pass
    database = tmp_path / f"{agent}.db"
    assert database.exists()  # the store opened before the client failed
    assert _open_handles(database) == 0


def test_the_store_refuses_a_thread_other_than_the_one_that_opened_it(tmp_path: Path) -> None:
    """The concurrency model (persistence/sqlite.py): one connection, on the loop's thread."""
    with TestClient(_seller(tmp_path), base_url=SELLER) as client:
        resources = client.app_state["resources"]
        assert isinstance(resources, SellerResources)
        with pytest.raises(sqlite3.ProgrammingError, match="same thread"):
            resources.store.for_origin(ELSEWHERE.buyer)


def test_each_boot_points_the_buyers_credentials_at_its_one_principal(
    tmp_path: Path, buyer_key: Ed25519Key
) -> None:
    """The settings point both of the buyer's credentials at its one principal on every boot:
    a rotated token takes effect on the next boot, and the one it replaces stops working."""
    keys: dict[LibraryOrigin | str, list[Ed25519Key]] = {BUYER: [buyer_key]}
    by_signature = signed_headers("GET", f"{SELLER}/whoami", buyer_key, origin=BUYER)

    def boot(token: str | None) -> TestClient:
        settings = replace(
            seller_settings(tmp_path, origins=ELSEWHERE),
            bearer_token=None if token is None else SecretStr(token),
        )
        return TestClient(seller_app(settings, resolver=StaticKeyResolver(keys)), base_url=SELLER)

    def status(client: TestClient, token: str) -> int:
        answer: httpx.Response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
        return answer.status_code

    with boot(TOKEN) as client:
        principal = _resolved(client, by_signature).principal
        assert _resolved(client, {"Authorization": f"Bearer {TOKEN}"}).principal == principal
    with boot("rotated-token") as client:
        assert status(client, TOKEN) == 401
        assert _resolved(client, {"Authorization": "Bearer rotated-token"}).principal == principal
        assert _resolved(client, by_signature).principal == principal
    with SellerRecords.open(tmp_path / "seller.db") as records:
        assert records.credentials(principal.id) == [
            KeptOriginCredential(origin=ELSEWHERE.buyer),
            KeptTokenCredential(token_hash=sha256_hex(b"rotated-token")),
        ]
    with boot(None) as client:
        assert status(client, "rotated-token") == 401
        assert _resolved(client, by_signature).principal == principal


@pytest.mark.parametrize(
    "changed",
    [
        lambda s: replace(
            s, peer_buyer_origin=Origin.parse("https://buyer-two.wba-demo.noetis.dev")
        ),
        lambda s: replace(s, peer_buyer_legal_name="Another Agency LLC"),
    ],
    ids=["another origin", "another legal name"],
)
def test_a_boot_that_would_rewrite_the_buyers_identity_refuses_to_start(
    tmp_path: Path, buyer_key: Ed25519Key, changed: Callable[[SellerSettings], SellerSettings]
) -> None:
    """The proposals issued to the buyer name its domain and legal name, so no boot rewrites
    them: settings that name the buyer otherwise stop the seller at startup, and the
    principal and the proposals issued to it stay as they were."""
    keys: dict[LibraryOrigin | str, list[Ed25519Key]] = {BUYER: [buyer_key]}
    settings = seller_settings(tmp_path, origins=ELSEWHERE)
    with TestClient(seller_app(settings), base_url=SELLER):
        pass
    before = _buyer_principal(tmp_path)

    with pytest.raises(IdentityChanged), TestClient(seller_app(changed(settings))):
        pass

    assert _buyer_principal(tmp_path) == before
    path = "/proposals/demo-wba-1"
    headers = signed_headers("GET", f"{SELLER}{path}", buyer_key, origin=BUYER)
    app = seller_app(settings, resolver=StaticKeyResolver(keys))
    with TestClient(app, base_url=SELLER) as client:
        document = read_json(client.get(path, headers=headers).content)
    assert document["buyer"] == {"domain": before.domain, "legal_name": before.legal_name}


# The fault switch (TEST ONLY)


def _commit_signed(client: TestClient) -> bool:
    """Whether the seller's answer to a commit carries a signature."""
    return "signature" in client.post("/proposals/demo-wba-1/commit", content=b"{}").headers


def test_the_fault_mode_belongs_to_one_app(tmp_path: Path) -> None:
    one = TestClient(_seller(tmp_path / "one", faults=True), base_url=SELLER)
    other = TestClient(_seller(tmp_path / "other", faults=True), base_url=SELLER)
    with one, other:
        assert _commit_signed(one) and _commit_signed(other)
        faults = ControlClient(one)
        assert faults.call(FAULT, FaultMode(mode="strip")) == FaultMode(mode="strip", on="commit")
        assert not _commit_signed(one)
        assert _commit_signed(other)
        faults.call(FAULT, FaultMode(mode="none"))
        assert _commit_signed(one)


@pytest.mark.parametrize(("mode", "refusal"), [("none", None), *FAULT_REASONS.items()])
def test_each_fault_mode_breaks_the_answer_the_way_it_names(
    tmp_path: Path, buyer_key: Ed25519Key, mode: FaultName, refusal: str | None
) -> None:
    """The buyer's own verifier, over the seller's key, judges the seller's answer to a
    signed commit in each mode."""
    url = f"{SELLER}/proposals/demo-wba-1/commit"
    body = b"{}"
    request = signed_request("POST", url, buyer_key, origin=BUYER, body=body)
    with TestClient(_seller(tmp_path, faults=True, key=buyer_key), base_url=SELLER) as client:
        ControlClient(client).call(FAULT, FaultMode(mode=mode))
        answer = client.post(url, content=body, headers=dict(request.headers.items()))
    seller_key = keyfile.load_or_create(tmp_path / "wba-key.jwk")
    verifier = ResponseVerifier(StaticKeyResolver({SELLER: [seller_key]}))
    lines = [(k, v) for k, v in answer.headers.multi_items()]
    response = HTTPResponse(answer.status_code, lines, answer.content, request)
    with SyncRuntime() as runtime:
        sync = SyncResponseVerifier(verifier, runtime=runtime)
        if refusal is None:
            assert sync.verify(response, expected_origin=LibraryOrigin.parse(SELLER)).bound
        else:
            with pytest.raises(WebBotAuthError) as e:
                sync.verify(response, expected_origin=LibraryOrigin.parse(SELLER))
            assert e.value.reason == refusal


def test_a_bad_fault_mode_is_a_control_error_not_an_offer_error(tmp_path: Path) -> None:
    with TestClient(_seller(tmp_path, faults=True), base_url=SELLER) as client:
        response = client.request(FAULT.method, FAULT.path, json={"mode": "bogus"})
    assert response.status_code == 422
    body = ErrorBody.model_validate_json(response.content)
    assert body.error == "validation"
    assert body.detail.startswith("body/mode: ")


def test_the_fault_switch_is_absent_unless_the_settings_turn_it_on(seller: TestClient) -> None:
    assert seller.request(FAULT.method, FAULT.path, json={"mode": "strip"}).status_code == 404


# The buyer


@pytest.fixture
def buyer(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_buyer(_buyer_settings(tmp_path))) as client:
        yield client


def test_a_trigger_that_omits_the_seller_targets_the_configured_seller(tmp_path: Path) -> None:
    """A trigger without a seller goes to the seller the buyer's settings name."""
    sent: list[str] = []

    def network(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(503)  # unsigned, so the buyer refuses it

    app = create_buyer(_buyer_settings(tmp_path), transport=httpx.MockTransport(network))
    with TestClient(app) as client:
        outcome = ControlClient(client, operator_key=BUYER_KEY).call(
            READ, ReadTrigger(proposal_id="p-1")
        )
    assert sent == [f"{SELLER}/proposals/p-1"]  # the seller the settings name
    assert as_state(Refused, outcome).code == "signature-missing"


def test_the_buyer_lifespan_closes_the_client_and_the_store(tmp_path: Path) -> None:
    with TestClient(create_buyer(_buyer_settings(tmp_path))) as client:
        assert _healthy(client)
        resources = client.app_state["resources"]
        assert isinstance(resources, BuyerResources)
        assert not resources.client.is_closed and not resources.store.is_closed
    assert resources.client.is_closed and resources.store.is_closed
    assert {p.name for p in tmp_path.iterdir()} == {"keys", "buyer.db"}


@pytest.mark.parametrize("lifetime", [0, 301])
def test_a_signature_lifetime_the_library_wont_sign_with_stops_the_buyer_at_boot(
    tmp_path: Path, lifetime: int
) -> None:
    """The library signs for 1 to 300 s only: any other lifetime stops the boot, naming the
    variable, before the buyer mints a key or reports healthy."""
    settings = replace(_buyer_settings(tmp_path), signature_lifetime=lifetime)
    with pytest.raises(SettingsError) as e:
        create_buyer(settings)
    assert e.value.name == "WBA_SIGNATURE_LIFETIME"
    assert not any(tmp_path.rglob("*.jwk"))
