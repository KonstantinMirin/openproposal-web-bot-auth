"""The buyer's key rotation, through its operator routes, on an injected clock.

The keyring enforces the rotation order and its waits, and never loses or
overwrites a key. Each test builds the buyer with `create_app` over tmp_path,
with a clock the test moves, and rotates through `/operator/keys`, as an
operator does. The directory answers what the keyring publishes. The e2e
scenarios read the buyer's keys with the read-only `KeyStore`, as the last tests
do: it never writes, and never mints a key it doesn't find.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import DIRECTORY_PATH
from pydantic import SecretStr

from buyer.app import create_app
from shared.keyring import KeyStore, NoKeysError, RotationError
from tests.stack import BUYER_OPERATOR, buyer_settings

#: The rotation wait and the signature lifetime the tests run with.
WAIT, LIFETIME = 20.0, 10


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Buyer:
    client: TestClient
    clock: Clock
    keys_dir: Path

    def keys(self) -> dict[str, object]:
        response = self.client.get("/operator/keys", headers=BUYER_OPERATOR)
        assert response.status_code == 200, response.text
        state: dict[str, object] = response.json()
        return state

    def call(self, method: str, path: str) -> int:
        response: httpx.Response = self.client.request(
            method, f"/operator/keys{path}", headers=BUYER_OPERATOR
        )
        return response.status_code

    def directory(self) -> list[str]:
        return [k["kid"] for k in self.client.get(DIRECTORY_PATH).json()["keys"]]


def _buyer(
    data_dir: Path, clock: Clock, *, wait: float = WAIT, lifetime: int = LIFETIME
) -> TestClient:
    settings = replace(buyer_settings(data_dir), rotation_wait=wait, signature_lifetime=lifetime)
    return TestClient(create_app(settings, clock=clock))


@pytest.fixture
def buyer(tmp_path: Path) -> Iterator[Buyer]:
    clock = Clock()
    with _buyer(tmp_path, clock) as client:
        yield Buyer(client, clock, tmp_path / "keys")


def test_rotation_follows_the_order_and_its_waits(buyer: Buyer) -> None:
    old = buyer.keys()["active"]
    published = buyer.client.post("/operator/keys", headers=BUYER_OPERATOR).json()
    new = published["published_kid"]
    assert published["active"] == old  # the old key keeps signing
    assert set(buyer.directory()) == {old, new}

    assert buyer.call("POST", f"/{new}/activate") == 409  # a verifier may not list it yet
    buyer.clock.now += WAIT + 1
    assert buyer.call("POST", f"/{new}/activate") == 200
    assert buyer.keys()["active"] == new

    assert buyer.call("DELETE", f"/{old}") == 409  # its signatures may not have expired
    assert buyer.call("DELETE", f"/{new}") == 409  # it signs
    buyer.clock.now += LIFETIME + 1
    assert buyer.call("DELETE", f"/{old}") == 200
    assert buyer.directory() == [new]


def test_a_rotation_step_out_of_order_is_a_control_error(buyer: Buyer) -> None:
    response = buyer.client.post("/operator/keys/no-such-kid/activate", headers=BUYER_OPERATOR)
    assert response.status_code == 409
    assert response.json()["error"] == "rotation"
    assert buyer.client.get("/operator/keys").status_code == 403  # no operator key


def test_publish_retire_publish_keeps_every_key(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock, wait=0, lifetime=0) as client:
        buyer = Buyer(client, clock, tmp_path / "keys")
        original = buyer.keys()["active"]
        first = client.post("/operator/keys", headers=BUYER_OPERATOR).json()["published_kid"]
        assert buyer.call("DELETE", f"/{first}") == 200  # never signed, so it can go at once
        second = client.post("/operator/keys", headers=BUYER_OPERATOR).json()["published_kid"]
        assert second != first
        assert buyer.call("POST", f"/{second}/activate") == 200
        assert buyer.call("POST", f"/{original}/activate") == 200
        assert buyer.call("DELETE", f"/{second}") == 200
        assert buyer.directory() == [original]
    # Both retired keys are kept, and neither overwrote the other.
    assert {p.stem for p in (tmp_path / "keys" / "retired").glob("*.jwk")} == {first, second}


def test_a_restart_keeps_the_keys_and_the_rotation_state(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock) as client:
        published = client.post("/operator/keys", headers=BUYER_OPERATOR).json()
    clock.now += WAIT + 1
    with _buyer(tmp_path, clock) as client:
        after = Buyer(client, clock, tmp_path / "keys")
        assert after.keys() == {k: published[k] for k in ("published", "active")}
        # The publish time survived the restart, so the wait counts from it.
        assert after.call("POST", f"/{published['published_kid']}/activate") == 200


def test_the_scenarios_read_any_key_by_kid_published_or_retired(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock, wait=0, lifetime=0) as client:
        buyer = Buyer(client, clock, tmp_path / "keys")
        old = buyer.keys()["active"]
        new = client.post("/operator/keys", headers=BUYER_OPERATOR).json()["published_kid"]
        assert buyer.call("POST", f"/{new}/activate") == 200
        assert buyer.call("DELETE", f"/{old}") == 200
    assert isinstance(old, str) and isinstance(new, str)
    # As e2e/scenarios/conftest.py reads the buyer's keys volume.
    keys = KeyStore.open(tmp_path / "keys")
    assert keys.active().thumbprint == new
    assert keys.key(new).thumbprint == new
    with pytest.raises(RotationError):
        keys.key(old)  # retired: not published any more
    assert keys.key(old, include_retired=True).thumbprint == old
    with pytest.raises(RotationError):
        keys.key("no-such-kid", include_retired=True)
    assert not list((tmp_path / "keys").rglob("no-such-kid*"))  # a missing kid is never minted


def test_the_key_store_reads_a_directory_without_keys_and_writes_nothing(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    empty.chmod(0o555)  # read-only, as the e2e mounts the buyer's keys
    with pytest.raises(NoKeysError):
        KeyStore.open(empty)
    with pytest.raises(NoKeysError):
        KeyStore.open(tmp_path / "missing")
    assert list(empty.iterdir()) == []
    assert not (tmp_path / "missing").exists()


def test_a_deleted_active_key_is_refused_never_minted_again(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock, wait=0, lifetime=0) as client:
        active = Buyer(client, clock, tmp_path / "keys").keys()["active"]
        assert client.post("/operator/keys", headers=BUYER_OPERATOR).status_code == 200
    (tmp_path / "keys" / f"{active}.jwk").unlink()
    with pytest.raises(RotationError):
        KeyStore.open(tmp_path / "keys").active()
    assert not (tmp_path / "keys" / f"{active}.jwk").exists()


def test_the_operator_key_comes_from_the_settings(tmp_path: Path) -> None:
    other = replace(buyer_settings(tmp_path), operator_key=SecretStr("another-key"))
    with TestClient(create_app(other)) as client:
        assert client.get("/operator/keys", headers=BUYER_OPERATOR).status_code == 403
