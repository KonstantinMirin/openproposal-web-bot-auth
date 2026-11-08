"""The buyer's key rotation, through its operator routes, on an injected clock.

The keyring enforces the rotation order and its waits, and never loses or
overwrites a key. Each test builds the buyer with `create_app` over tmp_path,
with a clock the test moves, and rotates through the buyer's key controls
(`KEYS`, `PUBLISH`, `ACTIVATE`, `RETIRE`), as an operator does. The directory
answers what the keyring publishes. The e2e scenarios read the buyer's keys
with the read-only `KeyStore`, as the last tests do: it never writes, and never
mints a key it doesn't find.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import DIRECTORY_PATH
from pydantic import SecretStr

from buyer.app import create_app
from protocol.values import objects, read_json
from shared.keyring import KeyStore, NoKeysError, RotationError
from tests.stack import BUYER_KEY, buyer_settings
from transport.client import ControlClient, ControlFailed
from transport.control import ACTIVATE, KEYS, PUBLISH, RETIRE, ControlOp, ErrorBody, KeyState

#: The signature lifetime the tests run with, and the rotation wait of a directory served
#: with `max-age=0`: no cache holds it, and a verifier may keep its copy for the profile's
#: 300 s (§ 2.8.3).
LIFETIME, WAIT = 10, 300


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

    @property
    def control(self) -> ControlClient:
        return ControlClient(self.client, operator_key=BUYER_KEY)

    def keys(self) -> KeyState:
        return self.control.call(KEYS, None)

    def publish(self) -> str:
        """Publishes a new key; its kid."""
        return self.control.call(PUBLISH, None).published_kid

    def step(self, op: ControlOp[None, KeyState], kid: str) -> int:
        """The status of a rotation step on `kid`: 200, or the refusal's."""
        try:
            self.control.call(op, None, kid=kid)
        except ControlFailed as e:
            return e.status
        return 200

    def directory(self) -> list[str]:
        """The kids the buyer's directory lists."""
        keys = objects(read_json(self.client.get(DIRECTORY_PATH).content).get("keys"))
        return [str(k.get("kid")) for k in keys]


def _buyer(
    data_dir: Path, clock: Clock, *, max_age: int = 0, lifetime: int = LIFETIME
) -> TestClient:
    settings = replace(
        buyer_settings(data_dir), directory_max_age=max_age, signature_lifetime=lifetime
    )
    return TestClient(create_app(settings, clock=clock))


@pytest.fixture
def buyer(tmp_path: Path) -> Iterator[Buyer]:
    clock = Clock()
    with _buyer(tmp_path, clock) as client:
        yield Buyer(client, clock, tmp_path / "keys")


def test_rotation_follows_the_order_and_its_waits(buyer: Buyer) -> None:
    old = buyer.keys().active
    published = buyer.control.call(PUBLISH, None)
    new = published.published_kid
    assert published.active == old  # the old key keeps signing
    assert set(buyer.directory()) == {old, new}

    assert buyer.step(ACTIVATE, new) == 409  # a verifier may not list it yet
    buyer.clock.now += WAIT + 1
    assert buyer.step(ACTIVATE, new) == 200
    assert buyer.keys().active == new

    assert buyer.step(RETIRE, old) == 409  # its signatures may not have expired
    assert buyer.step(RETIRE, new) == 409  # it signs
    buyer.clock.now += LIFETIME + 1
    assert buyer.step(RETIRE, old) == 200
    assert buyer.directory() == [new]


def test_the_wait_is_the_directory_max_age_plus_the_profiles_cache_lifetime(
    tmp_path: Path,
) -> None:
    """A cache may serve the directory without the new key for its max-age, and a verifier
    may answer from that copy for 300 s more, so the key signs only after both (§ 2.8.3)."""
    clock = Clock()
    with _buyer(tmp_path, clock, max_age=3600) as client:
        buyer = Buyer(client, clock, tmp_path / "keys")
        assert client.get(DIRECTORY_PATH).headers["cache-control"] == "max-age=3600"
        new = buyer.publish()
        clock.now += 3600 + 300 - 1
        assert buyer.step(ACTIVATE, new) == 409
        clock.now += 1
        assert buyer.step(ACTIVATE, new) == 200


def test_a_directory_holds_at_most_sixteen_keys(buyer: Buyer) -> None:
    """The buyer never publishes a directory a verifier would refuse: a key beyond the
    sixteenth is refused, and the directory keeps answering with the keys it has."""
    published = [buyer.publish() for _ in range(15)]
    assert len(buyer.directory()) == 16
    with pytest.raises(ControlFailed) as failed:
        buyer.control.call(PUBLISH, None)
    assert failed.value.status == 409
    assert set(buyer.directory()) == {buyer.keys().active, *published}
    assert buyer.step(RETIRE, published[0]) == 200  # never signed, so it can go at once
    replacement = buyer.publish()
    assert set(buyer.directory()) == {buyer.keys().active, *published[1:], replacement}


def test_a_rotation_step_out_of_order_is_a_control_error(buyer: Buyer) -> None:
    with pytest.raises(ControlFailed) as failed:
        buyer.control.call(ACTIVATE, None, kid="no-such-kid")
    assert failed.value.status == 409
    assert failed.value.error is not None and failed.value.error.error == "rotation"
    with pytest.raises(ControlFailed) as failed:
        ControlClient(buyer.client).call(KEYS, None)  # no operator key
    assert failed.value.status == 403


def test_publish_retire_publish_keeps_every_key(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock, lifetime=0) as client:
        buyer = Buyer(client, clock, tmp_path / "keys")
        original = buyer.keys().active
        first = buyer.publish()
        assert buyer.step(RETIRE, first) == 200  # never signed, so it can go at once
        second = buyer.publish()
        assert second != first
        clock.now += WAIT
        assert buyer.step(ACTIVATE, second) == 200
        assert buyer.step(ACTIVATE, original) == 200
        assert buyer.step(RETIRE, second) == 200
        assert buyer.directory() == [original]
    # Both retired keys are kept, and neither overwrote the other.
    assert {p.stem for p in (tmp_path / "keys" / "retired").glob("*.jwk")} == {first, second}


def test_a_restart_keeps_the_keys_and_the_rotation_state(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock) as client:
        published = Buyer(client, clock, tmp_path / "keys").control.call(PUBLISH, None)
    clock.now += WAIT + 1
    with _buyer(tmp_path, clock) as client:
        after = Buyer(client, clock, tmp_path / "keys")
        assert after.keys() == KeyState(published=published.published, active=published.active)
        # The publish time survived the restart, so the wait counts from it.
        assert after.step(ACTIVATE, published.published_kid) == 200


def test_the_scenarios_read_any_key_by_kid_published_or_retired(tmp_path: Path) -> None:
    clock = Clock()
    with _buyer(tmp_path, clock, lifetime=0) as client:
        buyer = Buyer(client, clock, tmp_path / "keys")
        old = buyer.keys().active
        new = buyer.publish()
        clock.now += WAIT
        assert buyer.step(ACTIVATE, new) == 200
        assert buyer.step(RETIRE, old) == 200
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
    with _buyer(tmp_path, clock, lifetime=0) as client:
        buyer = Buyer(client, clock, tmp_path / "keys")
        active = buyer.keys().active
        buyer.publish()
    (tmp_path / "keys" / f"{active}.jwk").unlink()
    with pytest.raises(RotationError):
        KeyStore.open(tmp_path / "keys").active()
    assert not (tmp_path / "keys" / f"{active}.jwk").exists()


def test_the_operator_key_comes_from_the_settings(tmp_path: Path) -> None:
    other = replace(buyer_settings(tmp_path), operator_key=SecretStr("another-key"))
    with TestClient(create_app(other)) as client, pytest.raises(ControlFailed) as failed:
        ControlClient(client, operator_key=BUYER_KEY).call(KEYS, None)
    assert (failed.value.status, failed.value.error) == (
        403,
        ErrorBody(error="operator-key", detail="operator key required"),
    )
