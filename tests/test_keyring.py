"""The keyring enforces the rotation order, and never loses or overwrites a key."""

import pytest

from shared.keyring import Keyring, KeyringState, RotationError


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_rotation_order_and_waits(tmp_path):
    clock = Clock()
    ring = Keyring(tmp_path, rotation_wait=20, signature_lifetime=10, clock=clock)
    old = ring.active()
    new = ring.publish()
    assert ring.active().thumbprint == old.thumbprint  # the old key keeps signing
    assert {k.thumbprint for k in ring.published()} == {old.thumbprint, new.thumbprint}

    with pytest.raises(RotationError):
        ring.activate(new.thumbprint)  # too early: a verifier may not list it yet
    clock.now += 21
    ring.activate(new.thumbprint)
    assert ring.active().thumbprint == new.thumbprint

    with pytest.raises(RotationError):
        ring.retire(old.thumbprint)  # its signatures may not have expired
    with pytest.raises(RotationError):
        ring.retire(new.thumbprint)  # it signs
    clock.now += 11
    ring.retire(old.thumbprint)
    assert [k.thumbprint for k in ring.published()] == [new.thumbprint]


def test_publish_retire_publish_keeps_every_key(tmp_path):
    clock = Clock()
    ring = Keyring(tmp_path, rotation_wait=0, signature_lifetime=0, clock=clock)
    original = ring.active()
    first = ring.publish()
    ring.retire(first.thumbprint)  # never signed, so it can go at once
    second = ring.publish()
    assert second.thumbprint != first.thumbprint
    ring.activate(second.thumbprint)
    ring.activate(original.thumbprint)
    ring.retire(second.thumbprint)
    retired = {p.stem for p in (tmp_path / "retired").glob("*.jwk")}
    assert retired == {
        first.thumbprint,
        second.thumbprint,
    }  # both retired keys kept, neither overwritten


def test_the_state_round_trips_and_the_first_key_counts_as_published_at_zero(tmp_path):
    ring = Keyring(tmp_path, rotation_wait=20, signature_lifetime=10, clock=Clock())
    state = ring.state()
    assert state.published == {state.active: 0.0}
    assert isinstance(state.published[state.active], float)
    assert KeyringState.model_validate_json(state.model_dump_json()) == state
    assert not (tmp_path / "state.json.new").exists()  # written whole, then moved into place


def test_a_key_is_read_by_kid_published_or_retired(tmp_path):
    clock = Clock()
    ring = Keyring(tmp_path, rotation_wait=0, signature_lifetime=0, clock=clock)
    old = ring.active()
    new = ring.publish()
    ring.activate(new.thumbprint)
    ring.retire(old.thumbprint)
    assert ring.key(new.thumbprint).thumbprint == new.thumbprint
    with pytest.raises(RotationError):
        ring.key(old.thumbprint)  # retired: not published any more
    assert ring.key(old.thumbprint, include_retired=True).thumbprint == old.thumbprint
    with pytest.raises(RotationError):
        ring.key("no-such-kid", include_retired=True)
