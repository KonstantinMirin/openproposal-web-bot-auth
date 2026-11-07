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
    assert ring.active().kid == old.kid  # the old key keeps signing
    assert {k.kid for k in ring.published()} == {old.kid, new.kid}

    with pytest.raises(RotationError):
        ring.activate(new.kid)  # too early: a verifier may not list it yet
    clock.now += 21
    ring.activate(new.kid)
    assert ring.active().kid == new.kid

    with pytest.raises(RotationError):
        ring.retire(old.kid)  # its signatures may not have expired
    with pytest.raises(RotationError):
        ring.retire(new.kid)  # it signs
    clock.now += 11
    ring.retire(old.kid)
    assert [k.kid for k in ring.published()] == [new.kid]


def test_publish_retire_publish_keeps_every_key(tmp_path):
    clock = Clock()
    ring = Keyring(tmp_path, rotation_wait=0, signature_lifetime=0, clock=clock)
    original = ring.active()
    first = ring.publish()
    ring.retire(first.kid)  # never signed, so it can go at once
    second = ring.publish()
    assert second.kid != first.kid
    ring.activate(second.kid)
    ring.activate(original.kid)
    ring.retire(second.kid)
    retired = {p.stem for p in (tmp_path / "retired").glob("*.jwk")}
    assert retired == {first.kid, second.kid}  # both retired keys kept, neither overwritten


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
    ring.activate(new.kid)
    ring.retire(old.kid)
    assert ring.key(new.kid).kid == new.kid
    with pytest.raises(RotationError):
        ring.key(old.kid)  # retired: not published any more
    assert ring.key(old.kid, include_retired=True).kid == old.kid
    with pytest.raises(RotationError):
        ring.key("no-such-kid", include_retired=True)
