"""The buyer's signing keys: one private JWK file each, minted on first boot, never shared.

The directory publishes every key in `keys/`; one of them, the active key,
signs. A rotation follows standard practice, and the keyring enforces its waits:

1. `publish()` adds a new key to the directory. The old key keeps signing.
2. `activate(kid)` switches signing to it, once `rotation_wait` has passed since
   it was published. Set that to the longest time a verifier serves a cached
   directory without fetching it again: the library's
   `FetchPolicy.max_cache_age` (300 s by default) for the sellers you call.
3. `retire(kid)` takes the old key out of the directory, once every signature it
   made has expired: `signature_lifetime` after it stopped signing. Its file
   moves to `keys/retired/`.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path

from iab_agentic_primitives.web_bot_auth import Ed25519Key


class RotationError(Exception):
    """A rotation step asked for before its wait has passed, or on the wrong key."""


class Keyring:
    def __init__(self, directory: Path, *, rotation_wait: float, signature_lifetime: float,
                 clock: Callable[[], float] = time.time) -> None:
        self.directory = directory
        self.rotation_wait = rotation_wait
        self.signature_lifetime = signature_lifetime
        self._clock = clock
        self._state_file = directory / "state.json"
        if not self._files():
            Ed25519Key.load_or_create(directory / "0001.jwk")
            self._save({"active": "0001.jwk", "published": {"0001.jwk": 0}, "stopped": {}})

    def _files(self) -> list[Path]:
        return sorted(self.directory.glob("*.jwk"))

    def _state(self) -> dict:
        return json.loads(self._state_file.read_text())

    def _save(self, state: dict) -> None:
        self._state_file.write_text(json.dumps(state))

    def _file_of(self, kid: str) -> Path:
        for f in self._files():
            if Ed25519Key.load_or_create(f).kid == kid:
                return f
        raise RotationError(f"no published key {kid}")

    def published(self) -> list[Ed25519Key]:
        return [Ed25519Key.load_or_create(f) for f in self._files()]

    def active(self) -> Ed25519Key:
        return Ed25519Key.load_or_create(self.directory / self._state()["active"])

    def publish(self) -> Ed25519Key:
        """Step 1: a new key in the directory. It doesn't sign yet."""
        name = f"{int(self._files()[-1].stem) + 1:04d}.jwk"
        key = Ed25519Key.load_or_create(self.directory / name)
        state = self._state()
        state["published"][name] = self._clock()
        self._save(state)
        return key

    def activate(self, kid: str) -> Ed25519Key:
        """Step 2: sign with `kid`, once every verifier's cached directory lists it."""
        name, state = self._file_of(kid).name, self._state()
        ready = state["published"].get(name, 0) + self.rotation_wait
        if self._clock() < ready:
            raise RotationError(f"{kid} is published; verifiers may not list it for "
                                f"{ready - self._clock():.0f} s more")
        if name != state["active"]:
            state["stopped"][state["active"]] = self._clock()
            state["active"] = name
            self._save(state)
        return self.active()

    def retire(self, kid: str) -> None:
        """Step 3: take `kid` out of the directory, once every signature it made has expired."""
        name, state = self._file_of(kid).name, self._state()
        if name == state["active"]:
            raise RotationError(f"{kid} still signs")
        expired = state["stopped"].get(name, 0) + self.signature_lifetime
        if self._clock() < expired:
            raise RotationError(f"signatures by {kid} last {expired - self._clock():.0f} s more")
        (self.directory / "retired").mkdir(exist_ok=True)
        (self.directory / name).rename(self.directory / "retired" / name)
