"""The buyer's signing keys: one private JWK file each, `keys/<kid>.jwk`, minted here and never shared.

The directory publishes every key in `keys/`; one of them, the active key,
signs. A rotation follows standard practice, and the keyring enforces its waits:

1. `publish()` adds a new key to the directory. The old key keeps signing.
2. `activate(kid)` switches signing to it, once `rotation_wait` has passed since
   it was published. That is the longest a verifier may keep using a copy of the
   directory without the new key: an HTTP cache may hold the response for its
   `Cache-Control: max-age` (`DirectoryMiddleware`'s `max_age`, 300 s by
   default), and the library's verifier answers from a cached copy for
   `FetchPolicy.max_cache_age` (300 s by default), so production waits 600 s.
3. `retire(kid)` takes the old key out of the directory, once every signature it
   made has expired: `signature_lifetime` after it stopped signing. Its file
   moves to `keys/retired/`.

Files are named by kid, so a published key never reuses a retired key's name.
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
            kid = self._mint().kid
            self._save({"active": kid, "published": {kid: 0}, "stopped": {}})

    def _files(self) -> list[Path]:
        return sorted(self.directory.glob("*.jwk"))

    def _mint(self) -> Ed25519Key:
        """A new key, written with mode 0600 by the library, then named by its kid."""
        pending = self.directory / "minting.jwk.new"
        key = Ed25519Key.load_or_create(pending)
        pending.rename(self.directory / f"{key.kid}.jwk")
        return key

    def _state(self) -> dict:
        return json.loads(self._state_file.read_text())

    def _save(self, state: dict) -> None:
        self._state_file.write_text(json.dumps(state))

    def _published(self, kid: str) -> Path:
        path = self.directory / f"{kid}.jwk"
        if not path.exists():
            raise RotationError(f"no published key {kid}")
        return path

    def published(self) -> list[Ed25519Key]:
        return [Ed25519Key.load_or_create(f) for f in self._files()]

    def active(self) -> Ed25519Key:
        return Ed25519Key.load_or_create(self._published(self._state()["active"]))

    def publish(self) -> Ed25519Key:
        """Step 1: a new key in the directory. It doesn't sign yet."""
        key = self._mint()
        state = self._state()
        state["published"][key.kid] = self._clock()
        self._save(state)
        return key

    def activate(self, kid: str) -> Ed25519Key:
        """Step 2: sign with `kid`, once every verifier's cached directory lists it."""
        self._published(kid)
        state = self._state()
        ready = state["published"].get(kid, 0) + self.rotation_wait
        if self._clock() < ready:
            raise RotationError(f"{kid} is published; verifiers may not list it for "
                                f"{ready - self._clock():.0f} s more")
        if kid != state["active"]:
            state["stopped"][state["active"]] = self._clock()
            state["active"] = kid
            self._save(state)
        return self.active()

    def retire(self, kid: str) -> None:
        """Step 3: take `kid` out of the directory, once every signature it made has expired."""
        path, state = self._published(kid), self._state()
        if kid == state["active"]:
            raise RotationError(f"{kid} still signs")
        expired = state["stopped"].get(kid, 0) + self.signature_lifetime
        if self._clock() < expired:
            raise RotationError(f"signatures by {kid} last {expired - self._clock():.0f} s more")
        target = self.directory / "retired" / path.name
        if target.exists():
            raise RotationError(f"{target} exists; refusing to overwrite a retired key")
        target.parent.mkdir(exist_ok=True)
        path.rename(target)
