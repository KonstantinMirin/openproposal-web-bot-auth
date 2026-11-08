"""A party's signing keys: one private JWK file each, `keys/<kid>.jwk`.

Each key is minted here and never shared.

The directory publishes every key in `keys/`; one of them, the active key,
signs. A rotation follows standard practice, and the keyring enforces its waits:

1. `publish()` adds a new key to the directory. The old key keeps signing.
2. `activate(kid)` switches signing to it, once `rotation_wait` has passed since
   it was published. That is the longest a verifier may keep using a copy of the
   directory without the new key: an HTTP cache may hold the response for its
   `Cache-Control: max-age` (`DirectoryMiddleware`'s `max_age`, 300 s by
   default), and the library's verifier answers from a cached copy for
   `MemoryDirectoryStore.max_cache_age` (300 s by default), so production waits 600 s.
3. `retire(kid)` takes the old key out of the directory, once every signature it
   made has expired: `signature_lifetime` after it stopped signing. Its file
   moves to `keys/retired/`.

Files are named by kid, so a published key never reuses a retired key's name.
`state.json` holds a `KeyringState`, written whole to a temporary file and moved
into place, so a reader never sees half of it. Each step builds the next state
with a named transition, a constructor call that checks every field, so a step
can't write a state the keyring can't read back. `key(kid)` is how anyone else
reads a key, the e2e scenarios included.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from iab_agentic_primitives.web_bot_auth import Ed25519Key, keyfile

from protocol.values import Value


class KeyringState(Value):
    """`state.json`: the active kid, and when each key was published and stopped signing."""

    active: str
    #: Unix time each key was published. The first key counts as published at 0.0.
    published: dict[str, float]
    #: Unix time each key stopped signing.
    stopped: dict[str, float]

    @classmethod
    def first(cls, kid: str) -> KeyringState:
        """A keyring's first state: `kid` signs, and counts as published at 0.0."""
        return cls(active=kid, published={kid: 0.0}, stopped={})

    def published_at(self, kid: str, at: float) -> KeyringState:
        """The next state once `kid` is published at `at`. The active key keeps signing."""
        return KeyringState(
            active=self.active, published={**self.published, kid: at}, stopped=self.stopped
        )

    def activated(self, kid: str, at: float) -> KeyringState:
        """The next state once `kid` signs from `at`: the key it replaces stopped signing then."""
        return KeyringState(
            active=kid,
            published=self.published,
            stopped={**self.stopped, self.active: at},
        )


class RotationError(Exception):
    """A rotation step asked for before its wait has passed, or on the wrong key."""


class NotPublishedError(RotationError):
    def __init__(self, kid: str) -> None:
        super().__init__(f"no published key {kid}")


class TooEarlyError(RotationError):
    def __init__(self, kid: str, step: str, seconds: float) -> None:
        super().__init__(f"{kid}: {step} for {seconds:.0f} s more")


class StillSigningError(RotationError):
    def __init__(self, kid: str) -> None:
        super().__init__(f"{kid} still signs")


class RetiredExistsError(RotationError):
    def __init__(self, path: Path) -> None:
        super().__init__(f"{path} exists; refusing to overwrite a retired key")


class Keyring:
    def __init__(
        self,
        directory: Path,
        *,
        rotation_wait: float,
        signature_lifetime: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Opens the keyring in `directory`, minting a first key when it holds none."""
        self.directory = directory
        self.rotation_wait = rotation_wait
        self.signature_lifetime = signature_lifetime
        self._clock = clock
        self._state_file = directory / "state.json"
        if not self._files():
            kid = self._mint().thumbprint
            self._save(KeyringState.first(kid))

    def _files(self) -> list[Path]:
        return sorted(self.directory.glob("*.jwk"))

    def _mint(self) -> Ed25519Key:
        """A new key, written with mode 0600 by the library, then named by its kid."""
        pending = self.directory / "minting.jwk.new"
        key = keyfile.load_or_create(pending)
        pending.rename(self.directory / f"{key.thumbprint}.jwk")
        return key

    def state(self) -> KeyringState:
        return KeyringState.model_validate_json(self._state_file.read_text())

    def _save(self, state: KeyringState) -> None:
        partial = self._state_file.with_suffix(".json.new")
        partial.write_text(state.model_dump_json())
        partial.replace(self._state_file)

    def _published(self, kid: str) -> Path:
        path = self.directory / f"{kid}.jwk"
        if not path.exists():
            raise NotPublishedError(kid)
        return path

    def key(self, kid: str, *, include_retired: bool = False) -> Ed25519Key:
        """The key `kid`, if published; or also if retired, when `include_retired`."""
        retired = self.directory / "retired" / f"{kid}.jwk"
        if include_retired and not (self.directory / f"{kid}.jwk").exists() and retired.exists():
            return keyfile.load_or_create(retired)
        return keyfile.load_or_create(self._published(kid))

    def published(self) -> list[Ed25519Key]:
        return [keyfile.load_or_create(f) for f in self._files()]

    def active(self) -> Ed25519Key:
        return self.key(self.state().active)

    def publish(self) -> Ed25519Key:
        """Step 1: a new key in the directory. It doesn't sign yet."""
        key = self._mint()
        self._save(self.state().published_at(key.thumbprint, self._clock()))
        return key

    def activate(self, kid: str) -> Ed25519Key:
        """Step 2: sign with `kid`, once every verifier's cached directory lists it."""
        self._published(kid)
        state = self.state()
        ready = state.published.get(kid, 0.0) + self.rotation_wait
        if self._clock() < ready:
            raise TooEarlyError(kid, "verifiers may not list it", ready - self._clock())
        if kid != state.active:
            self._save(state.activated(kid, self._clock()))
        return self.active()

    def retire(self, kid: str) -> None:
        """Step 3: take `kid` out of the directory, once every signature it made has expired."""
        path, state = self._published(kid), self.state()
        if kid == state.active:
            raise StillSigningError(kid)
        expired = state.stopped.get(kid, 0.0) + self.signature_lifetime
        if self._clock() < expired:
            raise TooEarlyError(kid, "its signatures last", expired - self._clock())
        target = self.directory / "retired" / path.name
        if target.exists():
            raise RetiredExistsError(target)
        target.parent.mkdir(exist_ok=True)
        path.rename(target)
