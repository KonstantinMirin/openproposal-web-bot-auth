"""A party's signing keys: one private JWK file each, `keys/<kid>.jwk`.

Three roles over one directory:

- `KeyStore.open(directory)` reads every key and `state.json` once and holds
  them in memory. It is read-only: it never writes and never mints. A directory
  that holds no keyring raises `NoKeysError`, and a kid it doesn't hold raises
  `NotPublishedError`. The buyer's published directory and its signer read the
  store, and so do the e2e scenarios, over a read-only mount.
- `Keyring` is the one writer. `Keyring.create(directory, ...)` mints the first
  key on first boot only, and opens the store. `publish`, `activate`, and
  `retire` rotate, and each refreshes the store's view once it has written.
- `SigningIdentity(keyring, origin).signer()` signs as the party's origin with
  the active key, for the keyring's signature lifetime: the one lifetime both
  the signer and the retirement wait use.

Each key is minted here and never shared. The directory publishes every key in
`keys/`; one of them, the active key, signs. A rotation follows standard
practice, and the keyring enforces its waits:

1. `publish()` adds a new key to the directory. The old key keeps signing.
2. `activate(kid)` switches signing to it, once `rotation_wait` has passed since
   it was published. That is the longest a verifier may keep using a copy of the
   directory without the new key: an HTTP cache may hold the response for its
   `Cache-Control: max-age` (`PublishPolicy.max_age`, 300 s by default), and the
   library's resolver answers from a cached copy for `CachePolicy.max_cache_age`
   (300 s by default), so production waits 600 s.
3. `retire(kid)` takes the old key out of the directory, once every signature it
   made has expired: `signature_lifetime` after it stopped signing. Its file
   moves to `keys/retired/`.

Files are named by kid, so a published key never reuses a retired key's name.
`state.json` holds a `KeyringState`, written whole to a temporary file and moved
into place, so a reader never sees half of it. Each step builds the next state
with a named transition, a constructor call that checks every field, so a step
can't write a state the store can't read back.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from iab_agentic_primitives.web_bot_auth import Ed25519Key, RequestSigner, keyfile
from iab_agentic_primitives.web_bot_auth import Origin as LibraryOrigin
from iab_agentic_primitives.web_bot_auth.signer import SignerConfig

from persistence.values import Origin
from protocol.values import Value

_STATE = "state.json"
_RETIRED = "retired"


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


class NoKeysError(LookupError):
    """A directory that holds no keyring: no key file, or no `state.json`."""

    def __init__(self, directory: Path) -> None:
        super().__init__(f"{directory} holds no keyring")


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


@dataclass(frozen=True)
class _Keys:
    """One reading of a keyring directory."""

    state: KeyringState
    published: Mapping[str, Ed25519Key]
    retired: Mapping[str, Ed25519Key]


def _by_kid(files: list[Path]) -> dict[str, Ed25519Key]:
    """Each key file, read with the library's JWK reader, by the kid that names it."""
    return {f.stem: Ed25519Key.from_jwk(json.loads(f.read_text())) for f in sorted(files)}


def _read(directory: Path) -> _Keys:
    published = _by_kid(list(directory.glob("*.jwk")))
    state = directory / _STATE
    if not published or not state.is_file():
        raise NoKeysError(directory)
    return _Keys(
        state=KeyringState.model_validate_json(state.read_text()),
        published=published,
        retired=_by_kid(list((directory / _RETIRED).glob("*.jwk"))),
    )


class KeyStore:
    """A party's keys and rotation state, read once and held in memory. Read-only."""

    def __init__(self, directory: Path, keys: _Keys) -> None:
        """Use `KeyStore.open`."""
        self.directory, self._keys = directory, keys

    @classmethod
    def open(cls, directory: Path) -> KeyStore:
        """The keys in `directory`; raises `NoKeysError` when it holds no keyring."""
        return cls(directory, _read(directory))

    def refresh(self) -> None:
        """Reads the directory again, once the keyring has written to it."""
        self._keys = _read(self.directory)

    @property
    def state(self) -> KeyringState:
        return self._keys.state

    def key(self, kid: str, *, include_retired: bool = False) -> Ed25519Key:
        """The key `kid`, if published; or also if retired, when `include_retired`.

        Raises `NotPublishedError` for any other kid.
        """
        key = self._keys.published.get(kid)
        if key is None and include_retired:
            key = self._keys.retired.get(kid)
        if key is None:
            raise NotPublishedError(kid)
        return key

    def published(self) -> list[Ed25519Key]:
        """Every key the directory publishes, held in memory."""
        return list(self._keys.published.values())

    def active(self) -> Ed25519Key:
        return self.key(self._keys.state.active)


def _mint(directory: Path) -> Ed25519Key:
    """A new key, written with mode 0600 by the library, then named by its kid."""
    pending = directory / "minting.jwk.new"
    key = keyfile.load_or_create(pending)
    pending.rename(directory / f"{key.thumbprint}.jwk")
    return key


def _save(directory: Path, state: KeyringState) -> None:
    target = directory / _STATE
    partial = target.with_suffix(".json.new")
    partial.write_text(state.model_dump_json())
    partial.replace(target)


class Keyring:
    """The one writer of a party's keys: first boot, and the three rotation steps."""

    def __init__(
        self,
        store: KeyStore,
        *,
        rotation_wait: float,
        signature_lifetime: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.rotation_wait = rotation_wait
        self.signature_lifetime = signature_lifetime
        self._clock = clock

    @classmethod
    def create(
        cls,
        directory: Path,
        *,
        rotation_wait: float,
        signature_lifetime: int,
        clock: Callable[[], float] = time.time,
    ) -> Keyring:
        """Opens the keyring in `directory`, minting a first key on first boot only: when the
        directory holds no key."""
        if not any(directory.glob("*.jwk")):
            _save(directory, KeyringState.first(_mint(directory).thumbprint))
        return cls(
            KeyStore.open(directory),
            rotation_wait=rotation_wait,
            signature_lifetime=signature_lifetime,
            clock=clock,
        )

    def publish(self) -> Ed25519Key:
        """Step 1: a new key in the directory. It doesn't sign yet."""
        key = _mint(self.store.directory)
        self._save(self.store.state.published_at(key.thumbprint, self._clock()))
        return key

    def activate(self, kid: str) -> Ed25519Key:
        """Step 2: sign with `kid`, once every verifier's cached directory lists it."""
        self.store.key(kid)
        state = self.store.state
        ready = state.published.get(kid, 0.0) + self.rotation_wait
        if self._clock() < ready:
            raise TooEarlyError(kid, "verifiers may not list it", ready - self._clock())
        if kid != state.active:
            self._save(state.activated(kid, self._clock()))
        return self.store.active()

    def retire(self, kid: str) -> None:
        """Step 3: take `kid` out of the directory, once every signature it made has expired."""
        self.store.key(kid)
        state = self.store.state
        if kid == state.active:
            raise StillSigningError(kid)
        expired = state.stopped.get(kid, 0.0) + self.signature_lifetime
        if self._clock() < expired:
            raise TooEarlyError(kid, "its signatures last", expired - self._clock())
        path = self.store.directory / f"{kid}.jwk"
        target = self.store.directory / _RETIRED / path.name
        if target.exists():
            raise RetiredExistsError(target)
        target.parent.mkdir(exist_ok=True)
        path.rename(target)
        self.store.refresh()

    def _save(self, state: KeyringState) -> None:
        _save(self.store.directory, state)
        self.store.refresh()


@dataclass(frozen=True)
class SigningIdentity:
    """A party's signing identity: its origin, and its keyring's active key."""

    keyring: Keyring
    origin: Origin

    def signer(self) -> RequestSigner:
        """Signs as the origin with the key active now, for the keyring's signature lifetime."""
        return RequestSigner(
            SignerConfig(
                self.keyring.store.active(),
                LibraryOrigin.parse(str(self.origin)),
                lifetime=self.keyring.signature_lifetime,
            )
        )
