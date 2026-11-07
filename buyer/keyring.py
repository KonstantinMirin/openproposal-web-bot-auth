"""The buyer's signing keys: one private JWK file each, minted on first boot, never shared.

The directory publishes every key in `keys/`. The newest key signs. Rotating
adds a key; retiring moves an old key's file to `keys/retired/`, so it leaves the
directory.
"""

from __future__ import annotations

from pathlib import Path

from iab_agentic_primitives.web_bot_auth import Ed25519Key


class Keyring:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        if not self._files():
            Ed25519Key.load_or_create(directory / "0001.jwk")

    def _files(self) -> list[Path]:
        return sorted(self.directory.glob("*.jwk"))

    def published(self) -> list[Ed25519Key]:
        return [Ed25519Key.load_or_create(f) for f in self._files()]

    def active(self) -> Ed25519Key:
        return Ed25519Key.load_or_create(self._files()[-1])

    def add(self) -> Ed25519Key:
        number = int(self._files()[-1].stem) + 1
        return Ed25519Key.load_or_create(self.directory / f"{number:04d}.jwk")

    def retire(self, kid: str) -> bool:
        files = self._files()
        for f in files:
            if Ed25519Key.load_or_create(f).kid == kid and len(files) > 1:
                (self.directory / "retired").mkdir(exist_ok=True)
                f.rename(self.directory / "retired" / f.name)
                return True
        return False
