"""A signing key kept in a file: loaded when it exists, created once when it doesn't.

:func:`load_or_create` is the one filesystem helper of the module. It publishes
a new key file atomically, so concurrent first boots are safe: when several
processes start together on a fresh path, such as ``uvicorn --workers N``,
exactly one key is written, every process loads that key, and no reader ever
sees a partly written file.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path

from .keys import Ed25519Key


def _load(path: Path) -> Ed25519Key:
    return Ed25519Key.from_jwk(json.loads(path.read_text()))


def _write_private(directory: Path, key: Ed25519Key, name: str) -> Path:
    """Writes ``key`` to a new ``0600`` file in ``directory``, flushed to disk."""
    fd, temp = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(key.private_jwk(), f)
        f.flush()
        os.fsync(f.fileno())
    return Path(temp)


def load_or_create(path: str | os.PathLike[str]) -> Ed25519Key:
    """Loads the private JWK at ``path``, or generates a key and writes it there.

    The file is created with mode ``0600``. The key is written to a temporary
    file in the same directory, flushed to disk, and published at ``path``
    with a hard link, which fails if the path exists. A process that loses
    that race loads the key that won. Concurrent first boots are safe.
    """
    target = Path(path)
    with contextlib.suppress(FileNotFoundError):
        return _load(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519Key.generate()
    temp = _write_private(target.parent, key, target.name)
    try:
        os.link(temp, target)
    except FileExistsError:
        return _load(target)
    finally:
        temp.unlink()
    return key


__all__ = [
    "load_or_create",
]
