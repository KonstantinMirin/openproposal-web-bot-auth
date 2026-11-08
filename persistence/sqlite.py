"""One SQLite base for both parties: how a database opens, and the one unit of work.

Concurrency model. Each agent process holds one connection, opened by its app
lifespan and closed on shutdown. The connection is bound to the thread that
opened it (`check_same_thread=True`, sqlite3's default): every route that
touches storage is `async def` and runs on the event loop's thread, and none
awaits inside a transaction, so transactions never interleave. Storage reached
from a worker thread, as a sync route would reach it, raises
`sqlite3.ProgrammingError` instead of sharing the connection.

The connection runs in autocommit, so a statement outside `transaction()`
commits on its own. Every write that must land with another runs inside one
`transaction()`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import get_args


class NoRowIdError(RuntimeError):
    """An INSERT reported no row id, so there is no row to name."""


class NotAVocabularyError(TypeError):
    def __init__(self, vocabulary: object) -> None:
        super().__init__(f"{vocabulary!r} is not a Literal of plain strings")


def open_db(path: Path, *schemas: str) -> sqlite3.Connection:
    """Opens (and creates) the database at `path` and applies `schemas`, in order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("".join(schemas))
    return db


@contextmanager
def open_read_only(path: Path | str) -> Iterator[sqlite3.Connection]:
    """A party's database, opened read-only, as an observer outside the party opens it."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[None]:
    """`with transaction(db):` runs the block as one SQLite transaction.

    `BEGIN IMMEDIATE` takes the write lock up front. The block's error rolls
    the transaction back and propagates. So does a failing `COMMIT`, for
    example a deferred foreign key or `SQLITE_BUSY`, which SQLite leaves open:
    the connection never stays inside a transaction after the block.
    """
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def inserted(cursor: sqlite3.Cursor) -> int:
    """The row id of the row `cursor` just inserted."""
    if cursor.lastrowid is None:
        raise NoRowIdError
    return cursor.lastrowid


def one_of(column: str, vocabulary: object) -> str:
    """A CHECK that `column` holds a term of `vocabulary`, a `Literal` or an alias of one.

    The schema mirrors the type, so a value the type refuses is refused on write too.
    """
    terms = get_args(getattr(vocabulary, "__value__", vocabulary))
    if not terms or not all(isinstance(t, str) and "'" not in t for t in terms):
        raise NotAVocabularyError(vocabulary)
    return f"CHECK ({column} IN ({', '.join(repr(t) for t in terms)}))"
