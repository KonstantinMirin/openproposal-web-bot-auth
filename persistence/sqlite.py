"""One SQLite base for both parties: how a database opens, and the one unit of work.

Concurrency model. Each agent process holds one connection, opened by its app
lifespan and closed on shutdown. The connection is bound to the thread that
opened it (`check_same_thread=True`, sqlite3's default): every route and every
dependency provider that touches storage is `async def` and runs on the event
loop's thread, and none awaits inside a transaction, so transactions never
interleave. Storage reached from a worker thread, as a sync route would reach
it, raises `sqlite3.ProgrammingError` instead of sharing the connection.

The connection runs in autocommit, so a statement outside `transaction()`
commits on its own. Every write that must land with another runs inside one
`transaction()`.

A row is read by name, never by position: `fetch_one` and `fetch_all` return
each row as a mapping from column name to value, and a typed record (a
`Value` whose fields are the columns `select` names) validates it. A column
that is renamed, missing, or of another type fails at that first read.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import get_args

from pydantic import BaseModel

from protocol.values import Value

#: A row as read: each column's value, by the column's name.
Fetched = dict[str, object]
#: The values bound to a query's `?` placeholders, in order.
Params = Sequence[object]


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


def json_array(texts: Iterable[str]) -> str:
    """A JSON array of JSON texts, as a TEXT column holds a list of values."""
    return "[" + ",".join(texts) + "]"


def is_closed(db: sqlite3.Connection) -> bool:
    """Whether `db` is closed. Readable from any thread, unlike a query on the connection."""
    try:
        _ = db.total_changes
    except sqlite3.ProgrammingError:
        return True
    return False


def select(table: str, *records: type[BaseModel], where: str) -> str:
    """`SELECT <columns> FROM <table> WHERE <where>`, the columns being the fields of
    `records`, in order.

    A record's fields are the columns it is read from, so the query and the
    record that validates its rows can't disagree on a name.
    """
    columns = ", ".join(dict.fromkeys((name for r in records for name in r.model_fields), True))
    return f"SELECT {columns} FROM {table} WHERE {where}"  # noqa: S608 -- module constants


def fetch_one(db: sqlite3.Connection, query: str, params: Params = ()) -> Fetched | None:
    """The first row `query` returns, by column name, or None when it returns none."""
    row: sqlite3.Row | None = db.execute(query, params).fetchone()
    return None if row is None else _by_name(row)


def fetch_all(db: sqlite3.Connection, query: str, params: Params = ()) -> list[Fetched]:
    """Every row `query` returns, in order, each by column name."""
    rows: list[sqlite3.Row] = db.execute(query, params).fetchall()
    return [_by_name(row) for row in rows]


def _by_name(row: sqlite3.Row) -> Fetched:
    fetched: Fetched = dict(row)
    return fetched


class _Count(Value):
    n: int


def count(db: sqlite3.Connection, query: str, params: Params = ()) -> int:
    """The `n` that `query`, a `SELECT COUNT(*) AS n ...`, returns."""
    return _Count.model_validate(fetch_one(db, query, params)).n


def one_of(column: str, vocabulary: object) -> str:
    """A CHECK that `column` holds a term of `vocabulary`, a `Literal` or an alias of one.

    The schema mirrors the type, so a value the type refuses is refused on write too.
    """
    alias: object = getattr(vocabulary, "__value__", vocabulary)
    terms: tuple[object, ...] = get_args(alias)
    if not terms or not all(isinstance(t, str) and "'" not in t for t in terms):
        raise NotAVocabularyError(vocabulary)
    return f"CHECK ({column} IN ({', '.join(repr(t) for t in terms)}))"
