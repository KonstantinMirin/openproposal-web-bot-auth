"""The one unit of work: a failed block or a failed COMMIT never leaves a transaction open."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from persistence.sqlite import open_db, transaction

SCHEMA = """
CREATE TABLE IF NOT EXISTS parent (id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS child (
    parent_id INTEGER REFERENCES parent (id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS strict_child (parent_id INTEGER REFERENCES parent (id));
"""


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    return open_db(tmp_path / "nested" / "test.db", SCHEMA)


def _count(db: sqlite3.Connection, table: str) -> int:
    row = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608 -- a literal table
    return int(row[0])


def test_a_failing_commit_rolls_back_and_the_next_transaction_commits(
    db: sqlite3.Connection,
) -> None:
    """Defect 1: a COMMIT that fails (here, a deferred foreign key) used to leave the
    connection inside the transaction, so every later transaction failed until restart."""
    with pytest.raises(sqlite3.IntegrityError), transaction(db):
        db.execute("INSERT INTO child (parent_id) VALUES (42)")
    assert db.in_transaction is False
    assert _count(db, "child") == 0

    with transaction(db):
        db.execute("INSERT INTO parent (id) VALUES (1)")
        db.execute("INSERT INTO child (parent_id) VALUES (1)")
    assert _count(db, "child") == 1


def test_an_error_in_the_block_rolls_back_and_propagates(db: sqlite3.Connection) -> None:
    class Boom(Exception):
        pass

    with pytest.raises(Boom), transaction(db):
        db.execute("INSERT INTO parent (id) VALUES (1)")
        raise Boom
    assert db.in_transaction is False
    assert _count(db, "parent") == 0


def test_a_transaction_takes_the_write_lock_up_front(tmp_path: Path) -> None:
    first, second = open_db(tmp_path / "x.db", SCHEMA), open_db(tmp_path / "x.db", SCHEMA)
    second.execute("PRAGMA busy_timeout = 0")
    with transaction(first), pytest.raises(sqlite3.OperationalError, match="locked"):
        second.execute("BEGIN IMMEDIATE")
