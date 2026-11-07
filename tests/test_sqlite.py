"""The one unit of work: a failed block or a failed COMMIT never leaves a transaction open."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Literal

import pytest

from persistence.sqlite import (
    NoRowIdError,
    NotAVocabularyError,
    inserted,
    one_of,
    open_db,
    transaction,
)

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


def test_open_db_creates_the_directory_and_enforces_foreign_keys(tmp_path: Path) -> None:
    db = open_db(tmp_path / "a" / "b" / "test.db", SCHEMA)
    assert (tmp_path / "a" / "b" / "test.db").exists()
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO strict_child (parent_id) VALUES (7)")


def test_inserted_refuses_a_missing_row_id(db: sqlite3.Connection) -> None:
    assert inserted(db.execute("INSERT INTO parent (id) VALUES (5)")) == 5
    with pytest.raises(NoRowIdError):
        inserted(db.cursor())  # a cursor that inserted nothing has no lastrowid


def test_one_of_mirrors_a_literal_and_refuses_anything_else(db: sqlite3.Connection) -> None:
    check = one_of("state", Literal["pending", "agreed"])
    assert check == "CHECK (state IN ('pending', 'agreed'))"
    db.execute(f"CREATE TABLE t (state TEXT {check})")
    db.execute("INSERT INTO t VALUES ('agreed')")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO t VALUES ('agred')")
    with pytest.raises(NotAVocabularyError):
        one_of("state", str)
    with pytest.raises(NotAVocabularyError):
        one_of("state", Literal["it's"])
