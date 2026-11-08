"""The buyer's tables: their one definition, and each commit row as the typed record it reads as.

buyer/repository.py writes these tables, and both it and the buyer's read model
(persistence/observe.py) read commits through the functions here. A record's
fields are the columns a read selects (`persistence.sqlite.select`), and the
record validates every row by name, so a renamed or retyped column fails at
the first read in the repository and in the read model alike.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Literal

from protocol.values import Value

from .sqlite import fetch_all, fetch_one, one_of, select
from .values import Origin

#: Where a commit stands: sent and waiting for a verified answer, or settled.
CommitState = Literal["pending", "agreed", "rejected"]

SCHEMA = f"""
-- Each Commit the buyer composed, to the seller at seller_origin. The buyer's
-- settings name its sellers (buyer/settings.py); it stores no seller, no
-- seller key, and no token. A pending commit is re-sent whole, with the
-- same idempotency_key, until the seller's answer verifies (§ 4.1.2, § 5.6.1).
-- An agreed commit names the seller's signed answer, the evidence it kept
-- (persistence/evidence.py); one answer settles one commit.
CREATE TABLE IF NOT EXISTS commits (
    id               INTEGER PRIMARY KEY,
    seller_origin    TEXT NOT NULL,
    proposal_id      TEXT NOT NULL,
    line_item_ids    TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL UNIQUE,
    body             BLOB NOT NULL,
    digest_input     BLOB NOT NULL,
    state            TEXT NOT NULL {one_of("state", CommitState)},
    entries          TEXT,
    errors           TEXT,
    response_id      INTEGER UNIQUE REFERENCES signed_responses (id),
    attributed       INTEGER
);
"""


def items_column(line_item_ids: Iterable[str]) -> str:
    """How `commits.line_item_ids` holds a set of line items: a sorted JSON array."""
    items: list[str] = sorted(line_item_ids)
    return json.dumps(items)


class KeptCommit(Value):
    """A Commit the buyer composed, and where it stands."""

    id: int
    state: CommitState
    idempotency_key: str
    #: The Commit as sent, and re-sent until it is answered.
    body: bytes
    digest_input: bytes
    #: The seller's signed answer that settled it as agreed; None until then.
    response_id: int | None


def commit(db: sqlite3.Connection, commit_id: int) -> KeptCommit | None:
    row = fetch_one(db, select("commits", KeptCommit, where="id = ?"), (commit_id,))
    return None if row is None else KeptCommit.model_validate(row)


def commits_on(
    db: sqlite3.Connection, proposal_id: str, line_item_ids: Iterable[str]
) -> list[KeptCommit]:
    """The commits on these line items of `proposal_id`, to any seller, oldest first."""
    where = "proposal_id = ? AND line_item_ids = ? ORDER BY id"
    query = select("commits", KeptCommit, where=where)
    rows = fetch_all(db, query, (proposal_id, items_column(line_item_ids)))
    return [KeptCommit.model_validate(row) for row in rows]


def pending(
    db: sqlite3.Connection, seller: Origin, proposal_id: str, line_item_ids: Iterable[str]
) -> KeptCommit | None:
    """The commit to `seller` on these line items of `proposal_id` that waits for an answer."""
    where = "seller_origin = ? AND proposal_id = ? AND line_item_ids = ? AND state = 'pending'"
    query = select("commits", KeptCommit, where=where)
    row = fetch_one(db, query, (str(seller), proposal_id, items_column(line_item_ids)))
    return None if row is None else KeptCommit.model_validate(row)
