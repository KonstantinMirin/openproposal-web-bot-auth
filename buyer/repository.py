"""The buyer's own records, in SQLite: its sellers, its commits, and the evidence of each agreement.

`BuyerRepository` takes and returns domain values, never rows, and it is the
only buyer code that serializes for storage. `keep_agreement` writes the
seller's signed answer and settles the commit in one transaction.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from iab_agentic_primitives.web_bot_auth import Origin
from openproposal import AssentEntry, Commit, ErrorObject, dump, dump_json
from pydantic import SecretStr

from persistence import evidence
from persistence.sqlite import inserted, one_of, open_db, transaction

#: Where a commit stands: sent and waiting for a verified answer, or settled.
CommitState = Literal["pending", "agreed", "rejected"]

SCHEMA = f"""
-- A seller this buyer deals with, by origin. The buyer stores no seller key:
-- keys come from the origin's directory. bearer_token is the credential the
-- seller issued this buyer, for the bearer flow.
CREATE TABLE IF NOT EXISTS sellers (
    origin        TEXT PRIMARY KEY,
    domain        TEXT NOT NULL,
    legal_name    TEXT NOT NULL,
    bearer_token  TEXT
);
-- Each Commit the buyer composed. A pending commit is re-sent whole, with the
-- same idempotency_key, until the seller's answer verifies (§ 4.1.2, § 5.6.1).
-- An agreed commit names the seller's signed answer, the evidence it kept
-- (persistence/evidence.py); one answer settles one commit.
CREATE TABLE IF NOT EXISTS commits (
    id               INTEGER PRIMARY KEY,
    seller_origin    TEXT NOT NULL REFERENCES sellers (origin),
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


@dataclass(frozen=True)
class Counterparty:
    """A seller this buyer deals with: known by its origin, never by a key."""

    origin: Origin
    domain: str
    legal_name: str
    #: The token the seller issued this buyer, for the bearer flow.
    bearer_token: SecretStr | None = None


@dataclass(frozen=True)
class CommitKey:
    """Which commit: to this seller, on this proposal, for these line items."""

    seller_origin: str
    proposal_id: str
    line_item_ids: tuple[str, ...]

    def items_column(self) -> str:
        return json.dumps(sorted(self.line_item_ids))


@dataclass(frozen=True)
class PendingCommit:
    """A composed Commit that waits for a verified answer, and its digest input."""

    id: int
    key: CommitKey
    body: bytes
    digest_input: bytes


class NotPendingError(LookupError):
    """The commit is not pending, so it can't be settled as rejected."""


class BuyerRepository:
    def __init__(self, path: Path) -> None:
        self.db = open_db(path, evidence.SCHEMA, SCHEMA)

    def close(self) -> None:
        """Closes the connection. The app's lifespan calls it on shutdown."""
        self.db.close()

    # Sellers

    def add_counterparty(self, seller: Counterparty) -> None:
        """Records a seller once; a restart keeps the first record."""
        token = seller.bearer_token.get_secret_value() if seller.bearer_token else None
        self.db.execute(
            "INSERT OR IGNORE INTO sellers (origin, domain, legal_name, bearer_token)"
            " VALUES (?, ?, ?, ?)",
            (str(seller.origin), seller.domain, seller.legal_name, token),
        )

    def counterparty(self, origin: str) -> Counterparty | None:
        row = self.db.execute(
            "SELECT origin, domain, legal_name, bearer_token FROM sellers WHERE origin = ?",
            (origin,),
        ).fetchone()
        if row is None:
            return None
        token = row["bearer_token"]
        return Counterparty(
            Origin.parse(row["origin"]),
            row["domain"],
            row["legal_name"],
            SecretStr(token) if token else None,
        )

    # Commits

    def pending(self, key: CommitKey) -> PendingCommit | None:
        row = self.db.execute(
            "SELECT id, body, digest_input FROM commits WHERE seller_origin = ?"
            " AND proposal_id = ? AND line_item_ids = ? AND state = 'pending'",
            (key.seller_origin, key.proposal_id, key.items_column()),
        ).fetchone()
        return None if row is None else _pending(row, key)

    def add_pending(self, key: CommitKey, commit: Commit, digest_input: bytes) -> PendingCommit:
        """Keeps a composed Commit, to be sent and, until it is answered, re-sent whole."""
        body = dump_json(commit).encode()
        cursor = self.db.execute(
            "INSERT INTO commits (seller_origin, proposal_id, line_item_ids, idempotency_key, body,"
            " digest_input, state) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            (
                key.seller_origin,
                key.proposal_id,
                key.items_column(),
                commit.entry.idempotency_key,
                body,
                digest_input,
            ),
        )
        return PendingCommit(inserted(cursor), key, body, digest_input)

    def keep_agreement(
        self,
        commit_id: int,
        response: evidence.StoredResponse,
        entries: Sequence[AssentEntry],
        *,
        attributed: bool,
    ) -> int:
        """Keeps the seller's signed answer and settles the commit as agreed, in one transaction.

        Returns the kept answer's id. A commit already agreed keeps its first
        answer: a repeat writes nothing and returns that answer's id.
        """
        with transaction(self.db):
            row = self.db.execute(
                "SELECT state, response_id FROM commits WHERE id = ?", (commit_id,)
            ).fetchone()
            if row is not None and row["state"] == "agreed":
                return int(row["response_id"])
            response_id = evidence.save_response(self.db, response)
            self._settle(commit_id, "agreed", entries=json.dumps([dump(e) for e in entries]))
            self.db.execute(
                "UPDATE commits SET response_id = ?, attributed = ? WHERE id = ?",
                (response_id, int(attributed), commit_id),
            )
        return response_id

    def settle_rejected(self, commit_id: int, errors: Sequence[ErrorObject]) -> None:
        """Settles a pending commit as rejected, with the seller's stored errors (§ 5.6.1)."""
        self._settle(commit_id, "rejected", errors=json.dumps([dump(e) for e in errors]))

    def _settle(
        self,
        commit_id: int,
        state: CommitState,
        *,
        entries: str | None = None,
        errors: str | None = None,
    ) -> None:
        cursor = self.db.execute(
            "UPDATE commits SET state = ?, entries = ?, errors = ?"
            " WHERE id = ? AND state = 'pending'",
            (state, entries, errors, commit_id),
        )
        if cursor.rowcount != 1:
            raise NotPendingError(commit_id)


def _pending(row: sqlite3.Row, key: CommitKey) -> PendingCommit:
    return PendingCommit(row["id"], key, bytes(row["body"]), bytes(row["digest_input"]))
