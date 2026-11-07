"""The buyer's own records, in SQLite: the sellers it deals with, its commits, and their evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from iab_agentic_primitives.web_bot_auth import VerifiedDirectory

SCHEMA = """
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
CREATE TABLE IF NOT EXISTS commits (
    id               INTEGER PRIMARY KEY,
    seller_origin    TEXT NOT NULL REFERENCES sellers (origin),
    proposal_id      TEXT NOT NULL,
    line_item_ids    TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL UNIQUE,
    body             BLOB NOT NULL,
    digest_input     BLOB NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('pending', 'agreed', 'rejected')),
    entries          TEXT,
    errors           TEXT
);
-- A verified key directory, as VerifiedDirectory.evidence() gives it: the URL,
-- status, header lines (its signatures included), body, and fetch time.
CREATE TABLE IF NOT EXISTS directories (
    digest    TEXT PRIMARY KEY,
    url       TEXT NOT NULL,
    evidence  TEXT NOT NULL
);
-- The signed response that carried the seller's entry, as received, with the
-- request it is bound to (§ 4.1.2, Signed messages).
CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY,
    commit_id         INTEGER NOT NULL REFERENCES commits (id),
    origin            TEXT NOT NULL,
    keyid             TEXT NOT NULL,
    attributed        INTEGER NOT NULL,
    request           TEXT NOT NULL,
    status            INTEGER NOT NULL,
    headers           TEXT NOT NULL,
    body              BLOB NOT NULL,
    directory_digest  TEXT REFERENCES directories (digest)
);
"""


def _save_directory(db: sqlite3.Connection, directory: VerifiedDirectory | None) -> str | None:
    """Stores a verified directory's evidence once, keyed by the SHA-256 of its body."""
    if directory is None:
        return None
    digest = hashlib.sha256(directory.body).hexdigest()
    db.execute("INSERT OR IGNORE INTO directories (digest, url, evidence) VALUES (?, ?, ?)",
               (digest, directory.url, json.dumps(directory.evidence())))
    return digest


class Store:
    def __init__(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def add_seller(self, origin: str, domain: str, legal_name: str, bearer_token: str | None) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO sellers (origin, domain, legal_name, bearer_token) VALUES (?, ?, ?, ?)",
            (origin, domain, legal_name, bearer_token),
        )

    def seller(self, origin: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM sellers WHERE origin = ?", (origin,)).fetchone()
        return dict(row) if row else None

    def pending_commit(self, seller_origin: str, proposal_id: str, line_item_ids: list[str]):
        return self.db.execute(
            "SELECT * FROM commits WHERE seller_origin = ? AND proposal_id = ? AND line_item_ids = ?"
            " AND state = 'pending'",
            (seller_origin, proposal_id, json.dumps(sorted(line_item_ids))),
        ).fetchone()

    def add_commit(self, seller_origin: str, proposal_id: str, line_item_ids: list[str],
                   idempotency_key: str, body: bytes, digest_input: bytes) -> sqlite3.Row:
        cursor = self.db.execute(
            "INSERT INTO commits (seller_origin, proposal_id, line_item_ids, idempotency_key, body,"
            " digest_input, state) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            (seller_origin, proposal_id, json.dumps(sorted(line_item_ids)), idempotency_key, body,
             digest_input),
        )
        return self.db.execute("SELECT * FROM commits WHERE id = ?", (cursor.lastrowid,)).fetchone()

    def settle_commit(self, commit_id: int, state: str, *, entries: list | None = None,
                      errors: list | None = None) -> None:
        self.db.execute(
            "UPDATE commits SET state = ?, entries = ?, errors = ? WHERE id = ?",
            (state, json.dumps(entries) if entries else None, json.dumps(errors) if errors else None,
             commit_id),
        )

    def record_evidence(self, *, commit_id: int, origin: str, keyid: str, attributed: bool,
                        request: dict[str, Any], status: int, headers: list[tuple[str, str]],
                        body: bytes, directory: VerifiedDirectory | None) -> int:
        digest = _save_directory(self.db, directory)
        cursor = self.db.execute(
            "INSERT INTO evidence (commit_id, origin, keyid, attributed, request, status, headers,"
            " body, directory_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (commit_id, origin, keyid, int(attributed), json.dumps(request), status,
             json.dumps(headers), body, digest),
        )
        return cursor.lastrowid
