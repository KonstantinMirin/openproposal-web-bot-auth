"""The buyer's own records, in SQLite: its sellers, its commits, and their evidence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from iab_agentic_primitives.web_bot_auth import VerifiedDirectory

from shared.evidence import DIRECTORIES_SCHEMA, save_directory

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
-- The signed response that carried the seller's entry, as received, with the
-- request it is bound to (§ 4.1.2, Signed messages).
CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY,
    commit_id         INTEGER NOT NULL REFERENCES commits (id),
    origin            TEXT NOT NULL,
    keyid             TEXT NOT NULL,
    attributed        INTEGER NOT NULL,
    request_method    TEXT NOT NULL,
    request_url       TEXT NOT NULL,
    request_headers   TEXT NOT NULL,
    request_body      BLOB NOT NULL,
    status            INTEGER NOT NULL,
    headers           TEXT NOT NULL,
    body              BLOB NOT NULL,
    directory_digest  TEXT REFERENCES directories (digest)
);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(DIRECTORIES_SCHEMA + SCHEMA)

    def close(self) -> None:
        """Closes the connection. The app's lifespan calls it on shutdown."""
        self.db.close()

    def add_seller(
        self, origin: str, domain: str, legal_name: str, bearer_token: str | None
    ) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO sellers (origin, domain, legal_name, bearer_token)"
            " VALUES (?, ?, ?, ?)",
            (origin, domain, legal_name, bearer_token),
        )

    def seller(self, origin: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM sellers WHERE origin = ?", (origin,)).fetchone()
        return dict(row) if row else None

    def pending_commit(self, seller_origin: str, proposal_id: str, line_item_ids: list[str]):
        return self.db.execute(
            "SELECT * FROM commits WHERE seller_origin = ? AND proposal_id = ?"
            " AND line_item_ids = ? AND state = 'pending'",
            (seller_origin, proposal_id, json.dumps(sorted(line_item_ids))),
        ).fetchone()

    def add_commit(
        self,
        seller_origin: str,
        proposal_id: str,
        line_item_ids: list[str],
        idempotency_key: str,
        body: bytes,
        digest_input: bytes,
    ) -> sqlite3.Row:
        cursor = self.db.execute(
            "INSERT INTO commits (seller_origin, proposal_id, line_item_ids, idempotency_key, body,"
            " digest_input, state) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            (
                seller_origin,
                proposal_id,
                json.dumps(sorted(line_item_ids)),
                idempotency_key,
                body,
                digest_input,
            ),
        )
        return self.db.execute("SELECT * FROM commits WHERE id = ?", (cursor.lastrowid,)).fetchone()

    def settle_commit(
        self, commit_id: int, state: str, *, entries: list | None = None, errors: list | None = None
    ) -> None:
        self.db.execute(
            "UPDATE commits SET state = ?, entries = ?, errors = ? WHERE id = ?",
            (
                state,
                json.dumps(entries) if entries else None,
                json.dumps(errors) if errors else None,
                commit_id,
            ),
        )

    def record_evidence(
        self,
        *,
        commit_id: int,
        origin: str,
        keyid: str,
        attributed: bool,
        request: tuple[str, str, list[tuple[str, str]], bytes],
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
        directory: VerifiedDirectory | None,
    ) -> int:
        """Stores the seller's signed answer as received, with the request it is bound to."""
        method, url, request_headers, request_body = request
        digest = save_directory(self.db, directory)
        cursor = self.db.execute(
            "INSERT INTO evidence (commit_id, origin, keyid, attributed, request_method,"
            " request_url, request_headers, request_body, status, headers, body, directory_digest)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                commit_id,
                origin,
                keyid,
                int(attributed),
                method,
                url,
                json.dumps(request_headers),
                request_body,
                status,
                json.dumps(headers),
                body,
                digest,
            ),
        )
        return cursor.lastrowid
