"""The seller's own records, in SQLite: who its buyers are, what it offered, and what was agreed."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from shared.wba import DirectoryBytes

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('buyer')),
    legal_name  TEXT NOT NULL,
    domain      TEXT NOT NULL
);
-- A credential names a principal. The seller stores a token's hash, never the
-- token, and an origin, never a key: keys come from the origin's directory.
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY,
    principal_id  TEXT NOT NULL REFERENCES principals (id),
    type          TEXT NOT NULL CHECK (type IN ('bearer', 'web_bot_auth')),
    token_hash    TEXT UNIQUE,
    origin        TEXT UNIQUE,
    CHECK ((type = 'bearer' AND token_hash IS NOT NULL AND origin IS NULL)
        OR (type = 'web_bot_auth' AND origin IS NOT NULL AND token_hash IS NULL))
);
-- An issued proposal (§ 4.3): its Full Representation without assent[], which
-- the assent table holds.
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id         TEXT PRIMARY KEY,
    buyer_principal_id  TEXT NOT NULL REFERENCES principals (id),
    document            TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS directories (
    digest   TEXT PRIMARY KEY,
    url      TEXT NOT NULL,
    headers  TEXT NOT NULL,
    body     BLOB NOT NULL
);
-- A confirmed signed request, as received (§ 4.1.2, Signed messages).
CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY,
    origin            TEXT NOT NULL,
    keyid             TEXT NOT NULL,
    method            TEXT NOT NULL,
    url               TEXT NOT NULL,
    headers           TEXT NOT NULL,
    body              BLOB NOT NULL,
    directory_digest  TEXT REFERENCES directories (digest)
);
CREATE TABLE IF NOT EXISTS assent (
    id                     INTEGER PRIMARY KEY,
    proposal_id            TEXT NOT NULL REFERENCES proposals (proposal_id),
    role                   TEXT NOT NULL,
    entry                  TEXT NOT NULL,
    idempotency_key        TEXT,
    principal_id           TEXT REFERENCES principals (id),
    authentication_method  TEXT,
    evidence_id            INTEGER REFERENCES evidence (id),
    attributed             INTEGER NOT NULL DEFAULT 0
);
-- Each commit the seller processed, by buyer and idempotency_key (§ 5.6.1).
-- A rejection whose retry isn't `same` is kept; a commit that wrote an entry
-- is answered from assent[].
CREATE TABLE IF NOT EXISTS commits (
    principal_id     TEXT NOT NULL REFERENCES principals (id),
    idempotency_key  TEXT NOT NULL,
    proposal_id      TEXT NOT NULL,
    canonical        BLOB NOT NULL,
    status           INTEGER,
    errors           TEXT,
    PRIMARY KEY (principal_id, idempotency_key)
);
-- The agreed record of a matching pair: its digest input and the two entries (§ 4.1.2).
CREATE TABLE IF NOT EXISTS agreed_records (
    id             INTEGER PRIMARY KEY,
    proposal_id    TEXT NOT NULL,
    record_digest  TEXT NOT NULL,
    digest_input   BLOB NOT NULL,
    entries        TEXT NOT NULL
);
"""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    # Principals and credentials

    def add_principal(self, id: str, legal_name: str, domain: str) -> None:
        self.db.execute(
            "INSERT INTO principals (id, kind, legal_name, domain) VALUES (?, 'buyer', ?, ?)",
            (id, legal_name, domain),
        )

    def add_origin_credential(self, principal_id: str, origin: str) -> None:
        self.db.execute(
            "INSERT INTO credentials (principal_id, type, origin) VALUES (?, 'web_bot_auth', ?)",
            (principal_id, origin),
        )

    def add_token_credential(self, principal_id: str, token: str) -> None:
        self.db.execute(
            "INSERT INTO credentials (principal_id, type, token_hash) VALUES (?, 'bearer', ?)",
            (principal_id, token_hash(token)),
        )

    def _principal_where(self, column: str, value: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT p.id, p.kind, p.legal_name, p.domain FROM credentials c"
            f" JOIN principals p ON p.id = c.principal_id WHERE c.{column} = ?",
            (value,),
        ).fetchone()
        return dict(row) if row else None

    def principal_for_origin(self, origin: str) -> dict[str, Any] | None:
        return self._principal_where("origin", origin)

    def principal_for_token(self, token: str) -> dict[str, Any] | None:
        return self._principal_where("token_hash", token_hash(token))

    def is_empty(self) -> bool:
        return self.db.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 0

    # Evidence

    def record_evidence(
        self,
        *,
        origin: str,
        keyid: str,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        directory: DirectoryBytes | None,
    ) -> int:
        digest = None
        if directory is not None:
            digest = hashlib.sha256(directory.body).hexdigest()
            self.db.execute(
                "INSERT OR IGNORE INTO directories (digest, url, headers, body) VALUES (?, ?, ?, ?)",
                (digest, directory.url, json.dumps(directory.headers), directory.body),
            )
        cursor = self.db.execute(
            "INSERT INTO evidence (origin, keyid, method, url, headers, body, directory_digest)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (origin, keyid, method, url, json.dumps(headers), body, digest),
        )
        return cursor.lastrowid

    # Proposals and assent

    def add_proposal(self, buyer_principal_id: str, document: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO proposals (proposal_id, buyer_principal_id, document) VALUES (?, ?, ?)",
            (document["proposal_id"], buyer_principal_id, json.dumps(document)),
        )

    def proposal(self, proposal_id: str) -> tuple[str, dict[str, Any]] | None:
        row = self.db.execute(
            "SELECT buyer_principal_id, document FROM proposals WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def save_proposal(self, document: dict[str, Any]) -> None:
        self.db.execute(
            "UPDATE proposals SET document = ? WHERE proposal_id = ?",
            (json.dumps(document), document["proposal_id"]),
        )

    def assent(self, proposal_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT entry FROM assent WHERE proposal_id = ? ORDER BY id", (proposal_id,)
        )
        return [json.loads(r[0]) for r in rows]

    def append_assent(
        self,
        proposal_id: str,
        entry: dict[str, Any],
        *,
        principal_id: str | None = None,
        authentication_method: str | None = None,
        evidence_id: int | None = None,
        attributed: bool = False,
    ) -> None:
        self.db.execute(
            "INSERT INTO assent (proposal_id, role, entry, idempotency_key, principal_id,"
            " authentication_method, evidence_id, attributed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                proposal_id,
                entry["role"],
                json.dumps(entry),
                entry.get("idempotency_key"),
                principal_id,
                authentication_method,
                evidence_id,
                int(attributed),
            ),
        )

    def add_agreed_record(
        self, proposal_id: str, record_digest: str, digest_input: bytes, entries: list[dict]
    ) -> None:
        self.db.execute(
            "INSERT INTO agreed_records (proposal_id, record_digest, digest_input, entries)"
            " VALUES (?, ?, ?, ?)",
            (proposal_id, record_digest, digest_input, json.dumps(entries)),
        )

    # Processed commits (§ 5.6.1)

    def processed_commit(self, principal_id: str, idempotency_key: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM commits WHERE principal_id = ? AND idempotency_key = ?",
            (principal_id, idempotency_key),
        ).fetchone()

    def record_commit(
        self,
        principal_id: str,
        idempotency_key: str,
        proposal_id: str,
        canonical: bytes,
        rejection: tuple[int, list[dict]] | None = None,
    ) -> None:
        status, errors = rejection if rejection else (None, None)
        self.db.execute(
            "INSERT INTO commits (principal_id, idempotency_key, proposal_id, canonical, status, errors)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (principal_id, idempotency_key, proposal_id, canonical, status,
             json.dumps(errors) if errors else None),
        )

    def transaction(self):
        """`with store.transaction():` runs the block as one SQLite transaction."""
        return _Transaction(self.db)


class _Transaction:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def __enter__(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")

    def __exit__(self, kind, value, traceback) -> None:
        self.db.execute("COMMIT" if kind is None else "ROLLBACK")
