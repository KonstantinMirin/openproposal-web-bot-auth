"""Keeping the key directory a signature verified against (§ 4.1.2, Signed messages).

§ 4.1.2: a party that keeps evidence keeps "the bytes of the key directory it
verified against". Each verification stores the `VerifiedDirectory` it used:
the exact body bytes, the header lines with that fetch's own directory
signatures, and when it was fetched. Two rows merge only when all of that is
identical, which happens when two signatures verified against one cached fetch.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3

import rfc8785
from iab_agentic_primitives.web_bot_auth import VerifiedDirectory

DIRECTORIES_SCHEMA = """
-- A verified key directory response: one row per fetch. evidence is
-- VerifiedDirectory.evidence(); body holds the exact bytes verified.
CREATE TABLE IF NOT EXISTS directories (
    digest      TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    status      INTEGER NOT NULL,
    headers     TEXT NOT NULL,
    body        BLOB NOT NULL,
    fetched_at  REAL,
    evidence    TEXT NOT NULL
);
"""


def save_directory(db: sqlite3.Connection, directory: VerifiedDirectory | None) -> str | None:
    """Stores the directory a verification used and returns its row key."""
    if directory is None:
        return None
    headers = [list(line) for line in directory.headers]
    fetch = {
        "url": directory.url,
        "status": directory.status,
        "headers": headers,
        "fetched_at": directory.fetched_at,
    }
    digest = hashlib.sha256(rfc8785.dumps(fetch) + directory.body).hexdigest()
    db.execute(
        "INSERT OR IGNORE INTO directories"
        " (digest, url, status, headers, body, fetched_at, evidence)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            digest,
            directory.url,
            directory.status,
            json.dumps(headers),
            directory.body,
            directory.fetched_at,
            json.dumps(directory.evidence()),
        ),
    )
    return digest
