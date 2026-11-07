"""Evidence both parties keep, in one schema (§ 4.1.2, Signed messages).

A party keeps the counterparty's signed message as exact bytes: the method and
URL or the status, every header line as received or sent, in order and with
its own case, and the body. A response is stored with the request it is bound
to. `StoredRequest` and `StoredResponse` carry the library's own `HTTPRequest`
and `HTTPResponse`, and `load_request` and `load_response` rebuild equal ones.

§ 4.1.2 also asks a party to keep "the bytes of the key directory it verified
against". Each verification stores the `VerifiedDirectory` it used: the exact
body bytes, the header lines with that fetch's own directory signatures, and
when it was fetched. Two rows merge only when all of that is identical, which
happens when two signatures verified against one cached fetch.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from iab_agentic_primitives.web_bot_auth import (
    HeaderLines,
    HTTPRequest,
    HTTPResponse,
    VerifiedDirectory,
)

from protocol.record import canonical, sha256_hex
from protocol.values import JsonObject, JsonValue

from .sqlite import inserted

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

#: The signed messages a party keeps. headers is a JSON array of [name, value]
#: lines, in order, as sent or received.
MESSAGES_SCHEMA = """
-- A request: one the party verified (origin and keyid are its signer's), or one
-- the party sent, which a kept response is bound to (keyid is NULL when it
-- carried a bearer token instead of a signature, and the token is not kept).
CREATE TABLE IF NOT EXISTS signed_requests (
    id                INTEGER PRIMARY KEY,
    origin            TEXT NOT NULL,
    keyid             TEXT,
    method            TEXT NOT NULL,
    url               TEXT NOT NULL,
    headers           TEXT NOT NULL,
    body              BLOB NOT NULL,
    directory_digest  TEXT REFERENCES directories (digest)
);
-- A verified response, with the request it answers.
CREATE TABLE IF NOT EXISTS signed_responses (
    id                INTEGER PRIMARY KEY,
    request_id        INTEGER NOT NULL REFERENCES signed_requests (id),
    origin            TEXT NOT NULL,
    keyid             TEXT NOT NULL,
    status            INTEGER NOT NULL,
    headers           TEXT NOT NULL,
    body              BLOB NOT NULL,
    directory_digest  TEXT REFERENCES directories (digest)
);
"""

#: Every table this module writes, for a party's `open_db`.
SCHEMA = DIRECTORIES_SCHEMA + MESSAGES_SCHEMA

#: A kept response by id, with the request it answers as request_* columns. For
#: readers outside the party (the runner, the e2e) until Step 7's read model.
RESPONSE_WITH_REQUEST = (
    "SELECT r.id, r.origin, r.keyid, r.status, r.headers, r.body, r.directory_digest,"
    " q.method AS request_method, q.url AS request_url, q.headers AS request_headers,"
    " q.body AS request_body"
    " FROM signed_responses r JOIN signed_requests q ON q.id = r.request_id WHERE r.id = ?"
)


@dataclass(frozen=True)
class StoredRequest:
    """A request to keep: who signed it, with which key, and the directory that confirmed it."""

    request: HTTPRequest
    origin: str
    keyid: str | None
    directory: VerifiedDirectory | None = None


@dataclass(frozen=True)
class StoredResponse:
    """A verified response to keep, bound to `request`."""

    response: HTTPResponse
    request: StoredRequest
    origin: str
    keyid: str
    directory: VerifiedDirectory | None = None


def _lines(headers: HeaderLines) -> str:
    return json.dumps([[name, value] for name, value in headers])


def _headers(text: str) -> list[tuple[str, str]]:
    return [(str(name), str(value)) for name, value in json.loads(text)]


def save_request(db: sqlite3.Connection, stored: StoredRequest) -> int:
    """Keeps a request and the directory that confirmed it; returns its row id."""
    request = stored.request
    cursor = db.execute(
        "INSERT INTO signed_requests (origin, keyid, method, url, headers, body, directory_digest)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            stored.origin,
            stored.keyid,
            request.method,
            request.url,
            _lines(request.headers),
            request.body,
            save_directory(db, stored.directory),
        ),
    )
    return inserted(cursor)


def save_response(db: sqlite3.Connection, stored: StoredResponse) -> int:
    """Keeps a response, the request it answers, and both directories; returns its row id."""
    request_id = save_request(db, stored.request)
    response = stored.response
    cursor = db.execute(
        "INSERT INTO signed_responses"
        " (request_id, origin, keyid, status, headers, body, directory_digest)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            request_id,
            stored.origin,
            stored.keyid,
            response.status,
            _lines(response.headers),
            response.body,
            save_directory(db, stored.directory),
        ),
    )
    return inserted(cursor)


class NoEvidenceError(LookupError):
    """No kept message has this id."""


def load_request(db: sqlite3.Connection, request_id: int) -> HTTPRequest:
    """The kept request, as the library's `HTTPRequest`."""
    row = db.execute(
        "SELECT method, url, headers, body FROM signed_requests WHERE id = ?", (request_id,)
    ).fetchone()
    if row is None:
        raise NoEvidenceError(request_id)
    return HTTPRequest(row["method"], row["url"], _headers(row["headers"]), row["body"])


def load_response(db: sqlite3.Connection, response_id: int) -> HTTPResponse:
    """The kept response, as the library's `HTTPResponse`, bound to the request it answers."""
    row = db.execute(
        "SELECT request_id, status, headers, body FROM signed_responses WHERE id = ?",
        (response_id,),
    ).fetchone()
    if row is None:
        raise NoEvidenceError(response_id)
    request = load_request(db, row["request_id"])
    return HTTPResponse(row["status"], _headers(row["headers"]), row["body"], request)


def save_directory(db: sqlite3.Connection, directory: VerifiedDirectory | None) -> str | None:
    """Stores the directory a verification used and returns its row key."""
    if directory is None:
        return None
    headers: list[JsonValue] = [[name, value] for name, value in directory.headers]
    fetch: JsonObject = {
        "url": directory.url,
        "status": directory.status,
        "headers": headers,
        "fetched_at": directory.fetched_at,
    }
    digest = sha256_hex(canonical(fetch) + directory.body)
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
