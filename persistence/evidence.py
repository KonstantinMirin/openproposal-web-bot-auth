"""Evidence both parties keep, in one schema (§ 4.1.2, Signed messages).

A party keeps the counterparty's signed message as exact bytes: the method and
URL or the status, every header line as received or sent, in order and with
its own case, and the body. A response is stored with the request it is bound
to. Each is kept and read back as the one value persistence/values.py defines
for it: a `SignedRequest` or a `SignedResponse`, whose `Signer` names the
origin and key that signed it.

§ 4.1.2 also asks a party to keep "the bytes of the key directory it verified
against". Each verification stores the directory response it used (a
`DirectoryFetch`): the exact body bytes, the header lines with that fetch's own
directory signatures, and when it was fetched. Two rows merge only when all of
that is identical, which happens when two signatures verified against one
cached fetch.

`EvidenceStore` is the one owner of these tables: the party's store keeps
evidence through it, inside its own transaction, and the read models of
persistence/observe.py read through it for observers outside the party (the
live runner, the e2e scenarios). It holds kept values only and verifies
nothing; transport/reverify.py verifies what it returns again, offline.
"""

from __future__ import annotations

import json
import sqlite3

from pydantic import Json

from protocol.record import sha256_hex
from protocol.values import JsonObject, JsonValue, Value, canonical

from .sqlite import Fetched, count, fetch_one, inserted, select
from .values import (
    DirectoryFetch,
    HeaderLine,
    KeptRequest,
    KeptResponse,
    Origin,
    SignedRequest,
    SignedResponse,
    Signer,
)

DIRECTORIES_SCHEMA = """
-- A verified key directory response: one row per fetch. body holds the exact
-- bytes verified.
CREATE TABLE IF NOT EXISTS directories (
    digest      TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    status      INTEGER NOT NULL,
    headers     TEXT NOT NULL,
    body        BLOB NOT NULL,
    fetched_at  INTEGER NOT NULL
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


#: Header lines as a `headers` column holds them, read back.
_Lines = Json[tuple[HeaderLine, ...]]


def _lines(lines: tuple[HeaderLine, ...]) -> str:
    pairs: list[list[str]] = [[name, value] for name, value in lines]
    return json.dumps(pairs)


class _RequestRow(Value):
    origin: Origin
    keyid: str | None
    method: str
    url: str
    headers: _Lines
    body: bytes
    directory_digest: str | None


class _ResponseRow(Value):
    request_id: int
    origin: Origin
    keyid: str
    status: int
    headers: _Lines
    body: bytes
    directory_digest: str | None


class _DirectoryRow(Value):
    url: str
    status: int
    headers: _Lines
    body: bytes
    fetched_at: int


class NoEvidenceError(LookupError):
    """No kept message or directory has this id."""


class EvidenceStore:
    """A party's kept messages and directories, over the party's own connection.

    Writes run in the caller's transaction, so evidence lands with the record
    it backs, or not at all.
    """

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    # Keeping

    def keep_request(self, kept: SignedRequest) -> int:
        """Keeps a request and the directory that confirmed it; returns its row id."""
        request, signer = kept.request, kept.signer
        cursor = self._db.execute(
            "INSERT INTO signed_requests"
            " (origin, keyid, method, url, headers, body, directory_digest)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(signer.origin),
                signer.keyid,
                request.method,
                request.url,
                _lines(request.lines),
                request.body,
                self.keep_directory(signer.directory),
            ),
        )
        return inserted(cursor)

    def keep_response(self, kept: SignedResponse) -> int:
        """Keeps a response, the request it answers, and both directories; returns its row id."""
        response, signer = kept.response, kept.signer
        request_id = self.keep_request(
            SignedRequest(request=response.request, signer=kept.request_signer)
        )
        cursor = self._db.execute(
            "INSERT INTO signed_responses"
            " (request_id, origin, keyid, status, headers, body, directory_digest)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                request_id,
                str(signer.origin),
                signer.keyid,
                response.status,
                _lines(response.lines),
                response.body,
                self.keep_directory(signer.directory),
            ),
        )
        return inserted(cursor)

    def keep_directory(self, directory: DirectoryFetch | None) -> str | None:
        """Keeps the directory a verification used and returns its row key."""
        if directory is None:
            return None
        headers: list[JsonValue] = [[name, value] for name, value in directory.lines]
        fetch: JsonObject = {
            "url": directory.url,
            "status": directory.status,
            "headers": headers,
            "fetched_at": directory.fetched_at,
        }
        digest = sha256_hex(canonical(fetch) + directory.body)
        self._db.execute(
            "INSERT OR IGNORE INTO directories (digest, url, status, headers, body, fetched_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                digest,
                directory.url,
                directory.status,
                json.dumps(headers),
                directory.body,
                directory.fetched_at,
            ),
        )
        return digest

    # Reading

    def request(self, request_id: int) -> SignedRequest:
        query = select("signed_requests", _RequestRow, where="id = ?")
        row = _RequestRow.model_validate(self._found(query, request_id))
        request = KeptRequest(
            method=row.method, url=row.url, lines=row.headers, body=row.body, id=request_id
        )
        return SignedRequest(request=request, signer=self._signer(row))

    def response(self, response_id: int) -> SignedResponse:
        query = select("signed_responses", _ResponseRow, where="id = ?")
        row = _ResponseRow.model_validate(self._found(query, response_id))
        request = self.request(row.request_id)
        response = KeptResponse(
            status=row.status,
            lines=row.headers,
            body=row.body,
            request=request.request,
            id=response_id,
        )
        return SignedResponse(
            response=response, signer=self._signer(row), request_signer=request.signer
        )

    def directory(self, digest: str) -> DirectoryFetch:
        query = select("directories", _DirectoryRow, where="digest = ?")
        row = _DirectoryRow.model_validate(self._found(query, digest))
        return DirectoryFetch(
            url=row.url,
            status=row.status,
            lines=row.headers,
            body=row.body,
            fetched_at=row.fetched_at,
        )

    def _found(self, query: str, key: int | str) -> Fetched:
        row = fetch_one(self._db, query, (key,))
        if row is None:
            raise NoEvidenceError(key)
        return row

    def _signer(self, row: _RequestRow | _ResponseRow) -> Signer:
        digest = row.directory_digest
        return Signer(
            origin=row.origin,
            keyid=row.keyid,
            directory=None if digest is None else self.directory(digest),
        )

    # Counts, for the observers

    def directories(self) -> int:
        """How many directory fetches the party kept."""
        return count(self._db, "SELECT COUNT(*) AS n FROM directories")

    def directories_of(self, origin: Origin) -> int:
        """How many kept directory fetches came from `origin`."""
        query = "SELECT COUNT(*) AS n FROM directories WHERE url = ?"
        return count(self._db, query, (origin.directory_url,))

    def messages(self) -> int:
        """How many signed messages the party kept, requests and responses together."""
        query = (
            "SELECT (SELECT COUNT(*) FROM signed_requests)"
            " + (SELECT COUNT(*) FROM signed_responses) AS n"
        )
        return count(self._db, query)

    def requests_from(self, origin: Origin) -> int:
        """How many kept requests `origin` signed."""
        query = "SELECT COUNT(*) AS n FROM signed_requests WHERE origin = ?"
        return count(self._db, query, (str(origin),))

    def requests_with_body(self, body: bytes) -> int:
        """How many kept requests carried exactly `body`."""
        query = "SELECT COUNT(*) AS n FROM signed_requests WHERE body = ?"
        return count(self._db, query, (body,))
