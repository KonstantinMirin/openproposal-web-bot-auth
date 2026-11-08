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

`EvidenceReader` is the one reader of these tables, for the party itself and
for observers outside it (the live runner, the e2e scenarios), which open a
party's database read-only. transport/reverify.py verifies what it reads
again, offline.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Self

from protocol.record import sha256_hex
from protocol.values import JsonObject, JsonValue, canonical

from .sqlite import inserted
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


def _lines(lines: tuple[HeaderLine, ...]) -> str:
    return json.dumps([[name, value] for name, value in lines])


def _decoded(text: str) -> tuple[HeaderLine, ...]:
    return tuple((str(name), str(value)) for name, value in json.loads(text))


def save_request(db: sqlite3.Connection, kept: SignedRequest) -> int:
    """Keeps a request and the directory that confirmed it; returns its row id."""
    request, signer = kept.request, kept.signer
    cursor = db.execute(
        "INSERT INTO signed_requests (origin, keyid, method, url, headers, body, directory_digest)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(signer.origin),
            signer.keyid,
            request.method,
            request.url,
            _lines(request.lines),
            request.body,
            save_directory(db, signer.directory),
        ),
    )
    return inserted(cursor)


def save_response(db: sqlite3.Connection, kept: SignedResponse) -> int:
    """Keeps a response, the request it answers, and both directories; returns its row id."""
    response, signer = kept.response, kept.signer
    request_id = save_request(
        db, SignedRequest(request=response.request, signer=kept.request_signer)
    )
    cursor = db.execute(
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
            save_directory(db, signer.directory),
        ),
    )
    return inserted(cursor)


def save_directory(db: sqlite3.Connection, directory: DirectoryFetch | None) -> str | None:
    """Stores the directory a verification used and returns its row key."""
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
    db.execute(
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


class NoEvidenceError(LookupError):
    """No kept message or directory has this id."""


class EvidenceReader:
    """Reads a party's kept messages and directories."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    @classmethod
    @contextmanager
    def open(cls, path: Path | str) -> Iterator[Self]:
        """A party's database, opened read-only, as an observer outside the party opens it."""
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            yield cls(db)
        finally:
            db.close()

    def _count(self, query: str, *args: object) -> int:
        return int(self.db.execute(query, args).fetchone()[0])

    def _signer(self, row: sqlite3.Row) -> Signer:
        digest = row["directory_digest"]
        return Signer(
            origin=Origin.parse(row["origin"]),
            keyid=row["keyid"],
            directory=None if digest is None else self.directory(digest),
        )

    def request(self, request_id: int) -> SignedRequest:
        row = self.db.execute(
            "SELECT origin, keyid, method, url, headers, body, directory_digest"
            " FROM signed_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise NoEvidenceError(request_id)
        request = KeptRequest(
            method=row["method"],
            url=row["url"],
            lines=_decoded(row["headers"]),
            body=bytes(row["body"]),
            id=request_id,
        )
        return SignedRequest(request=request, signer=self._signer(row))

    def response(self, response_id: int) -> SignedResponse:
        row = self.db.execute(
            "SELECT request_id, origin, keyid, status, headers, body, directory_digest"
            " FROM signed_responses WHERE id = ?",
            (response_id,),
        ).fetchone()
        if row is None:
            raise NoEvidenceError(response_id)
        request = self.request(row["request_id"])
        response = KeptResponse(
            status=row["status"],
            lines=_decoded(row["headers"]),
            body=bytes(row["body"]),
            request=request.request,
            id=response_id,
        )
        return SignedResponse(
            response=response, signer=self._signer(row), request_signer=request.signer
        )

    def directory(self, digest: str) -> DirectoryFetch:
        row = self.db.execute(
            "SELECT url, status, headers, body, fetched_at FROM directories WHERE digest = ?",
            (digest,),
        ).fetchone()
        if row is None:
            raise NoEvidenceError(digest)
        return DirectoryFetch(
            url=row["url"],
            status=row["status"],
            lines=_decoded(row["headers"]),
            body=bytes(row["body"]),
            fetched_at=row["fetched_at"],
        )

    def directories(self) -> int:
        """How many directory fetches the party kept."""
        return self._count("SELECT COUNT(*) FROM directories")

    def directories_of(self, origin: Origin) -> int:
        """How many kept directory fetches came from `origin`."""
        return self._count("SELECT COUNT(*) FROM directories WHERE url = ?", origin.directory_url)

    def requests_from(self, origin: Origin) -> int:
        """How many kept requests `origin` signed."""
        return self._count("SELECT COUNT(*) FROM signed_requests WHERE origin = ?", str(origin))

    def requests_with_body(self, body: bytes) -> int:
        return self._count("SELECT COUNT(*) FROM signed_requests WHERE body = ?", body)
