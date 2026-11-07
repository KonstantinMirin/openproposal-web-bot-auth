"""Evidence both parties keep, in one schema (§ 4.1.2, Signed messages).

A party keeps the counterparty's signed message as exact bytes: the method and
URL or the status, every header line as received or sent, in order and with
its own case, and the body. A response is stored with the request it is bound
to. `StoredRequest` and `StoredResponse` carry the library's own `HTTPRequest`
and `HTTPResponse`, and `EvidenceReader` rebuilds equal ones.

§ 4.1.2 also asks a party to keep "the bytes of the key directory it verified
against". Each verification stores the directory response it used (a
`KeptDirectory`, such as the library's `VerifiedDirectory`): the exact body
bytes, the header lines with that fetch's own directory signatures, and when it
was fetched. Two rows merge only when all of that is identical, which happens
when two signatures verified against one cached fetch.

`EvidenceReader` is the one reader of these tables, for the party itself and
for observers outside it (the live runner, the e2e scenarios), which open a
party's database read-only. It verifies a kept message again, offline, against
the directory bytes kept with it.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self

from iab_agentic_primitives.web_bot_auth import (
    DirectoryResponse,
    HeaderLines,
    HTTPRequest,
    HTTPResponse,
    MemoryNonceStore,
    Origin,
    RequestVerifier,
    ResponseVerifier,
    ServerIdentity,
    StaticKeyResolver,
    VerifiedRequest,
    VerifiedResponse,
    parse_directory_response,
)

from protocol.record import canonical, sha256_hex
from protocol.values import JsonObject, JsonValue

from .sqlite import inserted

DIRECTORIES_SCHEMA = """
-- A verified key directory response: one row per fetch. body holds the exact
-- bytes verified.
CREATE TABLE IF NOT EXISTS directories (
    digest      TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    status      INTEGER NOT NULL,
    headers     TEXT NOT NULL,
    body        BLOB NOT NULL,
    fetched_at  REAL
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


class KeptDirectory(Protocol):
    """A verified key directory response, as fetched: what § 4.1.2 asks a party to keep."""

    @property
    def url(self) -> str | None: ...
    @property
    def status(self) -> int: ...
    @property
    def headers(self) -> Iterable[tuple[str, str]]: ...
    @property
    def body(self) -> bytes: ...
    @property
    def fetched_at(self) -> int | None: ...


@dataclass(frozen=True)
class StoredRequest:
    """A request to keep: who signed it, with which key, and the directory that confirmed it."""

    request: HTTPRequest
    origin: str
    keyid: str | None
    directory: KeptDirectory | None = None


@dataclass(frozen=True)
class StoredResponse:
    """A verified response to keep, bound to `request`."""

    response: HTTPResponse
    request: StoredRequest
    origin: str
    keyid: str
    directory: KeptDirectory | None = None


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


def save_directory(db: sqlite3.Connection, directory: KeptDirectory | None) -> str | None:
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


@dataclass(frozen=True)
class KeptFetch:
    """A kept directory response, as it was fetched; a `KeptDirectory`."""

    digest: str
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    fetched_at: int | None


@dataclass(frozen=True)
class KeptRequest:
    """A kept request, and who signed it with which key, as the party recorded them."""

    id: int
    request: HTTPRequest
    origin: str
    keyid: str | None
    directory_digest: str | None


@dataclass(frozen=True)
class KeptResponse:
    """A kept response, bound to the kept request it answers."""

    id: int
    response: HTTPResponse
    request: KeptRequest
    origin: str
    keyid: str
    directory_digest: str | None


class EvidenceReader:
    """Reads a party's kept messages and directories, and verifies them again offline."""

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

    def request(self, request_id: int) -> KeptRequest:
        row = self.db.execute(
            "SELECT origin, keyid, method, url, headers, body, directory_digest"
            " FROM signed_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise NoEvidenceError(request_id)
        request = HTTPRequest(row["method"], row["url"], _headers(row["headers"]), row["body"])
        return KeptRequest(
            request_id, request, row["origin"], row["keyid"], row["directory_digest"]
        )

    def response(self, response_id: int) -> KeptResponse:
        row = self.db.execute(
            "SELECT request_id, origin, keyid, status, headers, body, directory_digest"
            " FROM signed_responses WHERE id = ?",
            (response_id,),
        ).fetchone()
        if row is None:
            raise NoEvidenceError(response_id)
        request = self.request(row["request_id"])
        response = HTTPResponse(
            row["status"], _headers(row["headers"]), row["body"], request.request
        )
        return KeptResponse(
            response_id, response, request, row["origin"], row["keyid"], row["directory_digest"]
        )

    def directory(self, digest: str) -> KeptFetch:
        row = self.db.execute(
            "SELECT url, status, headers, body, fetched_at FROM directories WHERE digest = ?",
            (digest,),
        ).fetchone()
        if row is None:
            raise NoEvidenceError(digest)
        fetched_at = None if row["fetched_at"] is None else int(row["fetched_at"])
        headers = tuple(_headers(row["headers"]))
        return KeptFetch(digest, row["url"], row["status"], headers, row["body"], fetched_at)

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

    def directory_keys(self, digest: str, origin: Origin) -> StaticKeyResolver:
        """The keys of a kept directory of `origin`, after the library verifies its kept bytes
        again. The authority is the origin's own (`Origin.authority`), derived here once."""
        kept = self.directory(digest)
        if kept.fetched_at is None:  # a fetch time says what the directory's expiry is against
            raise NoEvidenceError(digest)
        fetch = DirectoryResponse(
            kept.url, kept.status, list(kept.headers), kept.body, kept.fetched_at
        )
        directory = parse_directory_response(fetch, origin.authority, kept.fetched_at)
        return StaticKeyResolver({origin: directory.keys})

    async def reverify_request(
        self, kept: KeptRequest, identity: ServerIdentity
    ) -> VerifiedRequest:
        """Verifies a kept request again, as the party `identity` received it."""
        if kept.directory_digest is None:
            raise NoEvidenceError(kept.id)
        origin = Origin.parse(kept.origin)
        verifier = RequestVerifier(
            self.directory_keys(kept.directory_digest, origin),
            identity=identity,
            nonces=MemoryNonceStore(),
        )
        return await verifier.verify(kept.request)

    async def reverify_response(self, kept: KeptResponse) -> VerifiedResponse:
        """Verifies a kept response again, with its binding to the kept request."""
        if kept.directory_digest is None:
            raise NoEvidenceError(kept.id)
        origin = Origin.parse(kept.origin)
        verifier = ResponseVerifier(self.directory_keys(kept.directory_digest, origin))
        return await verifier.verify(kept.response, expected_origin=origin)
