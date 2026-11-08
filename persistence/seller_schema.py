"""The seller's tables: their one definition, and each row kind as the typed record it reads as.

seller/sqlite_store.py writes these tables, and both it and the seller's read
model (persistence/observe.py) read them through the functions here. Each
record's fields are the columns a read selects (`persistence.sqlite.select`),
and the record validates every row by name: a renamed or retyped column fails
at the first read, in the store and in the read model alike. The CHECKs are
built from the same Literals that type the records, so a value the type
refuses is refused on write too.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated

from openproposal import AssentEntry, AssentEntryRole, ErrorObject
from pydantic import Discriminator, Json, Strict, TypeAdapter

from protocol.values import JsonObject, Value

from .sqlite import fetch_all, fetch_one, one_of, select
from .values import AuthMethod, BearerMethod, Origin, PrincipalKind, SignatureMethod

#: An INTEGER column that holds 0 or 1, read as a bool.
Flag = Annotated[bool, Strict(False)]

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS principals (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL {one_of("kind", PrincipalKind)},
    legal_name  TEXT NOT NULL,
    domain      TEXT NOT NULL
);
-- A credential names a principal. The seller stores a token's hash, never the
-- token, and an origin, never a key: keys come from the origin's directory.
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY,
    principal_id  TEXT NOT NULL REFERENCES principals (id),
    type          TEXT NOT NULL {one_of("type", AuthMethod)},
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
-- The assent log, in order. A buyer's entry names how its principal
-- authenticated and the signed request that carried it (persistence/evidence.py),
-- which is written with the entry and never without one.
CREATE TABLE IF NOT EXISTS assent (
    id                     INTEGER PRIMARY KEY,
    proposal_id            TEXT NOT NULL REFERENCES proposals (proposal_id),
    role                   TEXT NOT NULL {one_of("role", AssentEntryRole)},
    entry                  TEXT NOT NULL,
    idempotency_key        TEXT,
    principal_id           TEXT REFERENCES principals (id),
    authentication_method  TEXT {one_of("authentication_method", AuthMethod)},
    evidence_id            INTEGER REFERENCES signed_requests (id),
    attributed             INTEGER NOT NULL DEFAULT 0
);
-- Each commit the seller processed, by buyer and idempotency_key (§ 5.6.1).
-- A rejection whose retry isn't `same` is kept as its ErrorObject; a commit
-- that wrote an entry is answered from assent[].
CREATE TABLE IF NOT EXISTS commits (
    principal_id     TEXT NOT NULL REFERENCES principals (id),
    idempotency_key  TEXT NOT NULL,
    proposal_id      TEXT NOT NULL,
    canonical        BLOB NOT NULL,
    error            TEXT,
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


# The assent log


class KeptEntry(Value):
    """An entry in the seller's assent log, with how its principal authenticated."""

    role: AssentEntryRole
    #: The entry as the log holds it.
    entry: Json[AssentEntry]
    idempotency_key: str | None
    principal_id: str | None
    authentication_method: AuthMethod | None
    #: The kept request that carried the entry; None for a bearer entry or the seller's own.
    evidence_id: int | None
    attributed: Flag


def entries(db: sqlite3.Connection, proposal_id: str) -> list[KeptEntry]:
    """The assent log of `proposal_id`, in order."""
    query = select("assent", KeptEntry, where="proposal_id = ? ORDER BY id")
    return [KeptEntry.model_validate(row) for row in fetch_all(db, query, (proposal_id,))]


# Principals and credentials


class KeptPrincipal(Value):
    """A party the seller knows: the identity its credentials point at."""

    id: str
    kind: PrincipalKind
    legal_name: str
    domain: str


#: The principal a signature credential points at, by its origin; the seller's store finds
#: a caller's principal with the same clause.
WITH_ORIGIN = "id = (SELECT principal_id FROM credentials WHERE origin = ?)"


def principal_with_origin(db: sqlite3.Connection, origin: Origin) -> KeptPrincipal | None:
    """The principal the signature credential `origin` points at, if any."""
    query = select("principals", KeptPrincipal, where=WITH_ORIGIN)
    row = fetch_one(db, query, (str(origin),))
    return None if row is None else KeptPrincipal.model_validate(row)


class KeptOriginCredential(Value):
    """A signature credential: the origin whose directory holds the principal's keys."""

    type: SignatureMethod = "web_bot_auth"
    origin: Origin
    token_hash: None = None


class KeptTokenCredential(Value):
    """A bearer credential: the hash of the token the seller issued, never the token."""

    type: BearerMethod = "bearer"
    origin: None = None
    token_hash: str


#: A credential the seller holds for a principal: exactly one of the two shapes the
#: table's CHECK allows, told apart by its `type`.
KeptCredential = Annotated[KeptOriginCredential | KeptTokenCredential, Discriminator("type")]
_CREDENTIAL: TypeAdapter[KeptCredential] = TypeAdapter(KeptCredential)


def credentials(db: sqlite3.Connection, principal_id: str) -> list[KeptCredential]:
    """The credentials that name `principal_id`, in the order they were added."""
    query = select(
        "credentials",
        KeptOriginCredential,
        KeptTokenCredential,
        where="principal_id = ? ORDER BY id",
    )
    return [_CREDENTIAL.validate_python(row) for row in fetch_all(db, query, (principal_id,))]


# Issued proposals


class IssuedRow(Value):
    """An issued proposal as the table holds it: its buyer, and its document as JSON."""

    buyer_principal_id: str
    document: Json[JsonObject]


def issued(db: sqlite3.Connection, proposal_id: str) -> IssuedRow | None:
    query = select("proposals", IssuedRow, where="proposal_id = ?")
    row = fetch_one(db, query, (proposal_id,))
    return None if row is None else IssuedRow.model_validate(row)


# Processed commits (§ 5.6.1)


class ProcessedRow(Value):
    """A commit the seller processed, and the rejection it stored, if any."""

    idempotency_key: str
    proposal_id: str
    #: The commit's canonical bytes, which a replay must equal.
    canonical: bytes
    error: Json[ErrorObject] | None


def processed(db: sqlite3.Connection, principal_id: str, key: str) -> ProcessedRow | None:
    """The commit `principal_id` sent under `key`, if the seller processed one."""
    query = select("commits", ProcessedRow, where="principal_id = ? AND idempotency_key = ?")
    row = fetch_one(db, query, (principal_id, key))
    return None if row is None else ProcessedRow.model_validate(row)


def processed_on(db: sqlite3.Connection, proposal_id: str) -> list[ProcessedRow]:
    """The commits the seller processed on `proposal_id`, by idempotency key."""
    query = select("commits", ProcessedRow, where="proposal_id = ? ORDER BY idempotency_key")
    return [ProcessedRow.model_validate(row) for row in fetch_all(db, query, (proposal_id,))]


# Agreed records


class KeptAgreement(Value):
    """An agreed record (§ 4.1.2): its digest input, and the digest over it."""

    record_digest: str
    digest_input: bytes


def agreed(db: sqlite3.Connection, proposal_id: str) -> list[KeptAgreement]:
    """The agreed records of `proposal_id`, in order."""
    query = select("agreed_records", KeptAgreement, where="proposal_id = ? ORDER BY id")
    return [KeptAgreement.model_validate(row) for row in fetch_all(db, query, (proposal_id,))]
