"""The seller's own records, in SQLite: who its buyers are, what it offered, and what was agreed.

`SqliteSellerStore` implements every port in seller/ports.py. It is the only
seller code that serializes for storage: each value has one row mapper here.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from iab_agentic_primitives.web_bot_auth import HTTPRequest
from openproposal import AssentEntry, AssentEntryRole, ErrorObject, dump, dump_json

from persistence import evidence
from persistence.sqlite import one_of, open_db, transaction
from protocol.record import sha256_hex
from protocol.values import JsonObject
from transport.auth import AuthMethod

from .caller import ResolvedCaller, SignatureCredential
from .ports import PrincipalRecord, ProcessedCommit, StoredProposal

SCHEMA = f"""
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

_PRINCIPAL_BY_CREDENTIAL = (
    "SELECT p.id, p.legal_name, p.domain FROM credentials c"
    " JOIN principals p ON p.id = c.principal_id"
)


def token_hash(token: str) -> str:
    """What the seller stores for a bearer token: its SHA-256, never the token."""
    return sha256_hex(token.encode())


def _principal(row: sqlite3.Row | None) -> PrincipalRecord | None:
    if row is None:
        return None
    return PrincipalRecord(id=row["id"], legal_name=row["legal_name"], domain=row["domain"])


def _document(text: str) -> JsonObject:
    document: JsonObject = json.loads(text)
    return document


def _signed_request(signature: SignatureCredential) -> evidence.StoredRequest:
    """The verified request as the evidence schema keeps it: the exact lines, in order."""
    message = signature.message
    lines = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in message.headers]
    request = HTTPRequest(message.method, message.url, lines, message.body)
    return evidence.StoredRequest(request, signature.origin, signature.keyid, message.directory)


class SqliteSellerStore:
    def __init__(self, path: Path) -> None:
        self.db = open_db(path, evidence.SCHEMA, SCHEMA)

    def close(self) -> None:
        """Closes the connection. The app's lifespan calls it on shutdown."""
        self.db.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """`with store.transaction():` runs the block as one SQLite transaction."""
        with transaction(self.db):
            yield

    # Principals and credentials (PrincipalDirectory, Onboarding)

    def is_empty(self) -> bool:
        return self.db.execute("SELECT 1 FROM principals LIMIT 1").fetchone() is None

    def add_principal(self, principal: PrincipalRecord) -> None:
        self.db.execute(
            "INSERT INTO principals (id, kind, legal_name, domain) VALUES (?, 'buyer', ?, ?)",
            (principal.id, principal.legal_name, principal.domain),
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

    def principal(self, principal_id: str) -> PrincipalRecord | None:
        return _principal(
            self.db.execute(
                "SELECT id, legal_name, domain FROM principals WHERE id = ?", (principal_id,)
            ).fetchone()
        )

    def for_origin(self, origin: str) -> PrincipalRecord | None:
        query = f"{_PRINCIPAL_BY_CREDENTIAL} WHERE c.origin = ?"
        return _principal(self.db.execute(query, (origin,)).fetchone())

    def for_token(self, token: str) -> PrincipalRecord | None:
        query = f"{_PRINCIPAL_BY_CREDENTIAL} WHERE c.token_hash = ?"
        return _principal(self.db.execute(query, (token_hash(token),)).fetchone())

    # Proposals and assent (OfferRepository)

    def issued(self, proposal_id: str) -> StoredProposal | None:
        row = self.db.execute(
            "SELECT buyer_principal_id, document FROM proposals WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()
        if row is None:
            return None
        return StoredProposal(row["buyer_principal_id"], _document(row["document"]))

    def save_proposal(self, proposal: StoredProposal) -> None:
        """Issues the proposal, or replaces the document of the one already issued."""
        self.db.execute(
            "INSERT INTO proposals (proposal_id, buyer_principal_id, document) VALUES (?, ?, ?)"
            " ON CONFLICT (proposal_id) DO UPDATE SET document = excluded.document",
            (proposal.proposal_id, proposal.buyer_principal_id, json.dumps(proposal.document)),
        )

    def assent(self, proposal_id: str) -> list[AssentEntry]:
        rows = self.db.execute(
            "SELECT entry FROM assent WHERE proposal_id = ? ORDER BY id", (proposal_id,)
        )
        return [AssentEntry.model_validate(json.loads(row["entry"])) for row in rows]

    def append_assent(
        self, proposal_id: str, entry: AssentEntry, by: ResolvedCaller | None
    ) -> None:
        """Appends an entry. A buyer's entry keeps how its principal authenticated and, for a
        signature, the signed request that carried it, in the caller's transaction."""
        method: AuthMethod | None = None if by is None else by.credential.method
        evidence_id = None
        if by is not None and isinstance(by.credential, SignatureCredential):
            evidence_id = evidence.save_request(self.db, _signed_request(by.credential))
        self.db.execute(
            "INSERT INTO assent (proposal_id, role, entry, idempotency_key, principal_id,"
            " authentication_method, evidence_id, attributed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                proposal_id,
                entry.role,
                dump_json(entry),
                entry.idempotency_key,
                None if by is None else by.principal.id,
                method,
                evidence_id,
                int(by is not None and by.attributed),
            ),
        )

    def save_agreed(
        self, proposal_id: str, digest: str, digest_input: bytes, entries: Sequence[AssentEntry]
    ) -> None:
        self.db.execute(
            "INSERT INTO agreed_records (proposal_id, record_digest, digest_input, entries)"
            " VALUES (?, ?, ?, ?)",
            (proposal_id, digest, digest_input, json.dumps([dump(e) for e in entries])),
        )

    # Processed commits (CommitLedger, § 5.6.1)

    def processed(self, principal_id: str, key: str) -> ProcessedCommit | None:
        row = self.db.execute(
            "SELECT canonical, proposal_id, error FROM commits"
            " WHERE principal_id = ? AND idempotency_key = ?",
            (principal_id, key),
        ).fetchone()
        if row is None:
            return None
        error = None if row["error"] is None else ErrorObject.model_validate_json(row["error"])
        return ProcessedCommit(bytes(row["canonical"]), row["proposal_id"], error)

    def record(
        self,
        principal_id: str,
        key: str,
        proposal_id: str,
        canonical: bytes,
        error: ErrorObject | None,
    ) -> None:
        self.db.execute(
            "INSERT INTO commits (principal_id, idempotency_key, proposal_id, canonical, error)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                principal_id,
                key,
                proposal_id,
                canonical,
                None if error is None else dump_json(error),
            ),
        )
