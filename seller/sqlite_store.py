"""The seller's own records, in SQLite: who its buyers are, what it offered, and what was agreed.

`SqliteSellerStore` implements every port in seller/ports.py. It is the only
seller code that serializes for storage. It writes the tables that
persistence/seller_schema.py defines and reads them through that module, the
seller's read model's too; a principal row is read straight into the port's
`Principal`, by its fields' names, its `kind` included.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from openproposal import AssentEntry, ErrorObject, dump_json

from persistence import evidence, seller_schema
from persistence.sqlite import fetch_one, is_closed, json_array, open_db, select, transaction
from persistence.values import Origin, Provenance
from protocol.record import sha256_hex

from .ports import Principal, ProcessedCommit, StoredProposal

#: A principal, by id, and by the credential that names it.
_BY_ID = select("principals", Principal, where="id = ?")
_BY_ORIGIN = select(
    "principals",
    Principal,
    where="id = (SELECT principal_id FROM credentials WHERE origin = ?)",
)
_BY_TOKEN = select(
    "principals",
    Principal,
    where="id = (SELECT principal_id FROM credentials WHERE token_hash = ?)",
)


def token_hash(token: str) -> str:
    """What the seller stores for a bearer token: its SHA-256, never the token."""
    return sha256_hex(token.encode())


class SqliteSellerStore:
    def __init__(self, path: Path) -> None:
        self._db = open_db(path, evidence.SCHEMA, seller_schema.SCHEMA)
        self._evidence = evidence.EvidenceStore(self._db)

    def close(self) -> None:
        """Closes the connection. The app's lifespan calls it on shutdown."""
        self._db.close()

    @property
    def is_closed(self) -> bool:
        return is_closed(self._db)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """`with store.transaction():` runs the block as one SQLite transaction."""
        with transaction(self._db):
            yield

    # Principals and credentials (PrincipalDirectory, Onboarding)

    def is_empty(self) -> bool:
        return fetch_one(self._db, "SELECT 1 FROM principals LIMIT 1") is None

    def add_principal(self, principal: Principal) -> None:
        self._db.execute(
            "INSERT INTO principals (id, kind, legal_name, domain) VALUES (?, ?, ?, ?)",
            (principal.id, principal.kind, principal.legal_name, principal.domain),
        )

    def add_origin_credential(self, principal_id: str, origin: Origin) -> None:
        self._db.execute(
            "INSERT INTO credentials (principal_id, type, origin) VALUES (?, 'web_bot_auth', ?)",
            (principal_id, str(origin)),
        )

    def add_token_credential(self, principal_id: str, token: str) -> None:
        self._db.execute(
            "INSERT INTO credentials (principal_id, type, token_hash) VALUES (?, 'bearer', ?)",
            (principal_id, token_hash(token)),
        )

    def principal(self, principal_id: str) -> Principal | None:
        return self._principal(_BY_ID, principal_id)

    def for_origin(self, origin: Origin) -> Principal | None:
        return self._principal(_BY_ORIGIN, str(origin))

    def for_token(self, token: str) -> Principal | None:
        return self._principal(_BY_TOKEN, token_hash(token))

    def _principal(self, query: str, key: str) -> Principal | None:
        row = fetch_one(self._db, query, (key,))
        return None if row is None else Principal.model_validate(row)

    # Proposals and assent (OfferRepository)

    def issued(self, proposal_id: str) -> StoredProposal | None:
        row = seller_schema.issued(self._db, proposal_id)
        if row is None:
            return None
        return StoredProposal(buyer_principal_id=row.buyer_principal_id, document=row.document)

    def save_proposal(self, proposal: StoredProposal) -> None:
        """Issues the proposal, or replaces the document of the one already issued."""
        self._db.execute(
            "INSERT INTO proposals (proposal_id, buyer_principal_id, document) VALUES (?, ?, ?)"
            " ON CONFLICT (proposal_id) DO UPDATE SET document = excluded.document",
            (proposal.proposal_id, proposal.buyer_principal_id, json.dumps(proposal.document)),
        )

    def assent(self, proposal_id: str) -> list[AssentEntry]:
        return [kept.entry for kept in seller_schema.entries(self._db, proposal_id)]

    def append_assent(
        self, proposal_id: str, entry: AssentEntry, provenance: Provenance | None
    ) -> None:
        """Appends an entry. A buyer's entry keeps its provenance and, for a signature, the
        signed request that carried it, in the caller's transaction."""
        p = provenance
        evidence_id = None
        if p is not None and p.signed is not None:
            evidence_id = self._evidence.keep_request(p.signed)
        self._db.execute(
            "INSERT INTO assent (proposal_id, role, entry, idempotency_key, principal_id,"
            " authentication_method, evidence_id, attributed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                proposal_id,
                entry.role,
                dump_json(entry),
                entry.idempotency_key,
                None if p is None else p.principal_id,
                None if p is None else p.method,
                evidence_id,
                int(p is not None and p.attributed),
            ),
        )

    def save_agreed(
        self, proposal_id: str, digest: str, digest_input: bytes, entries: Sequence[AssentEntry]
    ) -> None:
        self._db.execute(
            "INSERT INTO agreed_records (proposal_id, record_digest, digest_input, entries)"
            " VALUES (?, ?, ?, ?)",
            (proposal_id, digest, digest_input, json_array(dump_json(e) for e in entries)),
        )

    # Processed commits (CommitLedger, § 5.6.1)

    def processed(self, principal_id: str, key: str) -> ProcessedCommit | None:
        row = seller_schema.processed(self._db, principal_id, key)
        if row is None:
            return None
        return ProcessedCommit(
            canonical=row.canonical, proposal_id=row.proposal_id, error=row.error
        )

    def record(
        self,
        principal_id: str,
        key: str,
        proposal_id: str,
        canonical: bytes,
        error: ErrorObject | None,
    ) -> None:
        self._db.execute(
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
