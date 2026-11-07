"""What an observer outside a party reads of its records: the live runner and the e2e.

Each party's database is its own, written only by its store
(seller/sqlite_store.py, buyer/repository.py). An observer opens it read-only
(`EvidenceReader.open`) and reads it through one of these read models, never
with its own SQL: `SellerRecords` for the seller's assent log, ledger, and
agreed records, and `BuyerRecords` for the buyer's commits. Both also read the
evidence tables every party keeps (`EvidenceReader`).

The values are what the observer checks and reports, typed, and nothing the
party itself decides on.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Literal

from .evidence import EvidenceReader


@dataclass(frozen=True)
class KeptEntry:
    """An entry in the seller's assent log, with how its principal authenticated."""

    role: str
    idempotency_key: str | None
    principal_id: str | None
    authentication_method: str | None
    #: The kept request that carried the entry; None for a bearer entry or the seller's own.
    evidence_id: int | None
    attributed: bool


@dataclass(frozen=True)
class KeptCredential:
    """A credential the seller holds for a principal: an origin, or a token's hash."""

    type: str
    origin: str | None
    token_hash: str | None


@dataclass(frozen=True)
class KeptAgreement:
    """An agreed record (§ 4.1.2): its digest input, and the digest over it."""

    record_digest: str
    digest_input: bytes


@dataclass(frozen=True)
class KeptCommit:
    """A Commit the buyer composed, and where it stands."""

    id: int
    state: Literal["pending", "agreed", "rejected"]
    idempotency_key: str
    body: bytes
    digest_input: bytes


class SellerRecords(EvidenceReader):
    """The seller's records, read-only."""

    def entries(self, proposal_id: str) -> list[KeptEntry]:
        """The assent log of `proposal_id`, in order."""
        rows = self.db.execute(
            "SELECT role, idempotency_key, principal_id, authentication_method, evidence_id,"
            " attributed FROM assent WHERE proposal_id = ? ORDER BY id",
            (proposal_id,),
        ).fetchall()
        return [
            KeptEntry(
                r["role"],
                r["idempotency_key"],
                r["principal_id"],
                r["authentication_method"],
                r["evidence_id"],
                bool(r["attributed"]),
            )
            for r in rows
        ]

    def credentials(self, principal_id: str) -> list[KeptCredential]:
        rows = self.db.execute(
            "SELECT type, origin, token_hash FROM credentials WHERE principal_id = ? ORDER BY id",
            (principal_id,),
        ).fetchall()
        return [KeptCredential(r["type"], r["origin"], r["token_hash"]) for r in rows]

    def processed(self, proposal_id: str) -> list[str]:
        """The idempotency keys of the commits the seller processed on `proposal_id`, sorted."""
        rows = self.db.execute(
            "SELECT idempotency_key FROM commits WHERE proposal_id = ? ORDER BY idempotency_key",
            (proposal_id,),
        ).fetchall()
        return [r["idempotency_key"] for r in rows]

    def agreed(self, proposal_id: str) -> list[KeptAgreement]:
        rows = self.db.execute(
            "SELECT record_digest, digest_input FROM agreed_records WHERE proposal_id = ?"
            " ORDER BY id",
            (proposal_id,),
        ).fetchall()
        return [KeptAgreement(r["record_digest"], bytes(r["digest_input"])) for r in rows]


class BuyerRecords(EvidenceReader):
    """The buyer's records, read-only."""

    def commit(self, commit_id: int) -> KeptCommit | None:
        row = self.db.execute(_COMMITS + " WHERE id = ?", (commit_id,)).fetchone()
        return None if row is None else _commit(row)

    def commits(self, proposal_id: str, line_item_ids: list[str]) -> list[KeptCommit]:
        """The buyer's commits on these line items of `proposal_id`, oldest first."""
        items = json.dumps(sorted(line_item_ids))
        rows = self.db.execute(
            _COMMITS + " WHERE proposal_id = ? AND line_item_ids = ? ORDER BY id",
            (proposal_id, items),
        ).fetchall()
        return [_commit(r) for r in rows]


_COMMITS = "SELECT id, state, idempotency_key, body, digest_input FROM commits"


def _commit(row: sqlite3.Row) -> KeptCommit:
    return KeptCommit(
        row["id"],
        row["state"],
        row["idempotency_key"],
        bytes(row["body"]),
        bytes(row["digest_input"]),
    )
