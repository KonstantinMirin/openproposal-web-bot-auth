"""What an observer outside a party reads of its records: the live runner and the e2e.

Each party's database is its own, written only by its store
(seller/sqlite_store.py, buyer/repository.py). An observer opens it read-only
(`SellerRecords.open`, `BuyerRecords.open`) and reads it through one of these
read models, never with its own SQL. Each holds the party's `EvidenceStore`
and exposes only the half of it that party keeps:

- `SellerRecords`: the assent log, the ledger, the agreed records, and the
  signed requests the seller verified, with the directories that confirmed
  them.
- `BuyerRecords`: the commits, and the signed answers the buyer verified, each
  with the request it is bound to.

The values are what the observer checks and reports, typed, and nothing the
party itself decides on. Re-verifying them is transport/reverify.py's work.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from .evidence import EvidenceStore
from .sqlite import open_read_only
from .values import Origin, SignedRequest, SignedResponse


class _ReadModel:
    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db
        self._evidence = EvidenceStore(db)

    @classmethod
    @contextmanager
    def open(cls, path: Path | str) -> Iterator[Self]:
        """The party's database at `path`, opened read-only."""
        with open_read_only(path) as db:
            yield cls(db)

    def directories(self) -> int:
        """How many directory fetches the party kept."""
        return self._evidence.directories()


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


class SellerRecords(_ReadModel):
    """The seller's records, read-only."""

    def request(self, request_id: int) -> SignedRequest:
        """A signed request the seller verified, with who signed it."""
        return self._evidence.request(request_id)

    def requests_from(self, origin: Origin) -> int:
        """How many kept requests `origin` signed."""
        return self._evidence.requests_from(origin)

    def requests_with_body(self, body: bytes) -> int:
        """How many kept requests carried exactly `body`."""
        return self._evidence.requests_with_body(body)

    def directories_of(self, origin: Origin) -> int:
        """How many kept directory fetches came from `origin`."""
        return self._evidence.directories_of(origin)

    def entries(self, proposal_id: str) -> list[KeptEntry]:
        """The assent log of `proposal_id`, in order."""
        rows = self._db.execute(
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
        rows = self._db.execute(
            "SELECT type, origin, token_hash FROM credentials WHERE principal_id = ? ORDER BY id",
            (principal_id,),
        ).fetchall()
        return [KeptCredential(r["type"], r["origin"], r["token_hash"]) for r in rows]

    def processed(self, proposal_id: str) -> list[str]:
        """The idempotency keys of the commits the seller processed on `proposal_id`, sorted."""
        rows = self._db.execute(
            "SELECT idempotency_key FROM commits WHERE proposal_id = ? ORDER BY idempotency_key",
            (proposal_id,),
        ).fetchall()
        return [r["idempotency_key"] for r in rows]

    def agreed(self, proposal_id: str) -> list[KeptAgreement]:
        rows = self._db.execute(
            "SELECT record_digest, digest_input FROM agreed_records WHERE proposal_id = ?"
            " ORDER BY id",
            (proposal_id,),
        ).fetchall()
        return [KeptAgreement(r["record_digest"], bytes(r["digest_input"])) for r in rows]


class BuyerRecords(_ReadModel):
    """The buyer's records, read-only."""

    def response(self, response_id: int) -> SignedResponse:
        """A signed answer the buyer verified, with the request it is bound to."""
        return self._evidence.response(response_id)

    def commit(self, commit_id: int) -> KeptCommit | None:
        row = self._db.execute(_COMMITS + " WHERE id = ?", (commit_id,)).fetchone()
        return None if row is None else _commit(row)

    def commits(self, proposal_id: str, line_item_ids: list[str]) -> list[KeptCommit]:
        """The buyer's commits on these line items of `proposal_id`, oldest first."""
        items = json.dumps(sorted(line_item_ids))
        rows = self._db.execute(
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
