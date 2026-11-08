"""What an observer outside a party reads of its records: the live runner and the e2e.

Each party's database is its own, written only by its store
(seller/sqlite_store.py, buyer/repository.py). An observer opens it read-only
(`SellerRecords.open`, `BuyerRecords.open`) and reads it through one of these
read models, never with its own SQL. A read model reads the party's tables
through the same schema module as the party's store (persistence/seller_schema.py,
persistence/buyer_schema.py), and holds the party's `EvidenceStore`, exposing
only the half of it that party keeps:

- `SellerRecords`: its principals and the credentials that point at them,
  the assent log, the ledger, the agreed records, and the signed requests the
  seller verified, with the directories that confirmed them. An observer finds
  a principal by its credential (`principal_with_origin`), never by a literal
  id.
- `BuyerRecords`: the commits, and the signed answers the buyer verified, each
  with the request it is bound to.

The values are what the observer checks and reports, typed, and nothing the
party itself decides on. Re-verifying them is transport/reverify.py's work.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Self

from . import buyer_schema, seller_schema
from .buyer_schema import KeptCommit
from .evidence import EvidenceStore
from .seller_schema import (
    KeptAgreement,
    KeptCredential,
    KeptEntry,
    KeptOriginCredential,
    KeptPrincipal,
    KeptTokenCredential,
)
from .sqlite import open_read_only
from .values import Origin, SignedRequest, SignedResponse

__all__ = [
    "BuyerRecords",
    "KeptAgreement",
    "KeptCommit",
    "KeptCredential",
    "KeptEntry",
    "KeptOriginCredential",
    "KeptPrincipal",
    "KeptTokenCredential",
    "SellerRecords",
]


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

    def messages(self) -> int:
        """How many signed messages the party kept, requests and responses together."""
        return self._evidence.messages()


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
        return seller_schema.entries(self._db, proposal_id)

    def principal_with_origin(self, origin: Origin) -> KeptPrincipal | None:
        """The principal the signature credential `origin` points at, if any."""
        return seller_schema.principal_with_origin(self._db, origin)

    def credentials(self, principal_id: str) -> list[KeptCredential]:
        """The credentials that name `principal_id`, in the order they were added."""
        return seller_schema.credentials(self._db, principal_id)

    def processed(self, proposal_id: str) -> list[str]:
        """The idempotency keys of the commits the seller processed on `proposal_id`, sorted."""
        return [c.idempotency_key for c in seller_schema.processed_on(self._db, proposal_id)]

    def agreed(self, proposal_id: str) -> list[KeptAgreement]:
        """The agreed records of `proposal_id`, in order."""
        return seller_schema.agreed(self._db, proposal_id)


class BuyerRecords(_ReadModel):
    """The buyer's records, read-only."""

    def response(self, response_id: int) -> SignedResponse:
        """A signed answer the buyer verified, with the request it is bound to."""
        return self._evidence.response(response_id)

    def commit(self, commit_id: int) -> KeptCommit | None:
        return buyer_schema.commit(self._db, commit_id)

    def commits(self, proposal_id: str, line_item_ids: list[str]) -> list[KeptCommit]:
        """The buyer's commits on these line items of `proposal_id`, oldest first."""
        return buyer_schema.commits_on(self._db, proposal_id, line_item_ids)
