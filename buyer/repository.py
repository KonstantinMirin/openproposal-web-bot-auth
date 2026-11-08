"""The buyer's own records, in SQLite: its sellers, its commits, and the evidence of each agreement.

`BuyerRepository` takes and returns domain values, never rows, and it is the
only buyer code that serializes for storage. It writes the tables that
persistence/buyer_schema.py defines and reads commits through that module, the
buyer's read model's too; a seller row is read straight into a `Counterparty`,
by its fields' names. `keep_agreement` writes the seller's signed answer and
settles the commit in one transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from openproposal import AssentEntry, Commit, ErrorObject, dump_json
from pydantic import SecretStr

from persistence import buyer_schema, evidence
from persistence.buyer_schema import CommitState, KeptCommit, items_column
from persistence.sqlite import (
    fetch_one,
    inserted,
    is_closed,
    json_array,
    open_db,
    select,
    transaction,
)
from persistence.values import Origin, SignedResponse
from protocol.values import Value, commitment_key


class Counterparty(Value):
    """A seller this buyer deals with: known by its origin, never by a key.

    The repository reads a seller row straight into it, by its fields' names.
    """

    origin: Origin
    domain: str
    legal_name: str
    #: The token the seller issued this buyer, for the bearer flow.
    bearer_token: SecretStr | None = None


_COUNTERPARTY = select("sellers", Counterparty, where="origin = ?")


@dataclass(frozen=True, kw_only=True)
class CommitKey:
    """Which commit: to this seller, on this proposal, for these line items."""

    seller_origin: Origin
    proposal_id: str
    line_item_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class PendingCommit:
    """A composed Commit that waits for a verified answer, and its digest input."""

    id: int
    key: CommitKey
    body: bytes
    digest_input: bytes


class NotPendingError(LookupError):
    """The commit is not pending, so it can't be settled as rejected."""


class BuyerRepository:
    def __init__(self, path: Path) -> None:
        self._db = open_db(path, evidence.SCHEMA, buyer_schema.SCHEMA)
        self._evidence = evidence.EvidenceStore(self._db)

    def close(self) -> None:
        """Closes the connection. The app's lifespan calls it on shutdown."""
        self._db.close()

    @property
    def is_closed(self) -> bool:
        return is_closed(self._db)

    # Sellers

    def add_counterparty(self, seller: Counterparty) -> None:
        """Records a seller once; a restart keeps the first record."""
        token = seller.bearer_token.get_secret_value() if seller.bearer_token else None
        self._db.execute(
            "INSERT OR IGNORE INTO sellers (origin, domain, legal_name, bearer_token)"
            " VALUES (?, ?, ?, ?)",
            (str(seller.origin), seller.domain, seller.legal_name, token),
        )

    def counterparty(self, origin: Origin) -> Counterparty | None:
        row = fetch_one(self._db, _COUNTERPARTY, (str(origin),))
        return None if row is None else Counterparty.model_validate(row)

    # Commits

    def pending(self, key: CommitKey) -> PendingCommit | None:
        kept = buyer_schema.pending(self._db, key.seller_origin, key.proposal_id, key.line_item_ids)
        return None if kept is None else _pending(kept, key)

    def add_pending(self, key: CommitKey, commit: Commit, digest_input: bytes) -> PendingCommit:
        """Keeps a composed Commit, to be sent and, until it is answered, re-sent whole."""
        body = dump_json(commit).encode()
        cursor = self._db.execute(
            "INSERT INTO commits (seller_origin, proposal_id, line_item_ids, idempotency_key, body,"
            " digest_input, state) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            (
                str(key.seller_origin),
                key.proposal_id,
                items_column(key.line_item_ids),
                commitment_key(commit.entry),
                body,
                digest_input,
            ),
        )
        return PendingCommit(id=inserted(cursor), key=key, body=body, digest_input=digest_input)

    def keep_agreement(
        self,
        commit_id: int,
        response: SignedResponse,
        entries: Sequence[AssentEntry],
        *,
        attributed: bool,
    ) -> int:
        """Keeps the seller's signed answer and settles the commit as agreed, in one transaction.

        Returns the kept answer's id. A commit already agreed keeps its first
        answer: a repeat writes nothing and returns that answer's id.
        """
        with transaction(self._db):
            kept = buyer_schema.commit(self._db, commit_id)
            if kept is not None and kept.state == "agreed" and kept.response_id is not None:
                return kept.response_id
            response_id = self._evidence.keep_response(response)
            self._settle(commit_id, "agreed", entries=json_array(dump_json(e) for e in entries))
            self._db.execute(
                "UPDATE commits SET response_id = ?, attributed = ? WHERE id = ?",
                (response_id, int(attributed), commit_id),
            )
        return response_id

    def settle_rejected(self, commit_id: int, errors: Sequence[ErrorObject]) -> None:
        """Settles a pending commit as rejected, with the seller's stored errors (§ 5.6.1)."""
        self._settle(commit_id, "rejected", errors=json_array(dump_json(e) for e in errors))

    def _settle(
        self,
        commit_id: int,
        state: CommitState,
        *,
        entries: str | None = None,
        errors: str | None = None,
    ) -> None:
        cursor = self._db.execute(
            "UPDATE commits SET state = ?, entries = ?, errors = ?"
            " WHERE id = ? AND state = 'pending'",
            (state, entries, errors, commit_id),
        )
        if cursor.rowcount != 1:
            raise NotPendingError(commit_id)


def _pending(kept: KeptCommit, key: CommitKey) -> PendingCommit:
    return PendingCommit(id=kept.id, key=key, body=kept.body, digest_input=kept.digest_input)
