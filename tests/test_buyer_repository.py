"""The buyer's repository: an agreement keeps its evidence and settlement together, or neither."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from iab_agentic_primitives.web_bot_auth import HTTPRequest, HTTPResponse, Origin
from openproposal import AssentEntry, Commit, ErrorObject
from pydantic import SecretStr

from buyer.repository import BuyerRepository, CommitKey, Counterparty, NotPendingError
from persistence.evidence import StoredRequest, StoredResponse, load_response

SELLER = Counterparty(
    Origin.parse("https://seller.example"), "seller.example", "Demo Seller Inc.", SecretStr("t")
)
KEY = CommitKey("https://seller.example", "p-1", ("b-item", "a-item"))
ENTRY = {
    "role": "commitment",
    "version": 1,
    "record_digest": "sha256:" + "0" * 64,
    "line_item_ids": ["a-item", "b-item"],
    "at": "2029-01-01T00:00:00Z",
    "idempotency_key": "key-1",
}
WRITES = {
    "commitment": {
        "basis": "spend",
        "amount": 1000,
        "advertisers": [{"domain": "brand-a.example"}],
        "flight": {"start": "2029-11-02T00:00:00Z", "end": "2029-12-21T23:59:59Z"},
    }
}
COMMIT = Commit.model_validate({"entry": ENTRY, "writes": {"a-item": WRITES, "b-item": WRITES}})
REQUEST = HTTPRequest(
    "POST",
    "https://seller.example/proposals/p-1/commit",
    [("Content-Type", "application/json"), ("Signature", "sig1=:AA==:")],
    b"{}",
)
RESPONSE = HTTPResponse(200, [("Content-Type", "application/json")], b'{"entries": []}', REQUEST)
KEPT = StoredResponse(
    RESPONSE,
    StoredRequest(REQUEST, "https://buyer.example", "buyer-kid"),
    str(SELLER.origin),
    "kid",
)


@pytest.fixture
def repository(tmp_path: Path) -> BuyerRepository:
    repository = BuyerRepository(tmp_path / "buyer.db")
    repository.add_counterparty(SELLER)
    return repository


def _count(repository: BuyerRepository, table: str) -> int:
    query = f"SELECT COUNT(*) FROM {table}"  # noqa: S608 -- a literal table name
    return int(repository.db.execute(query).fetchone()[0])


def _state(repository: BuyerRepository, commit_id: int) -> str:
    row = repository.db.execute("SELECT state FROM commits WHERE id = ?", (commit_id,)).fetchone()
    return str(row[0])


def test_a_counterparty_round_trips_and_a_restart_keeps_the_first(
    repository: BuyerRepository,
) -> None:
    assert repository.counterparty("https://seller.example") == SELLER
    repository.add_counterparty(Counterparty(SELLER.origin, "other", "Other", None))
    assert repository.counterparty("https://seller.example") == SELLER
    assert repository.counterparty("https://other.example") is None


def test_a_pending_commit_is_found_by_its_key_whatever_the_item_order(
    repository: BuyerRepository,
) -> None:
    assert repository.pending(KEY) is None
    pending = repository.add_pending(KEY, COMMIT, b"digest input")
    found = repository.pending(CommitKey(KEY.seller_origin, KEY.proposal_id, ("a-item", "b-item")))
    assert found is not None
    assert (found.id, found.body, found.digest_input) == (pending.id, pending.body, b"digest input")
    assert Commit.model_validate_json(found.body) == COMMIT


def test_keep_agreement_writes_the_evidence_and_the_settlement_together(
    repository: BuyerRepository,
) -> None:
    pending = repository.add_pending(KEY, COMMIT, b"digest input")
    entry = AssentEntry.model_validate(ENTRY)
    response_id = repository.keep_agreement(pending.id, KEPT, [entry], attributed=True)
    assert _state(repository, pending.id) == "agreed"
    assert load_response(repository.db, response_id) == RESPONSE
    row = repository.db.execute(
        "SELECT response_id, attributed FROM commits WHERE id = ?", (pending.id,)
    ).fetchone()
    assert tuple(row) == (response_id, 1)
    assert repository.pending(KEY) is None


def test_a_repeated_agreement_writes_no_second_evidence_row(repository: BuyerRepository) -> None:
    pending = repository.add_pending(KEY, COMMIT, b"digest input")
    first = repository.keep_agreement(pending.id, KEPT, [], attributed=True)
    again = repository.keep_agreement(pending.id, KEPT, [], attributed=True)
    assert first == again
    assert (_count(repository, "signed_responses"), _count(repository, "signed_requests")) == (1, 1)


def test_a_failed_settlement_keeps_no_evidence(repository: BuyerRepository) -> None:
    """Defect 3: the evidence and the settlement were separate autocommits, so a failure
    between them left evidence for a commit that was still pending."""
    pending = repository.add_pending(KEY, COMMIT, b"digest input")
    repository.settle_rejected(pending.id, [])  # now the settlement inside keep_agreement fails
    with pytest.raises(NotPendingError):
        repository.keep_agreement(pending.id, KEPT, [], attributed=False)
    assert (_count(repository, "signed_responses"), _count(repository, "signed_requests")) == (0, 0)
    assert _state(repository, pending.id) == "rejected"
    assert repository.db.in_transaction is False


def test_a_rejection_keeps_the_sellers_errors(repository: BuyerRepository) -> None:
    pending = repository.add_pending(KEY, COMMIT, b"digest input")
    error = ErrorObject.model_validate({"code": "expired", "detail": "late", "retry": "none"})
    repository.settle_rejected(pending.id, [error])
    assert _state(repository, pending.id) == "rejected"
    stored = repository.db.execute("SELECT errors FROM commits").fetchone()[0]
    assert [ErrorObject.model_validate(e) for e in json.loads(stored)] == [error]
    with pytest.raises(NotPendingError):
        repository.settle_rejected(pending.id, [error])


def test_the_commit_state_refuses_an_unknown_term(repository: BuyerRepository) -> None:
    pending = repository.add_pending(KEY, COMMIT, b"digest input")
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        repository.db.execute("UPDATE commits SET state = 'agred' WHERE id = ?", (pending.id,))
