"""The seller's store hands back the values it was given, through a real SQLite file."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from openproposal import AssentEntry, ErrorObject

from protocol.operations import acceptance_for
from seller.ports import PrincipalRecord, StoredProposal
from seller.sqlite_store import SqliteSellerStore, token_hash

BUYER = PrincipalRecord("buyer-wba", "Demo Buyer Agency LLC", "buyer.example")
COMMITMENT = AssentEntry.model_validate(
    {
        "role": "commitment",
        "version": 1,
        "record_digest": "sha256:" + "0" * 64,
        "line_item_ids": ["business-daily-display"],
        "at": "2029-01-01T00:00:00Z",
        "idempotency_key": "key-1",
    }
)


@pytest.fixture
def store(tmp_path: Path) -> SqliteSellerStore:
    store = SqliteSellerStore(tmp_path / "seller.db")
    store.add_principal(BUYER)
    store.add_origin_credential(BUYER.id, "https://buyer.example")
    store.add_token_credential(BUYER.id, "the-token")
    store.save_proposal(StoredProposal(BUYER.id, {"proposal_id": "p-1", "version": 1}))
    return store


def test_principals_resolve_by_origin_and_by_token_hash(store: SqliteSellerStore) -> None:
    assert store.is_empty() is False
    assert store.for_origin("https://buyer.example") == BUYER
    assert store.for_token("the-token") == BUYER
    assert store.principal(BUYER.id) == BUYER
    assert store.for_origin("https://other.example") is None
    assert store.for_token("another-token") is None
    assert store.principal("nobody") is None
    stored = store.db.execute("SELECT token_hash FROM credentials WHERE type = 'bearer'")
    assert stored.fetchone()[0] == token_hash("the-token") != "the-token"


def test_an_empty_store_is_empty(tmp_path: Path) -> None:
    assert SqliteSellerStore(tmp_path / "empty.db").is_empty()


def test_a_proposal_is_issued_once_and_its_document_replaced(store: SqliteSellerStore) -> None:
    assert store.issued("p-1") == StoredProposal(BUYER.id, {"proposal_id": "p-1", "version": 1})
    store.save_proposal(StoredProposal(BUYER.id, {"proposal_id": "p-1", "version": 2}))
    issued = store.issued("p-1")
    assert issued is not None and issued.document["version"] == 2
    assert store.issued("p-2") is None


def test_the_assent_log_returns_the_same_entries_in_order(store: SqliteSellerStore) -> None:
    # How a buyer's entry authenticated, and its evidence, are kept by the commit route:
    # tests/test_boundary.py drives them through the app.
    acceptance = acceptance_for(COMMITMENT, datetime(2029, 1, 1, 0, 0, 1, tzinfo=UTC))
    store.append_assent("p-1", COMMITMENT, None)
    store.append_assent("p-1", acceptance, None)
    assert store.assent("p-1") == [COMMITMENT, acceptance]
    store.save_agreed("p-1", COMMITMENT.record_digest, b"input", [COMMITMENT, acceptance])
    agreed = store.db.execute("SELECT digest_input FROM agreed_records").fetchone()
    assert agreed[0] == b"input"


def test_the_ledger_keeps_a_processed_commit_with_and_without_its_error(
    store: SqliteSellerStore,
) -> None:
    error = ErrorObject.model_validate(
        {"code": "not_committable", "detail": "agreed", "retry": "none", "version": 1}
    )
    store.record(BUYER.id, "key-1", "p-1", b"canonical-1", None)
    store.record(BUYER.id, "key-2", "p-1", b"canonical-2", error)
    one, two = store.processed(BUYER.id, "key-1"), store.processed(BUYER.id, "key-2")
    assert one is not None and (one.canonical, one.proposal_id, one.error) == (
        b"canonical-1",
        "p-1",
        None,
    )
    assert two is not None and two.error == error
    assert store.processed(BUYER.id, "key-3") is None


@pytest.mark.parametrize(
    ("column", "value"), [("role", "approval"), ("authentication_method", "password")]
)
def test_the_assent_table_refuses_an_unknown_term(
    store: SqliteSellerStore, column: str, value: str
) -> None:
    values = {"role": "commitment", "authentication_method": "bearer"} | {column: value}
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        store.db.execute(
            "INSERT INTO assent (proposal_id, role, entry, authentication_method)"
            " VALUES ('p-1', ?, '{}', ?)",
            (values["role"], values["authentication_method"]),
        )


def test_the_store_has_one_transaction_and_it_rolls_back(store: SqliteSellerStore) -> None:
    with pytest.raises(sqlite3.IntegrityError), store.transaction():
        store.record(BUYER.id, "key-9", "p-1", b"c", None)
        store.record(BUYER.id, "key-9", "p-1", b"c", None)  # the same key twice
    assert store.processed(BUYER.id, "key-9") is None
    assert store.db.in_transaction is False
