"""What an observer reads of each party's records (persistence/observe.py), after a real flow.

Both agents run in process (tests/stack.py) and agree on a commit. Each party's
kept evidence then verifies again offline, against the directory bytes kept
with it, and a copy of the database with one changed byte doesn't.
"""

from __future__ import annotations

import asyncio
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    ServerIdentity,
    WebBotAuthError,
)

from persistence.evidence import NoEvidenceError
from persistence.observe import BuyerRecords, KeptOriginCredential, SellerRecords
from persistence.values import Origin
from tests.stack import BUYER, SELLER, Stack
from transport.reverify import reverify_request, reverify_response

DISPLAY = "business-daily-display"


@pytest.fixture
def agreed(tmp_path: Path) -> Iterator[tuple[Stack, dict[str, object]]]:
    with Stack(tmp_path / "agents") as stack:
        outcome = stack.commit("demo-wba-1", [DISPLAY]).json()
        assert outcome["state"] == "agreed", outcome
        yield stack, outcome


def _tampered(path: Path, copy: Path, statement: str) -> Path:
    shutil.copy(path, copy)
    db = sqlite3.connect(copy)
    try:
        db.execute(statement)
        db.commit()
    finally:
        db.close()
    return copy


def test_the_seller_records_read_the_commit_as_the_boundary_resolved_it(
    agreed: tuple[Stack, dict[str, object]],
) -> None:
    stack, _ = agreed
    with stack.seller_records() as seller:
        commitment, acceptance = seller.entries("demo-wba-1")
        assert (commitment.role, acceptance.role) == ("commitment", "acceptance")
        assert commitment.principal_id == "buyer-wba"
        assert commitment.authentication_method == "web_bot_auth"
        assert seller.processed("demo-wba-1") == [commitment.idempotency_key]
        assert seller.credentials("buyer-wba") == [KeptOriginCredential(origin=Origin.parse(BUYER))]
        assert seller.directories_of(Origin.parse(BUYER)) == 1
        assert seller.requests_from(Origin.parse(BUYER)) == 1


def test_one_directory_fetch_verified_twice_is_kept_once(tmp_path: Path) -> None:
    with Stack(tmp_path / "agents") as stack:
        for proposal_id in ("demo-wba-1", "demo-wba-2"):
            assert stack.commit(proposal_id, [DISPLAY]).json()["state"] == "agreed"
        served = stack.buyer.get(DIRECTORY_PATH).content
    with stack.seller_records() as seller:
        # Two signatures, one cached fetch: one row, with the exact body bytes verified.
        assert seller.requests_from(Origin.parse(BUYER)) == 2
        assert seller.directories() == 1
        entry, _ = seller.entries("demo-wba-1")
        assert entry.evidence_id is not None
        kept = seller.request(entry.evidence_id).signer.directory
        assert kept is not None
    assert kept.url == f"{BUYER}{DIRECTORY_PATH}"
    assert kept.body == served  # the same key set, byte for byte


def test_both_parties_kept_evidence_verifies_again_offline(
    agreed: tuple[Stack, dict[str, object]],
) -> None:
    stack, outcome = agreed
    with stack.seller_records() as seller:
        (commitment, _) = seller.entries("demo-wba-1")
        assert commitment.evidence_id is not None
        kept = seller.request(commitment.evidence_id)
        identity = ServerIdentity.from_config(SELLER)
        again = asyncio.run(reverify_request(kept, identity))
    assert str(again.origin) == BUYER and again.body_covered
    assert again.keyid == stack.buyer_keys.active().thumbprint

    with stack.buyer_records() as buyer:
        evidence_id = outcome["evidence_id"]
        assert isinstance(evidence_id, int)
        answered = asyncio.run(reverify_response(buyer.response(evidence_id)))
        commit_id = outcome["commit_id"]
        assert isinstance(commit_id, int)
        commit = buyer.commit(commit_id)
        # The scenarios find a commit by its proposal and line items, in any order.
        assert buyer.commits("demo-wba-1", [DISPLAY]) == [commit]
        assert buyer.commits("demo-wba-1", ["weather-app-ctv"]) == []
    assert answered.bound and answered.body_covered
    assert commit is not None and commit.state == "agreed"
    assert kept.request.body == commit.body  # the exact bytes the buyer signed and sent


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE signed_requests SET body = CAST(replace(CAST(body AS TEXT), '1', '2') AS BLOB)",
        "UPDATE signed_requests SET url = url || '?x=1'",
    ],
    ids=["body", "url"],
)
def test_a_tampered_kept_request_fails_to_verify_again(
    agreed: tuple[Stack, dict[str, object]], tmp_path: Path, statement: str
) -> None:
    stack, _ = agreed
    copy = _tampered(stack.seller_dir / "seller.db", tmp_path / "copy.db", statement)
    with SellerRecords.open(copy) as seller:
        (commitment, _) = seller.entries("demo-wba-1")
        assert commitment.evidence_id is not None
        kept = seller.request(commitment.evidence_id)
        with pytest.raises(WebBotAuthError):
            asyncio.run(reverify_request(kept, ServerIdentity.from_config(SELLER)))


def test_a_tampered_kept_answer_fails_to_verify_again(
    agreed: tuple[Stack, dict[str, object]], tmp_path: Path
) -> None:
    stack, outcome = agreed
    statement = "UPDATE signed_responses SET status = 201"
    copy = _tampered(stack.buyer_dir / "buyer.db", tmp_path / "copy.db", statement)
    with BuyerRecords.open(copy) as buyer:
        evidence_id = outcome["evidence_id"]
        assert isinstance(evidence_id, int)
        with pytest.raises(WebBotAuthError):
            asyncio.run(reverify_response(buyer.response(evidence_id)))


def test_an_unknown_id_is_no_evidence(agreed: tuple[Stack, dict[str, object]]) -> None:
    stack, _ = agreed
    with stack.buyer_records() as buyer:
        with pytest.raises(NoEvidenceError):
            buyer.response(999)
        assert buyer.commit(999) is None
    with (
        stack.seller_records() as seller,
        pytest.raises(NoEvidenceError),
    ):
        seller.request(999)
