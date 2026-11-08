"""What an observer reads of each party's records (persistence/observe.py), after a real flow.

Both agents run in process (tests/stack.py) and agree on a commit. Each party's
kept evidence then verifies again offline, against the directory bytes kept
with it, and a copy of the database with one changed byte doesn't.
"""

from __future__ import annotations

import asyncio
import shutil
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    ServerIdentity,
    WebBotAuthError,
)

from persistence.evidence import NoEvidenceError
from persistence.observe import (
    BuyerRecords,
    KeptOriginCredential,
    KeptTokenCredential,
    SellerRecords,
)
from persistence.values import Origin
from protocol.record import sha256_hex
from tests.stack import BUYER, SELLER, TOKEN, Stack, as_state
from transport.control import Agreed
from transport.reverify import reverify_request, reverify_response

DISPLAY = "business-daily-display"


@pytest.fixture
def agreed(tmp_path: Path) -> Iterator[tuple[Stack, Agreed]]:
    with Stack(tmp_path / "agents") as stack:
        yield stack, as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY]))


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
    agreed: tuple[Stack, Agreed],
) -> None:
    stack, _ = agreed
    with stack.seller_records() as seller:
        commitment, acceptance = seller.entries("demo-wba-1")
        assert (commitment.role, acceptance.role) == ("commitment", "acceptance")
        principal = seller.principal_with_origin(Origin.parse(BUYER))
        assert principal is not None and principal.domain == Origin.parse(BUYER).host
        assert commitment.principal_id == principal.id
        assert commitment.authentication_method == "web_bot_auth"
        assert seller.processed("demo-wba-1") == [commitment.idempotency_key]
        assert seller.credentials(principal.id) == [
            KeptOriginCredential(origin=Origin.parse(BUYER)),
            KeptTokenCredential(token_hash=sha256_hex(TOKEN.encode())),
        ]
        assert seller.directories_of(Origin.parse(BUYER)) == 1
        assert seller.requests_from(Origin.parse(BUYER)) == 1


def test_one_directory_fetch_verified_twice_is_kept_once(tmp_path: Path) -> None:
    with Stack(tmp_path / "agents") as stack:
        for proposal_id in ("demo-wba-1", "demo-wba-2"):
            as_state(Agreed, stack.commit(proposal_id, [DISPLAY]))
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
    agreed: tuple[Stack, Agreed],
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
        answered = asyncio.run(reverify_response(buyer.response(outcome.evidence_id)))
        commit = buyer.commit(outcome.commit_id)
        # The scenarios find a commit by its proposal and line items, in any order.
        assert buyer.commits("demo-wba-1", [DISPLAY]) == [commit]
        assert buyer.commits("demo-wba-1", ["weather-app-ctv"]) == []
    assert answered.bound and answered.body_covered
    assert commit is not None and commit.state == "agreed"
    assert kept.request.body == commit.body  # the exact bytes the buyer signed and sent


def test_kept_evidence_verifies_again_long_after_its_signatures_expired(
    agreed: tuple[Stack, Agreed], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifying a kept message again is a function of its row: it verifies at the instant
    the party verified it, so a day later it gives the same answer as at once."""
    stack, outcome = agreed
    with stack.seller_records() as seller, stack.buyer_records() as buyer:
        (commitment, _) = seller.entries("demo-wba-1")
        assert commitment.evidence_id is not None
        kept, answer = seller.request(commitment.evidence_id), buyer.response(outcome.evidence_id)
    identity = ServerIdentity.from_config(SELLER)
    at_once = asyncio.run(reverify_request(kept, identity)), asyncio.run(reverify_response(answer))
    later = time.time() + 86_400
    monkeypatch.setattr(time, "time", lambda: later)
    again = asyncio.run(reverify_request(kept, identity)), asyncio.run(reverify_response(answer))
    assert [(v.origin, v.keyid, v.expires) for v in again] == [
        (v.origin, v.keyid, v.expires) for v in at_once
    ]
    assert all(v.expires < later for v in again)


@pytest.mark.parametrize("proposal_id", ["offre-été", "a b"])
def test_a_proposal_id_the_url_encodes_keeps_evidence_that_verifies(
    tmp_path: Path, proposal_id: str
) -> None:
    """The buyer keeps its request as the wire carried it, the URL as encoded and signed."""
    with Stack(tmp_path / "agents") as stack:
        stack.issue(proposal_id)
        outcome = as_state(Agreed, stack.commit(proposal_id, [DISPLAY]))
        with stack.buyer_records() as buyer:
            answer = buyer.response(outcome.evidence_id)
        sent = stack.requests[-1]
    assert (
        answer.response.request.url == str(sent.url) != f"{SELLER}/proposals/{proposal_id}/commit"
    )
    assert asyncio.run(reverify_response(answer)).bound


@pytest.mark.parametrize("proposal_id", ["a?b", "a#b"])
def test_a_proposal_id_with_a_query_or_fragment_character_stays_one_segment(
    tmp_path: Path, proposal_id: str
) -> None:
    """The buyer encodes the id as one path segment, so the seller sees the whole id."""
    with Stack(tmp_path / "agents") as stack:
        stack.issue(proposal_id)
        as_state(Agreed, stack.commit(proposal_id, [DISPLAY]))
        sent = stack.requests[-1]
    assert sent.url.raw_path.decode().startswith("/proposals/a%")
    assert sent.url.query == b""


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE signed_requests SET body = CAST(replace(CAST(body AS TEXT), '1', '2') AS BLOB)",
        "UPDATE signed_requests SET url = url || '?x=1'",
    ],
    ids=["body", "url"],
)
def test_a_tampered_kept_request_fails_to_verify_again(
    agreed: tuple[Stack, Agreed], tmp_path: Path, statement: str
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
    agreed: tuple[Stack, Agreed], tmp_path: Path
) -> None:
    stack, outcome = agreed
    statement = "UPDATE signed_responses SET status = 201"
    copy = _tampered(stack.buyer_dir / "buyer.db", tmp_path / "copy.db", statement)
    with BuyerRecords.open(copy) as buyer, pytest.raises(WebBotAuthError):
        asyncio.run(reverify_response(buyer.response(outcome.evidence_id)))


def test_an_unknown_id_is_no_evidence(agreed: tuple[Stack, Agreed]) -> None:
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
