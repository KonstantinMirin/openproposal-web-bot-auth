"""The buyer, through its operator routes, against the seller app in process (tests/stack.py).

The buyer mirrors the seller's identity boundary: whatever the seller sends is
verified, then parsed, inside one refusal boundary. Each test drives
`/operator/read` or `/operator/commit` and reads the outcome and what each
party kept.

- A signed or bearer commit is agreed, and both parties keep the agreement,
  with the header lines exactly as the transport carried them.
- A verified answer that is malformed, an error without `retry`, or a boundary
  refusal is refused, never a 500, and settles nothing.
- An unknown line item or seller is refused before anything is sent.
- A proposal that names another seller is refused; a `CommitResult` that
  doesn't answer the commit is refused, and so is one whose `record_digest`
  doesn't recompute from the digest input the buyer kept.
- An answer correctly signed by another origin than the seller's is refused,
  on a read and on a commit, under either credential.
- A stored rejection settles the commit; `retry: same` keeps it pending.
- Each seller fault mode is refused, on a read and on a commit, for each
  credential that it breaks.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from persistence.observe import BuyerRecords, SellerRecords
from tests.stack import BUYER, CFBOT, OPERATOR, RESELLER, SELLER, Lines, Stack, lines

DISPLAY = "business-daily-display"
CTV = "weather-app-ctv"


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    with Stack(tmp_path) as running:
        yield running


def _commits(stack: Stack, proposal_id: str) -> list[str]:
    """The states of the buyer's commits on `proposal_id`, oldest first."""
    with stack.buyer_db() as db:
        rows = db.execute(
            "SELECT state FROM commits WHERE proposal_id = ? ORDER BY id", (proposal_id,)
        ).fetchall()
    return [r["state"] for r in rows]


def _kept_answers(stack: Stack) -> int:
    with stack.buyer_db() as db:
        return int(db.execute("SELECT COUNT(*) FROM signed_responses").fetchone()[0])


def _sent(stack: Stack) -> list[tuple[str, str]]:
    return [(r.method, str(r.url)) for r in stack.requests]


# Agreed


def test_a_signed_commit_is_agreed_and_both_parties_keep_it(stack: Stack) -> None:
    response = stack.commit("demo-wba-1", [DISPLAY])
    assert response.status_code == 200
    outcome = response.json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == "web_bot_auth"
    assert outcome["keyid"] == stack.buyer_keys.active().thumbprint
    assert outcome["seller"] == {
        "origin": SELLER,
        "domain": "seller.wba-demo.noetis.dev",
        "legal_name": "Demo Seller Inc.",
    }
    assert outcome["attributed"] is True  # the verified host is the proposal's seller domain
    assert [e["role"] for e in outcome["entries"]] == ["commitment", "acceptance"]
    # The trigger named no seller, so it went to the configured one.
    assert _sent(stack) == [
        ("GET", f"{SELLER}/proposals/demo-wba-1"),
        ("POST", f"{SELLER}/proposals/demo-wba-1/commit"),
    ]
    with stack.seller_db() as db:
        agreed = db.execute(
            "SELECT record_digest FROM agreed_records WHERE proposal_id = 'demo-wba-1'"
        ).fetchone()
    assert agreed["record_digest"] == outcome["record_digest"]
    assert _commits(stack, "demo-wba-1") == ["agreed"]
    with stack.buyer_db() as db:
        kept = db.execute(
            "SELECT origin, status, keyid FROM signed_responses WHERE id = ?",
            (outcome["evidence_id"],),
        ).fetchone()
    assert (kept["origin"], kept["status"]) == (SELLER, 200)
    assert kept["keyid"] == stack.seller_key.thumbprint
    _assert_kept_as_carried(stack, "demo-wba-1", outcome["evidence_id"])


def test_a_bearer_commit_is_agreed_with_no_signing_key(stack: Stack) -> None:
    outcome = stack.commit("demo-bearer-1", [DISPLAY], "bearer").json()
    assert outcome["state"] == "agreed", outcome
    assert outcome["authentication_method"] == "bearer"
    assert outcome["keyid"] is None
    (_, commit) = stack.requests
    assert commit.headers["authorization"].startswith("Bearer ")
    assert "signature" not in commit.headers
    with stack.buyer_db() as db:
        sent = db.execute(
            "SELECT q.headers FROM signed_responses r JOIN signed_requests q ON q.id = r.request_id"
        ).fetchone()
    assert "authorization" not in sent["headers"].lower()  # the token is never kept
    with BuyerRecords.open(stack.buyer_dir / "buyer.db") as records:
        kept = records.response(outcome["evidence_id"])
    assert list(kept.request.request.headers) == _sent_lines(commit)


def _sent_lines(request: httpx.Request) -> Lines:
    """The lines the buyer's client sent, as it sent them, the bearer token left out."""
    return [(k, v) for k, v in lines(request.headers.raw) if k.lower() != "authorization"]


def _assert_kept_as_carried(stack: Stack, proposal_id: str, evidence_id: int) -> None:
    """Each party kept the header lines of the signed commit exactly as the transport carried
    them: in order, in case, and every line."""
    (sent,) = [r for r in stack.requests if r.method == "POST"]
    (delivered,) = [a for r, a in zip(stack.requests, stack.responses, strict=True) if r is sent]
    with BuyerRecords.open(stack.buyer_dir / "buyer.db") as records:
        kept = records.response(evidence_id)
    assert list(kept.request.request.headers) == _sent_lines(sent)
    assert list(kept.response.headers) == lines(delivered.headers.raw)
    (received,) = [r for r in stack.received if r.method == "POST"]
    with SellerRecords.open(stack.seller_dir / "seller.db") as records:
        (commitment, _) = records.entries(proposal_id)
        assert commitment.evidence_id is not None
        kept_request = records.request(commitment.evidence_id)
    assert list(kept_request.request.headers) == received.headers


def test_a_read_answers_the_proposal_as_received(stack: Stack) -> None:
    outcome = stack.read("demo-wba-2").json()
    assert outcome["state"] == "read", outcome
    assert outcome["proposal"]["seller"]["domain"] == "seller.wba-demo.noetis.dev"
    assert [i["line_item_id"] for i in outcome["proposal"]["line_items"]] == [DISPLAY, CTV]
    assert stack.read("demo-bearer-1", "bearer").json()["keyid"] is None


def test_a_read_the_seller_refuses_is_rejected_with_its_errors(stack: Stack) -> None:
    outcome = stack.read("no-such-proposal").json()
    assert outcome["state"] == "rejected"
    assert [e["code"] for e in outcome["errors"]] == ["not_found"]
    assert outcome["commit_id"] is None


# Refused before anything is sent


def test_an_unknown_line_item_is_refused_unsent(stack: Stack) -> None:
    response = stack.commit("demo-wba-1", ["no-such-item"])
    assert response.status_code == 200
    outcome = response.json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "unknown-line-item")
    assert "no-such-item" in outcome["detail"]
    assert stack.requests == []


def test_a_trigger_for_another_seller_is_refused_unsent(stack: Stack) -> None:
    """The seller is resolved once, from the buyer's own records."""
    read = {"seller": "https://other.example", "proposal_id": "p-1"}
    for route, trigger in (
        ("/operator/read", read),
        ("/operator/commit", read | {"line_item_ids": [DISPLAY]}),
    ):
        outcome = stack.buyer.post(route, json=trigger, headers=OPERATOR).json()
        assert (outcome["state"], outcome["reason"]) == ("refused", "unknown-seller")
        assert outcome["seller"] is None
    assert stack.requests == []


def test_a_bearer_call_without_an_issued_token_is_refused_unsent(tmp_path: Path) -> None:
    with Stack(tmp_path, token=False) as stack:
        outcome = stack.commit("demo-bearer-1", [DISPLAY], "bearer").json()
        assert (outcome["state"], outcome["reason"]) == ("refused", "credential-not-issued")
        assert outcome["authentication_method"] == "bearer"
        assert stack.requests == []


def test_a_commit_to_a_proposal_the_seller_wont_show_is_refused(stack: Stack) -> None:
    outcome = stack.commit("no-such-proposal", [DISPLAY]).json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "unreadable-proposal")
    assert "not_found" in outcome["detail"]
    assert [m for m, _ in _sent(stack)] == ["GET"]  # nothing to commit to, so nothing sent


def test_a_commit_trigger_names_at_least_one_line_item(stack: Stack) -> None:
    trigger = {"proposal_id": "demo-wba-1", "line_item_ids": []}
    response = stack.buyer.post("/operator/commit", json=trigger, headers=OPERATOR)
    assert response.status_code == 422
    assert stack.requests == []


# Refused: what the seller sent


def _replace(stack: Stack, method: str, status: int, body: bytes) -> None:
    """The seller's answers to `method` requests become `body`, correctly signed."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        return stack.signed(request, status, body) if request.method == method else None

    stack.answer = answer


NO_RETRY = json.dumps({"errors": [{"code": "not_committable", "detail": "no"}]}).encode()
BOUNDARY = json.dumps({"error": "invalid-token", "detail": "no principal"}).encode()


@pytest.mark.parametrize(
    ("status", "body"),
    [(200, b"not json"), (200, b'{"version": 1}'), (200, b"[]"), (200, b"\xff\xfe{")],
    ids=["not-json", "not-a-proposal", "a-list", "not-utf-8"],
)
def test_a_malformed_read_is_refused(stack: Stack, status: int, body: bytes) -> None:
    _replace(stack, "GET", status, body)
    response = stack.read("demo-wba-1")
    assert response.status_code == 200
    outcome = response.json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "malformed-answer"), outcome
    # The commit flow refuses at the read, so it composes and sends nothing.
    assert stack.commit("demo-wba-1", [DISPLAY]).json()["reason"] == "malformed-answer"
    assert [m for m, _ in _sent(stack)] == ["GET", "GET"]
    assert _commits(stack, "demo-wba-1") == []


@pytest.mark.parametrize(
    ("status", "body", "reason"),
    [
        (409, b"[]", "malformed-answer"),
        (200, b'{"version": 1}', "malformed-answer"),
        (200, b'{"entries": []}', "malformed-answer"),
        (200, b"\xff", "malformed-answer"),
        # An error without retry is no § 2.4 answer, so it settles nothing.
        (409, NO_RETRY, "malformed-answer"),
        (401, BOUNDARY, "credential-refused"),
    ],
    ids=["list", "not-a-result", "no-entries", "not-utf-8", "no-retry", "boundary-refusal"],
)
def test_a_malformed_answer_to_a_commit_is_refused_and_settles_nothing(
    stack: Stack, status: int, body: bytes, reason: str
) -> None:
    _replace(stack, "POST", status, body)
    response = stack.commit("demo-wba-1", [DISPLAY])
    assert response.status_code == 200
    outcome = response.json()
    assert (outcome["state"], outcome["reason"]) == ("refused", reason), outcome
    assert _commits(stack, "demo-wba-1") == ["pending"]
    assert _kept_answers(stack) == 0


def _down(request: httpx.Request) -> httpx.Response:
    refused = "connection refused"
    raise httpx.ConnectError(refused, request=request)


def test_an_unreachable_seller_is_refused(stack: Stack) -> None:
    stack.answer = _down
    outcome = stack.read("demo-wba-1").json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "unreachable")


def _edited(stack: Stack, method: str, edit: Callable[[dict[str, object]], None]) -> None:
    """The seller's own answers to `method` requests, edited, then signed again."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        if request.method != method:
            return None
        real = stack.forward(request)
        document = real.json()
        edit(document)
        return stack.signed(request, real.status_code, json.dumps(document).encode())

    stack.answer = answer


def test_a_proposal_that_names_another_seller_is_refused(stack: Stack) -> None:
    """A correctly signed proposal from this seller that names another seller."""
    _edited(stack, "GET", lambda d: d.update(seller={"domain": "other.example", "legal_name": "X"}))
    outcome = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "wrong-seller"), outcome
    assert "other.example" in outcome["detail"]
    assert _commits(stack, "demo-wba-1") == []


def _entries(
    edit: Callable[[list[dict[str, object]]], object],
) -> Callable[[dict[str, object]], None]:
    def apply(document: dict[str, object]) -> None:
        entries = document["entries"]
        assert isinstance(entries, list)
        edit(entries)

    return apply


@pytest.mark.parametrize(
    ("edit", "rule"),
    [
        # The result doesn't start with the commit's own entry.
        (_entries(lambda e: e[0].update(at="2020-01-01T00:00:00Z")), "doesn't start with"),
        (_entries(lambda e: e.pop()), "no acceptance"),
        (_entries(lambda e: e[1].update(line_item_ids=[CTV])), "no acceptance"),
    ],
    ids=["first-entry", "no-acceptance", "acceptance-for-other-items"],
)
def test_a_result_that_doesnt_answer_the_commit_is_refused_then_replayed(
    stack: Stack, edit: Callable[[dict[str, object]], None], rule: str
) -> None:
    _edited(stack, "POST", edit)
    outcome = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "result-mismatch"), outcome
    assert rule in outcome["detail"]
    assert _commits(stack, "demo-wba-1") == ["pending"] and _kept_answers(stack) == 0
    # The same commit, re-sent whole, gets the seller's stored result.
    stack.answer = None
    assert stack.commit("demo-wba-1", [DISPLAY]).json()["state"] == "agreed"
    assert _commits(stack, "demo-wba-1") == ["agreed"]


def test_a_settlement_that_fails_keeps_no_evidence(stack: Stack) -> None:
    """The buyer keeps the answer and settles the commit in one transaction, so a commit
    another trigger settled meanwhile keeps nothing of this answer."""

    def settled_meanwhile(request: httpx.Request) -> httpx.Response | None:
        if request.method != "POST":
            return None
        db = sqlite3.connect(stack.buyer_dir / "buyer.db")
        try:  # another trigger settled the commit while this one waited for the seller
            db.execute("UPDATE commits SET state = 'rejected'")
            db.commit()
        finally:
            db.close()
        return stack.forward(request)

    stack.answer = settled_meanwhile
    response = stack.commit("demo-wba-1", [DISPLAY])
    assert response.status_code == 409
    assert response.json() == {
        "error": "not-pending",
        "detail": "commit 1 is no longer pending, so it stays settled",
    }
    assert _kept_answers(stack) == 0
    with stack.buyer_db() as db:
        assert db.execute("SELECT COUNT(*) FROM signed_requests").fetchone()[0] == 0


def _corrupt_digest_input(stack: Stack, commit_id: int) -> None:
    """Tamper: the buyer's stored digest input for `commit_id` no longer matches its body."""
    db = sqlite3.connect(stack.buyer_dir / "buyer.db")
    try:
        (kept,) = db.execute(
            "SELECT digest_input FROM commits WHERE id = ?", (commit_id,)
        ).fetchone()
        db.execute(
            "UPDATE commits SET digest_input = ? WHERE id = ?", (bytes(kept) + b" ", commit_id)
        )
        db.commit()
    finally:
        db.close()


def test_a_digest_that_doesnt_recompute_from_the_kept_input_is_refused(stack: Stack) -> None:
    """The seller's acceptance matches the commit, but its record_digest isn't the digest of
    the input the buyer kept for that commit."""
    stack.answer = lambda request: _down(request) if request.method == "POST" else None
    first = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert (first["state"], first["reason"]) == ("refused", "unreachable"), first
    assert _commits(stack, "demo-wba-1") == ["pending"]
    _corrupt_digest_input(stack, 1)
    stack.answer = None
    outcome = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "result-mismatch"), outcome
    assert "record_digest doesn't recompute" in outcome["detail"]
    assert _commits(stack, "demo-wba-1") == ["pending"] and _kept_answers(stack) == 0


# Refused: an answer signed by another origin


def _signed_by_the_reseller(stack: Stack, method: str) -> None:
    """The seller's own answers to `method` requests, signed again by the reseller, under its
    own origin, with its own key, which its directory publishes."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        if request.method != method:
            return None
        real = stack.forward(request)
        return stack.signed(request, real.status_code, real.content, by=RESELLER)

    stack.answer = answer


@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
@pytest.mark.parametrize("on", ["read", "commit"])
def test_an_answer_signed_by_another_origin_is_refused(
    stack: Stack, credential: str, on: str
) -> None:
    proposal_id = PROPOSAL[credential]
    _signed_by_the_reseller(stack, "GET" if on == "read" else "POST")
    if on == "read":
        outcome = stack.read(proposal_id, credential).json()
    else:
        outcome = stack.commit(proposal_id, [CTV], credential).json()
    assert (outcome["state"], outcome["reason"]) == ("refused", "origin-mismatch"), outcome
    assert RESELLER in outcome["detail"]
    assert outcome["authentication_method"] == credential
    assert _kept_answers(stack) == 0
    assert _commits(stack, proposal_id) == ([] if on == "read" else ["pending"])


def test_a_pending_commit_is_found_whatever_the_order_of_its_line_items(stack: Stack) -> None:
    later = {"errors": [{"code": "not_committable", "detail": "busy", "retry": "same"}]}
    _replace(stack, "POST", 503, json.dumps(later).encode())
    assert stack.commit("demo-wba-1", [DISPLAY, CTV]).json()["state"] == "rejected"
    stack.answer = None
    agreed = stack.commit("demo-wba-1", [CTV, DISPLAY]).json()
    assert agreed["state"] == "agreed", agreed
    first, again = (r.content for r in stack.requests if r.method == "POST")
    assert first == again  # the pending commit, re-sent whole
    assert _commits(stack, "demo-wba-1") == ["agreed"]


# Rejected


def test_a_stored_rejection_settles_the_commit(stack: Stack) -> None:
    assert stack.commit("demo-wba-1", [DISPLAY]).json()["state"] == "agreed"
    # An agreed line item can't be committed to again; the seller stores that answer.
    outcome = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert outcome["state"] == "rejected", outcome
    assert [(e["code"], e["retry"]) for e in outcome["errors"]] == [("not_committable", "none")]
    assert _commits(stack, "demo-wba-1") == ["agreed", "rejected"]


def test_a_retry_same_rejection_keeps_the_commit_pending(stack: Stack) -> None:
    later = {"errors": [{"code": "not_committable", "detail": "busy", "retry": "same"}]}
    _replace(stack, "POST", 503, json.dumps(later).encode())
    outcome = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert outcome["state"] == "rejected" and outcome["commit_id"] == 1
    assert _commits(stack, "demo-wba-1") == ["pending"]
    stack.answer = None
    agreed = stack.commit("demo-wba-1", [DISPLAY]).json()
    assert (agreed["state"], agreed["commit_id"]) == ("agreed", 1)
    first, again = (json.loads(r.content) for r in stack.requests if r.method == "POST")
    assert first == again  # re-sent whole, with the same idempotency_key


# The seller's fault modes (TEST ONLY, seller/faults.py)

#: What each mode breaks, per credential. A bearer request is unsigned, so there is no
#: request signature to bind to: unbound and rebound answers are what it should get.
FAULTS = [
    ("web_bot_auth", "strip", "signature-missing"),
    ("web_bot_auth", "unbound", "response-not-bound"),
    ("web_bot_auth", "rebound", "signature-invalid"),
    ("web_bot_auth", "wrong_digest", "content-digest"),
    ("bearer", "strip", "signature-missing"),
    ("bearer", "wrong_digest", "content-digest"),
]
PROPOSAL = {"web_bot_auth": "demo-wba-2", "bearer": "demo-bearer-1"}


@pytest.mark.parametrize(("credential", "mode", "reason"), FAULTS)
@pytest.mark.parametrize("on", ["read", "commit"])
def test_each_fault_is_refused(
    tmp_path: Path, credential: str, mode: str, reason: str, on: str
) -> None:
    proposal_id = PROPOSAL[credential]
    with Stack(tmp_path, faults=True) as stack:
        assert stack.seller.put("/test/fault", json={"mode": mode, "on": on}).status_code == 200
        if on == "read":
            outcome = stack.read(proposal_id, credential).json()
        else:
            outcome = stack.commit(proposal_id, [CTV], credential).json()
        assert (outcome["state"], outcome["reason"]) == ("refused", reason), outcome
        assert outcome["authentication_method"] == credential
        assert _kept_answers(stack) == 0
        assert stack.seller.put("/test/fault", json={"mode": "none"}).status_code == 200
        assert stack.commit(proposal_id, [CTV], credential).json()["state"] == "agreed"


@pytest.mark.parametrize("mode", ["unbound", "rebound"])
def test_an_answer_to_a_bearer_request_needs_no_binding(tmp_path: Path, mode: str) -> None:
    with Stack(tmp_path, faults=True) as stack:
        stack.seller.put("/test/fault", json={"mode": mode})
        assert stack.commit("demo-bearer-1", [CTV], "bearer").json()["state"] == "agreed"


# cfbot


def test_the_buyer_signs_for_cfbot_at_its_configured_origin(stack: Stack) -> None:
    check = stack.buyer.post("/operator/cloudflare-check", headers=OPERATOR).json()
    assert check["status"] == 200
    assert check["verdict"]["ok"] is True and check["verdict"]["identity"] == BUYER
    (sent,) = stack.requests
    assert str(sent.url) == f"{CFBOT}/verify"
    assert f'"{BUYER}' in sent.headers["signature-agent"]


def test_an_unreadable_cfbot_verdict_is_reported_as_text(stack: Stack) -> None:
    stack.cfbot = lambda _: httpx.Response(502, content=b"bad gateway")
    check = stack.buyer.post("/operator/cloudflare-check", headers=OPERATOR).json()
    assert check == {"status": 502, "verdict": "bad gateway"}
