"""The buyer, through its operator routes, against the seller app in process (tests/stack.py).

The buyer mirrors the seller's identity boundary: whatever the seller sends is
verified, then parsed, inside one refusal boundary. Each test drives
`/operator/read` or `/operator/commit` and reads the outcome and what each
party kept.

- A signed or bearer commit is agreed, and both parties keep the agreement,
  with the header lines exactly as the transport carried them. One buyer is
  one principal at the seller: a proposal read under one credential is
  committed under the other. The seller
  decides on the proposal as issued and saves the agreed proposal beside it.
- A verified answer that is malformed, an error without `retry`, or a boundary
  refusal is refused, never a 500, and settles nothing.
- An unknown line item or seller is refused before anything is sent, and a proposal
  the plan's writes don't fit is refused before the commit is sent.
- A proposal other than the one asked for, or one that names another seller, or another
  buyer by domain or by legal name, is refused; a `CommitResult` that
  doesn't answer the commit is refused, and so is one whose `record_digest`
  doesn't recompute from the digest input the buyer kept.
- An answer correctly signed by another origin than the seller's is refused,
  on a read and on a commit, under either credential.
- An unsigned answer is refused whatever its status, and settles nothing.
- A stored rejection settles the commit; `retry: same` keeps it pending.
- Each seller fault mode is refused, on a read and on a commit, for each
  credential that it breaks.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import get_args

import httpx
import pytest

from persistence.values import AuthMethod, Origin
from protocol.record import compose, digest_input, items_by_id
from protocol.values import JsonObject, JsonValue, read_json
from seller.faults import BINDING_FAULTS, refused_under
from tests._tools import plan_writes
from tests.stack import (
    BUYER,
    BUYER_OPERATOR,
    CFBOT,
    DEMO,
    ELSEWHERE,
    RESELLER,
    SELLER,
    Lines,
    Origins,
    Stack,
    as_state,
    lines,
)
from transport.client import ControlFailed
from transport.control import (
    CLOUDFLARE_CHECK,
    COMMIT,
    READ,
    Agreed,
    BreakingFault,
    CfbotAccepted,
    CommitTrigger,
    ErrorBody,
    Read,
    ReadTrigger,
    Refused,
    Rejected,
)

DISPLAY = "business-daily-display"
CTV = "weather-app-ctv"


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    with Stack(tmp_path) as running:
        yield running


def _commits(stack: Stack, proposal_id: str) -> list[str]:
    """The states of the buyer's commits on DISPLAY in `proposal_id`, oldest first."""
    return stack.commit_states(proposal_id, [DISPLAY])


def _kept_nothing(stack: Stack) -> bool:
    """The buyer kept no signed message: no answer, and no request bound to one."""
    with stack.buyer_records() as records:
        return records.messages() == 0


def _sent(stack: Stack) -> list[tuple[str, str]]:
    return [(r.method, str(r.url)) for r in stack.requests]


# Agreed


def test_a_signed_commit_is_agreed_and_both_parties_keep_it(stack: Stack) -> None:
    outcome = as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.authentication_method == "web_bot_auth"
    assert outcome.keyid == stack.buyer_keys.active().thumbprint
    seller = outcome.seller
    assert (str(seller.origin), seller.domain, seller.legal_name) == (
        SELLER,
        "seller.wba-demo.noetis.dev",
        "Demo Seller Inc.",
    )
    assert outcome.attributed is True  # the verified host is the proposal's seller domain
    assert [e.role for e in outcome.entries] == ["commitment", "acceptance"]
    # The trigger named no seller, so it went to the configured one.
    assert _sent(stack) == [
        ("GET", f"{SELLER}/proposals/demo-wba-1"),
        ("POST", f"{SELLER}/proposals/demo-wba-1/commit"),
    ]
    with stack.seller_records() as records:
        (agreed,) = records.agreed("demo-wba-1")
    assert agreed.record_digest == outcome.record_digest
    assert _commits(stack, "demo-wba-1") == ["agreed"]
    with stack.buyer_records() as records:
        kept = records.response(outcome.evidence_id)
    assert (str(kept.signer.origin), kept.response.status) == (SELLER, 200)
    assert kept.signer.keyid == stack.seller_key.thumbprint
    _assert_kept_as_carried(stack, "demo-wba-1", outcome.evidence_id)


def test_a_bearer_commit_is_agreed_with_no_signing_key(stack: Stack) -> None:
    outcome = as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY], "bearer"))
    assert outcome.authentication_method == "bearer"
    assert outcome.keyid is None
    (_, commit) = stack.requests
    assert commit.headers["authorization"].startswith("Bearer ")
    assert "signature" not in commit.headers
    with stack.buyer_records() as records:
        kept = records.response(outcome.evidence_id)
    sent = kept.response.request.lines
    assert all(name.lower() != "authorization" for name, _ in sent)  # the token is never kept
    assert list(sent) == _sent_lines(commit)


@pytest.mark.parametrize(
    ("proposal_id", "credential"),
    [("demo-wba-1", "web_bot_auth"), ("demo-wba-1", "bearer")],
)
def test_a_deployment_under_other_origins_reads_and_commits(
    tmp_path: Path, proposal_id: str, credential: AuthMethod
) -> None:
    """Each agent takes its own origin from its settings: the seller issues in its name."""
    with Stack(tmp_path, origins=ELSEWHERE) as stack:
        read = as_state(Read, stack.read(proposal_id, credential))
        assert read.proposal.get("seller") == {
            "domain": "sell-side.wba-demo.noetis.dev",
            "legal_name": "Demo Seller Inc.",
        }
        outcome = as_state(Agreed, stack.commit(proposal_id, [DISPLAY], credential))
    assert str(outcome.seller.origin) == "https://sell-side.wba-demo.noetis.dev"
    assert {r.url.host for r in stack.requests} == {"sell-side.wba-demo.noetis.dev"}


def test_one_buyer_is_one_principal_under_either_credential(stack: Stack) -> None:
    """A credential only points at the buyer's principal: what one credential reads, the
    other commits to, and the seller records the same principal for each."""
    as_state(Read, stack.read("demo-wba-1", "web_bot_auth"))
    by_token = as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY], "bearer"))
    as_state(Read, stack.read("demo-wba-1", "bearer"))
    by_signature = as_state(Agreed, stack.commit("demo-wba-1", [CTV], "web_bot_auth"))
    assert (by_token.authentication_method, by_signature.authentication_method) == (
        "bearer",
        "web_bot_auth",
    )
    with stack.seller_records() as records:
        principal = records.principal_with_origin(stack.origins.buyer)
        entries = records.entries("demo-wba-1")
    assert principal is not None and principal.domain == stack.origins.buyer.host
    commitments = [(e.principal_id, e.authentication_method) for e in entries if e.idempotency_key]
    assert commitments == [(principal.id, "bearer"), (principal.id, "web_bot_auth")]


def _outside_line_items(proposal: JsonObject) -> JsonObject:
    """The members of a proposal that a commit doesn't change."""
    return {k: v for k, v in proposal.items() if k not in {"line_items", "status", "assent"}}


def test_a_commit_saves_the_agreed_proposal_and_leaves_what_it_was_decided_on(
    stack: Stack,
) -> None:
    issued = as_state(Read, stack.read("demo-wba-2")).proposal
    as_state(Agreed, stack.commit("demo-wba-2", [DISPLAY]))
    agreed = as_state(Read, stack.read("demo-wba-2")).proposal

    # The named line item is the composed one, agreed; the rest of the proposal is as issued,
    # and its status follows § 4.3.3: the other line item is still published.
    writes = plan_writes(DISPLAY)
    composed = compose(issued, writes)
    assert items_by_id(agreed)[DISPLAY] == {**items_by_id(composed)[DISPLAY], "status": "agreed"}
    assert items_by_id(agreed)[CTV] == items_by_id(issued)[CTV]
    assert agreed.get("status") == "published"
    assert _outside_line_items(agreed) == _outside_line_items(issued)

    # The seller decided on the proposal as issued: the digest input it stored is the one
    # composed on what the buyer read before the commit.
    with stack.seller_records() as records:
        (stored,) = records.agreed("demo-wba-2")
    assert stored.digest_input == digest_input(composed, [DISPLAY])

    # The next commit is decided on the agreed proposal, and agrees the last line item.
    as_state(Agreed, stack.commit("demo-wba-2", [CTV]))
    final = as_state(Read, stack.read("demo-wba-2")).proposal
    assert items_by_id(final)[DISPLAY] == items_by_id(agreed)[DISPLAY]
    assert items_by_id(final)[CTV].get("status") == "agreed"
    assert final.get("status") == "agreed"


def _sent_lines(request: httpx.Request) -> Lines:
    """The lines the buyer's client sent, as it sent them, the bearer token left out."""
    return [(k, v) for k, v in lines(request.headers.raw) if k.lower() != "authorization"]


def _assert_kept_as_carried(stack: Stack, proposal_id: str, evidence_id: int) -> None:
    """Each party kept the header lines of the signed commit exactly as the transport carried
    them: in order, in case, and every line."""
    (sent,) = [r for r in stack.requests if r.method == "POST"]
    (delivered,) = [a for r, a in zip(stack.requests, stack.responses, strict=True) if r is sent]
    with stack.buyer_records() as records:
        kept = records.response(evidence_id)
    assert list(kept.response.request.lines) == _sent_lines(sent)
    assert list(kept.response.lines) == lines(delivered.headers.raw)
    (received,) = [r for r in stack.received if r.method == "POST"]
    with stack.seller_records() as records:
        (commitment, _) = records.entries(proposal_id)
        assert commitment.evidence_id is not None
        kept_request = records.request(commitment.evidence_id)
    assert list(kept_request.request.lines) == received.headers


def test_a_read_answers_the_proposal_as_received(stack: Stack) -> None:
    outcome = as_state(Read, stack.read("demo-wba-2"))
    assert outcome.proposal.get("seller") == {
        "domain": "seller.wba-demo.noetis.dev",
        "legal_name": "Demo Seller Inc.",
    }
    assert list(items_by_id(outcome.proposal)) == [DISPLAY, CTV]
    assert as_state(Read, stack.read("demo-wba-2", "bearer")).keyid is None


def test_a_read_the_seller_refuses_is_rejected_with_its_errors(stack: Stack) -> None:
    outcome = as_state(Rejected, stack.read("no-such-proposal"))
    assert [e.code for e in outcome.errors] == ["not_found"]
    assert outcome.commit_id is None


# Refused before anything is sent


def test_an_unknown_line_item_is_refused_unsent(stack: Stack) -> None:
    outcome = as_state(Refused, stack.commit("demo-wba-1", ["no-such-item"]))
    assert outcome.code == "unknown-line-item"
    assert "no-such-item" in outcome.detail
    assert stack.requests == []


def test_a_trigger_for_another_seller_is_refused_unsent(stack: Stack) -> None:
    """The seller is resolved once, from the buyer's own records."""
    other = Origin.parse("https://other.wba-demo.noetis.dev")
    outcomes = [
        stack.buyer_control.call(READ, ReadTrigger(seller=other, proposal_id="p-1")),
        stack.buyer_control.call(
            COMMIT, CommitTrigger(seller=other, proposal_id="p-1", line_item_ids=[DISPLAY])
        ),
    ]
    for outcome in outcomes:
        refused = as_state(Refused, outcome)
        assert (refused.code, refused.seller) == ("unknown-seller", None)
    assert stack.requests == []


@pytest.mark.parametrize(
    "seller",
    [
        "https://Seller.Example",
        f"{SELLER}/",
        f"{SELLER}:443",
        "seller.wba-demo.noetis.dev",
        "http://seller.wba-demo.noetis.dev",
    ],
    ids=["uppercase", "trailing-slash", "port", "no-scheme", "http"],
)
@pytest.mark.parametrize("route", [READ.path, COMMIT.path])
def test_a_trigger_that_names_no_origin_is_invalid(stack: Stack, seller: str, route: str) -> None:
    """A seller is named by its origin, `https://<host>`, and nothing else."""
    trigger = {"seller": seller, "proposal_id": "demo-wba-1", "line_item_ids": [DISPLAY]}
    response = stack.buyer.post(route, json=trigger, headers=BUYER_OPERATOR)
    assert response.status_code == 422, response.text
    assert ErrorBody.model_validate_json(response.content).error == "validation"
    assert stack.requests == []


def test_a_bearer_call_without_an_issued_token_is_refused_unsent(tmp_path: Path) -> None:
    with Stack(tmp_path, token=False) as stack:
        outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY], "bearer"))
        assert outcome.code == "credential-not-issued"
        assert outcome.authentication_method == "bearer"
        assert stack.requests == []


def test_a_commit_to_a_proposal_the_seller_wont_show_is_refused(stack: Stack) -> None:
    outcome = as_state(Refused, stack.commit("no-such-proposal", [DISPLAY]))
    assert outcome.code == "unreadable-proposal"
    assert "not_found" in outcome.detail
    assert [m for m, _ in _sent(stack)] == ["GET"]  # nothing to commit to, so nothing sent


def test_a_commit_trigger_names_at_least_one_line_item(stack: Stack) -> None:
    trigger = {"proposal_id": "demo-wba-1", "line_item_ids": []}
    response = stack.buyer.post(COMMIT.path, json=trigger, headers=BUYER_OPERATOR)
    assert response.status_code == 422
    assert ErrorBody.model_validate_json(response.content).error == "validation"
    assert stack.requests == []


# Refused: what the seller sent


def _replace(stack: Stack, method: str, status: int, body: bytes) -> None:
    """The seller's answers to `method` requests become `body`, correctly signed."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        return stack.signed(request, status, body) if request.method == method else None

    stack.answer = answer


NO_RETRY = json.dumps({"errors": [{"code": "not_committable", "detail": "no"}]}).encode()
BOUNDARY = json.dumps({"error": "invalid-token", "status": 401}).encode()


@pytest.mark.parametrize(
    ("status", "body"),
    [(200, b"not json"), (200, b'{"version": 1}'), (200, b"[]"), (200, b"\xff\xfe{")],
    ids=["not-json", "not-a-proposal", "a-list", "not-utf-8"],
)
def test_a_malformed_read_is_refused(stack: Stack, status: int, body: bytes) -> None:
    _replace(stack, "GET", status, body)
    assert as_state(Refused, stack.read("demo-wba-1")).code == "malformed-answer"
    # The commit flow refuses at the read, so it composes and sends nothing.
    assert as_state(Refused, stack.commit("demo-wba-1", [DISPLAY])).code == "malformed-answer"
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
    assert as_state(Refused, stack.commit("demo-wba-1", [DISPLAY])).code == reason
    assert _commits(stack, "demo-wba-1") == ["pending"]
    assert _kept_nothing(stack)


def _down(request: httpx.Request) -> httpx.Response:
    refused = "connection refused"
    raise httpx.ConnectError(refused, request=request)


def test_an_unreachable_seller_is_refused(stack: Stack) -> None:
    stack.answer = _down
    assert as_state(Refused, stack.read("demo-wba-1")).code == "unreachable"


def _edited(stack: Stack, method: str, edit: Callable[[JsonObject], None]) -> None:
    """The seller's own answers to `method` requests, edited, then signed again."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        if request.method != method:
            return None
        real = stack.forward(request)
        document = read_json(real.content)
        edit(document)
        return stack.signed(request, real.status_code, json.dumps(document).encode())

    stack.answer = answer


def test_a_proposal_that_names_a_member_twice_is_refused(stack: Stack) -> None:
    """A correctly signed proposal whose bytes name `seller` twice, the seller's own last: a
    reader that kept the first would read another seller from the same signed bytes."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        if request.method != "GET":
            return None
        real = stack.forward(request).content
        first = b'{"seller": {"domain": "other.example", "legal_name": "X"}, '
        return stack.signed(request, 200, first + real[1:])

    stack.answer = answer
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.code == "malformed-answer"
    assert "'seller' twice" in outcome.detail
    assert [m for m, _ in _sent(stack)] == ["GET"]
    assert _commits(stack, "demo-wba-1") == []


def test_a_proposal_that_names_another_seller_is_refused(stack: Stack) -> None:
    """A correctly signed proposal from this seller that names another seller."""
    _edited(stack, "GET", lambda d: d.update(seller={"domain": "other.example", "legal_name": "X"}))
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.code == "wrong-seller"
    assert "other.example" in outcome.detail
    assert _commits(stack, "demo-wba-1") == []


@pytest.mark.parametrize(
    ("buyer", "named"),
    [
        ({"domain": "other-agency.wba-demo.noetis.dev", "legal_name": "X"}, "other-agency"),
        (None, "None"),
    ],
    ids=["another buyer", "no buyer"],
)
@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
def test_a_proposal_that_names_another_buyer_is_refused(
    stack: Stack, buyer: JsonObject | None, named: str, credential: AuthMethod
) -> None:
    """A correctly signed proposal from this seller whose buyer isn't this buyer's own party:
    the buyer neither commits to it nor keeps anything of it."""

    def rename(document: JsonObject) -> None:
        if buyer is None:
            document.pop("buyer")
        else:
            document["buyer"] = buyer

    _edited(stack, "GET", rename)
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY], credential))
    assert outcome.code == "wrong-buyer"
    assert named in outcome.detail and BUYER.removeprefix("https://") in outcome.detail
    assert [m for m, _ in _sent(stack)] == ["GET"]
    assert _commits(stack, "demo-wba-1") == []


@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
def test_a_proposal_that_names_this_buyers_domain_under_another_legal_name_is_refused(
    stack: Stack, credential: AuthMethod
) -> None:
    """The buyer's own party is its domain and its legal name: a proposal that names its
    domain with another legal name doesn't name it, so the buyer agrees to nothing."""
    host = BUYER.removeprefix("https://")
    _edited(stack, "GET", lambda d: d.update(buyer={"domain": host, "legal_name": "Other LLC"}))
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY], credential))
    assert outcome.code == "wrong-buyer"
    assert "'Other LLC'" in outcome.detail and "'Demo Buyer Agency LLC'" in outcome.detail
    assert [m for m, _ in _sent(stack)] == ["GET"]
    assert _commits(stack, "demo-wba-1") == []


@pytest.mark.parametrize("operation", ["read", "commit"])
def test_a_proposal_other_than_the_one_asked_for_is_refused(stack: Stack, operation: str) -> None:
    """A correctly signed answer to the read of demo-wba-1 that is another proposal: the buyer
    neither shows it as demo-wba-1 nor commits to it under that id."""
    _edited(stack, "GET", lambda d: d.update(proposal_id="demo-wba-2"))
    if operation == "read":
        outcome = as_state(Refused, stack.read("demo-wba-1"))
    else:
        outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.code == "wrong-proposal"
    assert "demo-wba-2" in outcome.detail and "demo-wba-1" in outcome.detail
    assert [m for m, _ in _sent(stack)] == ["GET"]
    assert _commits(stack, "demo-wba-1") == [] and _kept_nothing(stack)


@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
def test_a_proposal_the_plan_doesnt_fit_is_refused(stack: Stack, credential: AuthMethod) -> None:
    """The plan selects a cancellation policy, and this proposal's line item offers none, so
    the buyer has no commit to send: it refuses, and sends and keeps nothing."""

    def without_the_policy(document: JsonObject) -> None:
        del items_by_id(document)[DISPLAY]["cancellation_policy"]

    _edited(stack, "GET", without_the_policy)
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY], credential))
    assert outcome.code == "plan-mismatch"
    assert "/cancellation_policy/selected" in outcome.detail
    assert [m for m, _ in _sent(stack)] == ["GET"]
    assert _commits(stack, "demo-wba-1") == [] and _kept_nothing(stack)


def _entries(edit: Callable[[list[JsonValue]], object]) -> Callable[[JsonObject], None]:
    def apply(document: JsonObject) -> None:
        entries = document.get("entries")
        assert isinstance(entries, list)
        edit(entries)

    return apply


def _member(index: int, **members: JsonValue) -> Callable[[list[JsonValue]], None]:
    """Sets `members` on the entry at `index`."""

    def set_members(entries: list[JsonValue]) -> None:
        entry = entries[index]
        assert isinstance(entry, dict)
        entry.update(members)

    return set_members


@pytest.mark.parametrize(
    ("edit", "rule"),
    [
        # The result doesn't start with the commit's own entry.
        (_entries(_member(0, at="2020-01-01T00:00:00Z")), "doesn't start with"),
        (_entries(lambda e: e.pop()), "no acceptance"),
        (_entries(_member(1, line_item_ids=[CTV])), "no acceptance"),
    ],
    ids=["first-entry", "no-acceptance", "acceptance-for-other-items"],
)
def test_a_result_that_doesnt_answer_the_commit_is_refused_then_replayed(
    stack: Stack, edit: Callable[[JsonObject], None], rule: str
) -> None:
    _edited(stack, "POST", edit)
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.code == "result-mismatch"
    assert rule in outcome.detail
    assert _commits(stack, "demo-wba-1") == ["pending"] and _kept_nothing(stack)
    # The same commit, re-sent whole, gets the seller's stored result.
    stack.answer = None
    as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY]))
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
    with pytest.raises(ControlFailed) as failed:
        stack.commit("demo-wba-1", [DISPLAY])
    assert failed.value.status == 409
    assert failed.value.error == ErrorBody(
        error="not-pending", detail="commit 1 is no longer pending, so it stays settled"
    )
    assert _kept_nothing(stack)


def _corrupt_digest_input(stack: Stack, commit_id: int) -> None:
    """Tamper: the buyer's stored digest input for `commit_id` no longer matches its body."""
    db = sqlite3.connect(stack.buyer_dir / "buyer.db")
    try:
        db.execute(
            "UPDATE commits SET digest_input = CAST(digest_input || ' ' AS BLOB) WHERE id = ?",
            (commit_id,),
        )
        db.commit()
    finally:
        db.close()


def test_a_digest_that_doesnt_recompute_from_the_kept_input_is_refused(stack: Stack) -> None:
    """The seller's acceptance matches the commit, but its record_digest isn't the digest of
    the input the buyer kept for that commit."""
    stack.answer = lambda request: _down(request) if request.method == "POST" else None
    assert as_state(Refused, stack.commit("demo-wba-1", [DISPLAY])).code == "unreachable"
    assert _commits(stack, "demo-wba-1") == ["pending"]
    _corrupt_digest_input(stack, 1)
    stack.answer = None
    outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.code == "result-mismatch"
    assert "record_digest doesn't recompute" in outcome.detail
    assert _commits(stack, "demo-wba-1") == ["pending"] and _kept_nothing(stack)


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
    stack: Stack, credential: AuthMethod, on: str
) -> None:
    proposal_id = "demo-wba-2"
    _signed_by_the_reseller(stack, "GET" if on == "read" else "POST")
    if on == "read":
        outcome = as_state(Refused, stack.read(proposal_id, credential))
    else:
        outcome = as_state(Refused, stack.commit(proposal_id, [CTV], credential))
    assert outcome.code == "origin-mismatch"
    assert RESELLER in outcome.detail
    assert outcome.authentication_method == credential
    assert _kept_nothing(stack)
    assert stack.commit_states(proposal_id, [CTV]) == ([] if on == "read" else ["pending"])


@pytest.mark.parametrize(
    ("status", "body"),
    [(409, NO_RETRY), (404, b'{"errors": [{"code": "not_found", "detail": "no"}]}'), (502, b"")],
    ids=["stored-rejection", "not-found", "bad-gateway"],
)
@pytest.mark.parametrize("on", ["read", "commit"])
def test_an_unsigned_answer_of_any_status_is_refused(
    stack: Stack, status: int, body: bytes, on: str
) -> None:
    """An unsigned refusal arrives with its own status, and is still no word of the seller's:
    it settles nothing, and its errors are never taken as a rejection."""
    method = "GET" if on == "read" else "POST"
    stack.answer = lambda r: httpx.Response(status, content=body) if r.method == method else None
    if on == "read":
        outcome = as_state(Refused, stack.read("demo-wba-1"))
    else:
        outcome = as_state(Refused, stack.commit("demo-wba-1", [DISPLAY]))
    assert outcome.code == "signature-missing"
    assert f"the seller's {status} answer" in outcome.detail
    assert _kept_nothing(stack)
    assert _commits(stack, "demo-wba-1") == ([] if on == "read" else ["pending"])


def test_each_boot_deals_with_the_sellers_its_settings_name(tmp_path: Path) -> None:
    """The buyer keeps no record of its sellers: a token its settings no longer hold is gone
    on the next boot, and so is a seller they no longer name."""
    with Stack(tmp_path) as stack:
        as_state(Read, stack.read("demo-wba-1", "bearer"))
    with Stack(tmp_path, token=False) as stack:
        refused = as_state(Refused, stack.read("demo-wba-1", "bearer"))
        assert refused.code == "credential-not-issued"
        as_state(Read, stack.read("demo-wba-1"))
    # The seller moves; its buyer, whose identity the seller never rewrites, stays.
    with Stack(tmp_path, origins=Origins(seller=ELSEWHERE.seller)) as stack:
        trigger = ReadTrigger(proposal_id="demo-wba-1", seller=DEMO.seller)
        refused = as_state(Refused, stack.buyer_control.call(READ, trigger))
        assert refused.code == "unknown-seller"
        assert stack.requests == []


def test_a_pending_commit_is_found_whatever_the_order_of_its_line_items(stack: Stack) -> None:
    later = {"errors": [{"code": "not_committable", "detail": "busy", "retry": "same"}]}
    _replace(stack, "POST", 503, json.dumps(later).encode())
    as_state(Rejected, stack.commit("demo-wba-1", [DISPLAY, CTV]))
    stack.answer = None
    as_state(Agreed, stack.commit("demo-wba-1", [CTV, DISPLAY]))
    first, again = (r.content for r in stack.requests if r.method == "POST")
    assert first == again  # the pending commit, re-sent whole
    assert stack.commit_states("demo-wba-1", [DISPLAY, CTV]) == ["agreed"]


# Rejected


def test_a_stored_rejection_settles_the_commit(stack: Stack) -> None:
    as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY]))
    # An agreed line item can't be committed to again; the seller stores that answer.
    outcome = as_state(Rejected, stack.commit("demo-wba-1", [DISPLAY]))
    assert [(e.code, e.retry) for e in outcome.errors] == [("not_committable", "none")]
    assert _commits(stack, "demo-wba-1") == ["agreed", "rejected"]


def test_a_retry_same_rejection_keeps_the_commit_pending(stack: Stack) -> None:
    later = {"errors": [{"code": "not_committable", "detail": "busy", "retry": "same"}]}
    _replace(stack, "POST", 503, json.dumps(later).encode())
    assert as_state(Rejected, stack.commit("demo-wba-1", [DISPLAY])).commit_id == 1
    assert _commits(stack, "demo-wba-1") == ["pending"]
    stack.answer = None
    assert as_state(Agreed, stack.commit("demo-wba-1", [DISPLAY])).commit_id == 1
    first, again = (json.loads(r.content) for r in stack.requests if r.method == "POST")
    assert first == again  # re-sent whole, with the same idempotency_key


# The seller's fault modes (TEST ONLY, seller/faults.py)

#: What each mode breaks, per credential. A bearer request is unsigned, so there is no
#: request signature to bind to: unbound and rebound answers are what it should get.
FAULTS: list[tuple[AuthMethod, BreakingFault, str]] = [
    (credential, mode, reason)
    for credential in get_args(AuthMethod)
    for mode, reason in refused_under(credential).items()
]


@pytest.mark.parametrize(("credential", "mode", "reason"), FAULTS)
@pytest.mark.parametrize("on", ["read", "commit"])
def test_each_fault_is_refused(
    tmp_path: Path, credential: AuthMethod, mode: BreakingFault, reason: str, on: str
) -> None:
    proposal_id = "demo-wba-2"
    with Stack(tmp_path, faults=True) as stack:
        stack.fault(mode, "read" if on == "read" else "commit")
        if on == "read":
            outcome = as_state(Refused, stack.read(proposal_id, credential))
        else:
            outcome = as_state(Refused, stack.commit(proposal_id, [CTV], credential))
        assert outcome.code == reason
        assert outcome.authentication_method == credential
        assert _kept_nothing(stack)
        stack.fault("none")
        as_state(Agreed, stack.commit(proposal_id, [CTV], credential))


@pytest.mark.parametrize("mode", sorted(BINDING_FAULTS))
def test_an_answer_to_a_bearer_request_needs_no_binding(
    tmp_path: Path, mode: BreakingFault
) -> None:
    with Stack(tmp_path, faults=True) as stack:
        stack.fault(mode)
        as_state(Agreed, stack.commit("demo-wba-2", [CTV], "bearer"))


# cfbot


def test_the_buyer_signs_for_cfbot_at_its_configured_origin(stack: Stack) -> None:
    check = stack.buyer_control.call(CLOUDFLARE_CHECK, None)
    assert check.status == 200
    assert isinstance(check.verdict, CfbotAccepted) and check.verdict.identity == BUYER
    (sent,) = stack.requests
    assert str(sent.url) == f"{CFBOT}/verify"
    assert f'"{BUYER}' in sent.headers["signature-agent"]


def test_an_answer_from_cfbot_that_is_no_verdict_is_a_bad_gateway(stack: Stack) -> None:
    stack.cfbot = lambda _: httpx.Response(502, content=b"bad gateway")
    with pytest.raises(ControlFailed) as failed:
        stack.buyer_control.call(CLOUDFLARE_CHECK, None)
    assert failed.value.status == 502
    assert failed.value.error is not None and failed.value.error.error == "cfbot-malformed"
    # A verdict in another shape than cfbot's is no verdict either.
    stack.cfbot = lambda _: httpx.Response(200, json={"ok": True})
    with pytest.raises(ControlFailed):
        stack.buyer_control.call(CLOUDFLARE_CHECK, None)
