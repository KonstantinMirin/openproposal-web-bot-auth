"""A number with no RFC 8785 form, through both apps in process (tests/stack.py).

A party digests what it reads (§ 4.1.1), so a body holding `NaN`, `1e400`
(beyond a double), or `2**60` (beyond 2**53) can't be digested. Each party
refuses such a body where it reads it, as a value, never as a 500:

- the seller answers a commit that holds one, signed or bearer, with a § 2.4
  `validation` rejection, and keeps nothing;
- the buyer refuses a correctly signed answer that holds one, to a read or to
  a commit, as `malformed-answer`, and settles nothing.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from persistence.values import AuthMethod
from protocol.operations import parse_errors
from tests.stack import SELLER, TOKEN, Stack, as_state, signed_headers
from transport.control import Refused

DISPLAY = "business-daily-display"
#: Each number as JSON text: NaN, a number beyond a double, an integer beyond 2**53.
NUMBERS = {"nan": "NaN", "beyond-a-double": "1e400", "beyond-2**53": str(2**60)}
#: The proposal the buyer commits to, under either credential.
PROPOSAL = "demo-wba-1"


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    with Stack(tmp_path) as running:
        yield running


def _commit(amount: str, extension: str) -> bytes:
    """A well-formed Commit on DISPLAY, with `amount` and an extension member as JSON text."""
    commit = {
        "entry": {
            "role": "commitment",
            "version": 1,
            "record_digest": "sha256:" + "0" * 64,
            "line_item_ids": [DISPLAY],
            "at": "2029-01-01T00:00:00Z",
            "idempotency_key": str(uuid.uuid4()),
        },
        "writes": {
            DISPLAY: {
                "commitment": {
                    "basis": "spend",
                    "amount": "AMOUNT",
                    "advertisers": [{"domain": "brand-a.example"}],
                    "flight": {"start": "2029-11-02T00:00:00Z", "end": "2029-12-21T23:59:59Z"},
                }
            }
        },
    }
    text = json.dumps(commit).replace('"AMOUNT"', amount)
    return ('{"x_note": ' + extension + ", " + text[1:]).encode()


def _headers(stack: Stack, credential: AuthMethod, url: str, body: bytes) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if credential == "bearer":
        return headers | {"Authorization": f"Bearer {TOKEN}"}
    return signed_headers("POST", url, stack.buyer_keys.active(), body=body)


@pytest.mark.parametrize("place", ["extension", "amount"])
@pytest.mark.parametrize("number", NUMBERS.values(), ids=NUMBERS.keys())
@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
def test_the_seller_rejects_a_commit_that_holds_one_as_validation(
    stack: Stack, credential: AuthMethod, number: str, place: str
) -> None:
    proposal_id = PROPOSAL
    body = _commit(number, "1") if place == "amount" else _commit("1000", number)
    url = f"{SELLER}/proposals/{proposal_id}/commit"
    answer = stack.seller.post(url, content=body, headers=_headers(stack, credential, url, body))
    assert answer.status_code == 400, answer.text
    (error,) = parse_errors(answer.content)
    assert (error.code, error.retry) == ("validation", "none")
    assert "RFC 8785" in error.detail
    with stack.seller_records() as records:
        assert records.entries(proposal_id) == []
        assert records.processed(proposal_id) == []


def _holding(stack: Stack, method: str, number: str) -> None:
    """The seller's own answers to `method` requests, with an extension member that holds
    `number`, then signed again."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        if request.method != method:
            return None
        real = stack.forward(request)
        body = b'{"x_note": ' + number.encode() + b", " + real.content[1:]
        return stack.signed(request, real.status_code, body)

    stack.answer = answer


@pytest.mark.parametrize("number", NUMBERS.values(), ids=NUMBERS.keys())
@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
def test_the_buyer_refuses_a_read_that_holds_one(
    stack: Stack, credential: AuthMethod, number: str
) -> None:
    _holding(stack, "GET", number)
    outcome = as_state(Refused, stack.read(PROPOSAL, credential))
    assert outcome.code == "malformed-answer"
    assert "RFC 8785" in outcome.detail


@pytest.mark.parametrize("number", NUMBERS.values(), ids=NUMBERS.keys())
@pytest.mark.parametrize("credential", ["web_bot_auth", "bearer"])
def test_the_buyer_refuses_a_commit_answer_that_holds_one_and_settles_nothing(
    stack: Stack, credential: AuthMethod, number: str
) -> None:
    proposal_id = PROPOSAL
    _holding(stack, "POST", number)
    outcome = as_state(Refused, stack.commit(proposal_id, [DISPLAY], credential))
    assert outcome.code == "malformed-answer"
    assert stack.commit_states(proposal_id, [DISPLAY]) == ["pending"]
    with stack.buyer_records() as records:
        assert records.messages() == 0
