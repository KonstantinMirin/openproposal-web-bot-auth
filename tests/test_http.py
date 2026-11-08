"""Both agents' HTTP seams: a status for every error code, and two error body forms only.

- `status_for` is total over `ErrorObjectCode`. Each core code gets § 2.4's informative status, an
  extension code acts on `retry`, and a code that is neither can't be built.
- Through both apps (tests/stack.py): every route answers a request that
  fails, for a missing operator key, a method or path it doesn't serve, a body
  it refuses, a domain error, a refused credential, or a failure nothing
  handles, with a body that is either a § 2.4 `{"errors": [...]}` or an
  `ErrorBody` (`{"error", "detail"}`), and a 500 holds no traceback.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_args

import httpx
import pytest
from openproposal import ErrorObject, ErrorObjectCode
from pydantic import ValidationError

from protocol.operations import parse_errors
from seller.http import status_for
from seller.seed import BUYER
from tests.stack import BUYER_OPERATOR, SELLER_OPERATOR, TOKEN, Stack
from transport.control import (
    ACTIVATE,
    CLOUDFLARE_CHECK,
    COMMIT,
    FAULT,
    HEALTH,
    ISSUE,
    KEYS,
    READ,
    RETIRE,
    ErrorBody,
)

#: § 2.4, informative: the status each core code fits over HTTP.
SPEC_STATUS = {
    "validation": 400,
    "not_offered": 400,
    "unresolved_reference": 400,
    "not_eligible": 403,
    "not_found": 404,
    "not_committable": 409,
    "stale_version": 409,
    "record_mismatch": 409,
    "expired": 410,
    "idempotency_conflict": 422,
}
CORE = get_args(get_args(ErrorObjectCode.__value__)[0])


def _error(code: str, retry: str = "none") -> ErrorObject:
    return ErrorObject.model_validate({"code": code, "detail": "d", "retry": retry})


def test_every_core_code_gets_its_spec_status_and_retry_same_fits_503() -> None:
    """The § 2.4 table: the SDK's core codes are the spec's, and each maps to its status."""
    assert set(CORE) == set(SPEC_STATUS)
    assert {code: status_for(_error(code)) for code in CORE} == SPEC_STATUS
    assert {status_for(_error(code, "same")) for code in CORE} == {503}


def test_an_extension_code_acts_on_retry() -> None:
    """A code § 2.4 doesn't list still gets a status, from its `retry`."""
    assert status_for(_error("seller.example.com:inventory-hold")) == 400
    assert status_for(_error("seller.example.com:inventory-hold", "same")) == 503


def test_a_code_that_is_neither_core_nor_namespaced_cannot_be_built() -> None:
    with pytest.raises(ValidationError):
        _error("bogus")


# Every failing answer, from every route of both apps


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    with Stack(tmp_path, faults=True) as running:
        yield running


def _drop(table: str, database: Callable[[Stack], Path]) -> Callable[[Stack], None]:
    """Injects a failure nothing handles: a table the agent reads is gone."""

    def drop(stack: Stack) -> None:
        db = sqlite3.connect(database(stack))
        try:
            db.execute(f"DROP TABLE {table}")
            db.commit()
        finally:
            db.close()

    return drop


def _seller_db(stack: Stack) -> Path:
    return stack.seller_dir / "seller.db"


def _cfbot_down(stack: Stack) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        refused = "connection refused"
        raise httpx.ConnectError(refused, request=request)

    stack.cfbot = down


def _cfbot_breaks(stack: Stack) -> None:
    """Injects a failure nothing handles: the call to cfbot raises a non-HTTP error."""

    def broken(_request: httpx.Request) -> httpx.Response:
        message = "the transport broke"
        raise RuntimeError(message)

    stack.cfbot = broken


def _settled_meanwhile(stack: Stack) -> None:
    """Another trigger settles the commit while this one waits for the seller's answer."""

    def answer(request: httpx.Request) -> httpx.Response | None:
        if request.method != "POST":
            return None
        db = sqlite3.connect(stack.buyer_dir / "buyer.db")
        try:
            db.execute("UPDATE commits SET state = 'rejected'")
            db.commit()
        finally:
            db.close()
        return stack.forward(request)

    stack.answer = answer


@dataclass(frozen=True)
class Failing:
    """A request one app's route fails, and the status and code it answers."""

    name: str
    app: str
    method: str
    path: str
    status: int
    code: str
    body: dict[str, object] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    #: Changes the stack before the request: an injected failure.
    before: Callable[[Stack], None] | None = None


TRIGGER: dict[str, object] = {
    "proposal_id": "demo-wba-1",
    "line_item_ids": ["business-daily-display"],
}
SIGNATURE_GARBAGE = {"Signature-Input": "garbage(", "Signature": "sig1=:AAAA:"}

FAILING = [
    # The seller's agent-facing routes
    Failing("proposal not issued", "seller", "GET", "/proposals/demo-wba-1", 404, "not_found"),
    Failing(
        "proposal wrong method", "seller", "PUT", "/proposals/demo-wba-1", 405, "method-not-allowed"
    ),
    Failing(
        "proposal bad token",
        "seller",
        "GET",
        "/proposals/demo-wba-1",
        401,
        "invalid-token",
        headers={"Authorization": "Bearer wrong"},
    ),
    Failing(
        "proposal store fails",
        "seller",
        "GET",
        "/proposals/demo-wba-1",
        500,
        "internal",
        headers={"Authorization": f"Bearer {TOKEN}"},
        before=_drop("proposals", _seller_db),
    ),
    Failing(
        "commit not a Commit",
        "seller",
        "POST",
        "/proposals/demo-wba-1/commit",
        400,
        "validation",
        body={},
    ),
    Failing(
        "commit bad signature",
        "seller",
        "POST",
        "/proposals/demo-wba-1/commit",
        400,
        "parse",
        body={},
        headers=SIGNATURE_GARBAGE,
    ),
    Failing(
        "commit wrong method",
        "seller",
        "GET",
        "/proposals/demo-wba-1/commit",
        405,
        "method-not-allowed",
    ),
    Failing(
        "whoami bad authorization",
        "seller",
        "GET",
        "/whoami",
        401,
        "invalid-authorization",
        headers={"Authorization": "Basic x"},
    ),
    Failing("whoami wrong method", "seller", "PUT", "/whoami", 405, "method-not-allowed"),
    Failing("seller health wrong method", "seller", "POST", HEALTH.path, 405, "method-not-allowed"),
    Failing("seller unknown path", "seller", "GET", "/no-such-route", 404, "not-found"),
    # The seller's controls
    Failing(
        "issue no key",
        "seller",
        "POST",
        ISSUE.path,
        403,
        "operator-key",
        body={"principal_id": BUYER},
    ),
    Failing(
        "issue wrong method",
        "seller",
        "GET",
        ISSUE.path,
        405,
        "method-not-allowed",
        headers=SELLER_OPERATOR,
    ),
    Failing(
        "issue invalid body",
        "seller",
        "POST",
        ISSUE.path,
        422,
        "validation",
        body={"principal": BUYER},
        headers=SELLER_OPERATOR,
    ),
    Failing(
        "issue unknown principal",
        "seller",
        "POST",
        ISSUE.path,
        404,
        "unknown-principal",
        body={"principal_id": "nobody"},
        headers=SELLER_OPERATOR,
    ),
    Failing(
        "issue store fails",
        "seller",
        "POST",
        ISSUE.path,
        500,
        "internal",
        body={"principal_id": BUYER},
        headers=SELLER_OPERATOR,
        before=_drop("proposals", _seller_db),
    ),
    Failing(
        "seller unknown control",
        "seller",
        "GET",
        "/operator/no-such-control",
        404,
        "not-found",
        headers=SELLER_OPERATOR,
    ),
    Failing(
        "fault invalid body",
        "seller",
        "PUT",
        FAULT.path,
        422,
        "validation",
        body={"mode": "bogus"},
    ),
    Failing("fault wrong method", "seller", "GET", FAULT.path, 405, "method-not-allowed"),
    # The buyer's routes
    Failing("buyer health wrong method", "buyer", "POST", HEALTH.path, 405, "method-not-allowed"),
    Failing("buyer unknown path", "buyer", "GET", "/no-such-route", 404, "not-found"),
    Failing(
        "buyer unknown control",
        "buyer",
        "GET",
        "/operator/no-such-control",
        404,
        "not-found",
        headers=BUYER_OPERATOR,
    ),
    # The buyer's controls
    Failing(
        "read no key",
        "buyer",
        "POST",
        READ.path,
        403,
        "operator-key",
        body={"proposal_id": "demo-wba-1"},
    ),
    Failing(
        "read wrong method",
        "buyer",
        "GET",
        READ.path,
        405,
        "method-not-allowed",
        headers=BUYER_OPERATOR,
    ),
    Failing(
        "read invalid body",
        "buyer",
        "POST",
        READ.path,
        422,
        "validation",
        body={},
        headers=BUYER_OPERATOR,
    ),
    Failing(
        "commit trigger no key",
        "buyer",
        "POST",
        COMMIT.path,
        403,
        "operator-key",
        body=TRIGGER,
    ),
    Failing(
        "commit trigger invalid body",
        "buyer",
        "POST",
        COMMIT.path,
        422,
        "validation",
        body={"proposal_id": "x"},
        headers=BUYER_OPERATOR,
    ),
    Failing(
        "commit trigger settled meanwhile",
        "buyer",
        "POST",
        COMMIT.path,
        409,
        "not-pending",
        body=TRIGGER,
        headers=BUYER_OPERATOR,
        before=_settled_meanwhile,
    ),
    Failing("keys no key", "buyer", "GET", KEYS.path, 403, "operator-key"),
    Failing(
        "keys wrong method",
        "buyer",
        "PUT",
        KEYS.path,
        405,
        "method-not-allowed",
        headers=BUYER_OPERATOR,
    ),
    Failing("publish no key", "buyer", "POST", KEYS.path, 403, "operator-key"),
    Failing("activate no key", "buyer", "POST", ACTIVATE.url(kid="kid"), 403, "operator-key"),
    Failing(
        "activate out of order",
        "buyer",
        "POST",
        ACTIVATE.url(kid="no-such-kid"),
        409,
        "rotation",
        headers=BUYER_OPERATOR,
    ),
    Failing("retire no key", "buyer", "DELETE", RETIRE.url(kid="kid"), 403, "operator-key"),
    Failing(
        "retire out of order",
        "buyer",
        "DELETE",
        RETIRE.url(kid="no-such-kid"),
        409,
        "rotation",
        headers=BUYER_OPERATOR,
    ),
    Failing(
        "cloudflare-check no key",
        "buyer",
        "POST",
        CLOUDFLARE_CHECK.path,
        403,
        "operator-key",
    ),
    Failing(
        "cloudflare-check cfbot down",
        "buyer",
        "POST",
        CLOUDFLARE_CHECK.path,
        502,
        "cfbot-unreachable",
        headers=BUYER_OPERATOR,
        before=_cfbot_down,
    ),
    Failing(
        "cloudflare-check breaks",
        "buyer",
        "POST",
        CLOUDFLARE_CHECK.path,
        500,
        "internal",
        headers=BUYER_OPERATOR,
        before=_cfbot_breaks,
    ),
]


def _code(response: httpx.Response) -> str:
    """The code of a failing answer, read as one of the two forms; neither fails the test."""
    try:
        return ErrorBody.model_validate_json(response.content).code
    except ValidationError:
        (error,) = parse_errors(response.content)
        return error.code


@pytest.mark.parametrize("row", FAILING, ids=lambda row: row.name)
def test_every_failing_answer_is_an_error_body_or_the_errors_envelope(
    stack: Stack, row: Failing
) -> None:
    if row.before is not None:
        row.before(stack)
    app = stack.seller if row.app == "seller" else stack.buyer
    response = app.request(row.method, row.path, json=row.body, headers=row.headers)
    assert (response.status_code, _code(response)) == (row.status, row.code), response.text
    assert "Traceback" not in response.text
