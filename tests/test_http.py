"""The seller's rendering seam: a status for every error code, and two error body forms.

- `status_for` is total over `ErrorObjectCode`. Each core code gets § 2.4's informative status, an
  extension code acts on `retry`, and a code that is neither can't be built.
- Through the app: a § 2.4 rejection is `{"errors": [...]}`; a control-plane
  failure (the operator key, an unknown principal, a control route's
  validation error, a route the seller doesn't have) is `{"error", "detail"}`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import get_args

import pytest
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import MemoryNonceStore, Origin, StaticKeyResolver
from openproposal import ErrorObject, ErrorObjectCode
from pydantic import SecretStr, ValidationError

from seller.app import create_app
from seller.http import status_for
from seller.settings import SellerSettings

SELLER = "https://seller.example.com"
OPERATOR = {"X-Operator-Key": "operator-key-for-tests"}
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


@pytest.fixture
def seller(tmp_path: Path) -> Iterator[TestClient]:
    settings = SellerSettings(
        self_origin=Origin.parse(SELLER),
        peer_buyer_origin=Origin.parse("https://buyer.example.com"),
        data_dir=tmp_path,
        operator_key=SecretStr(OPERATOR["X-Operator-Key"]),
    )
    app = create_app(settings, nonces=MemoryNonceStore(), resolver=StaticKeyResolver({}))
    with TestClient(app, base_url=SELLER) as client:
        yield client


@dataclass(frozen=True)
class ControlCall:
    name: str
    method: str
    path: str
    body: dict[str, str] | None
    headers: dict[str, str]
    status: int
    error: str


CONTROL_CALLS = [
    ControlCall(
        "no operator key",
        "POST",
        "/operator/issue",
        {"principal_id": "buyer-wba"},
        {},
        403,
        "operator-key",
    ),
    ControlCall(
        "unknown principal",
        "POST",
        "/operator/issue",
        {"principal_id": "nobody"},
        OPERATOR,
        404,
        "unknown-principal",
    ),
    ControlCall(
        "a control route's bad body",
        "POST",
        "/operator/issue",
        {"principal": "buyer-wba"},
        OPERATOR,
        422,
        "validation",
    ),
    ControlCall("no route", "GET", "/no-such-route", None, {}, 404, "not-found"),
    ControlCall("no method", "PUT", "/whoami", None, {}, 405, "method-not-allowed"),
]


@pytest.mark.parametrize("call", CONTROL_CALLS, ids=lambda call: call.name)
def test_a_control_plane_failure_is_error_and_detail(seller: TestClient, call: ControlCall) -> None:
    response = seller.request(call.method, call.path, json=call.body, headers=call.headers)
    assert response.status_code == call.status
    assert response.json().keys() == {"error", "detail"}
    assert response.json()["error"] == call.error


def test_an_offer_rejection_is_errors(seller: TestClient) -> None:
    response = seller.get("/proposals/demo-wba-1")  # no credential: not issued to this caller
    assert response.status_code == 404
    assert response.json() == {
        "errors": [
            {"code": "not_found", "detail": response.json()["errors"][0]["detail"], "retry": "none"}
        ]
    }
