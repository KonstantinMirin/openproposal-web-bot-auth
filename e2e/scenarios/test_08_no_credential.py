"""8. A commit with no credential is refused, and a bad credential is never treated as none.

The boundary runs before anything parses the body. It reads the body, because
a signature covers it through `Content-Digest`, but it never parses it, so a
failing credential is refused even when the body isn't JSON.
"""

import httpx
from conftest import SELLER, commit_body, signed

from persistence.observe import SellerRecords
from protocol.operations import parse_errors
from seller.caller import WHOAMI
from transport.control import ErrorBody


def _codes(response: httpx.Response) -> list[str]:
    return [e.code for e in parse_errors(response.content)]


def _refusal(response: httpx.Response) -> str:
    return ErrorBody.model_validate_json(response.content).code


def test_commit_without_a_credential_is_refused(
    web: httpx.Client, seller_records: SellerRecords
) -> None:
    response = web.post(
        f"{SELLER}/proposals/demo-wba-2/commit",
        content=commit_body(160000.0),
        headers={"Content-Type": "application/json"},
    )
    assert (response.status_code, _codes(response)) == (403, ["not_eligible"])
    assert seller_records.entries("demo-wba-2") == []


def test_an_invalid_token_is_refused_not_downgraded(web: httpx.Client) -> None:
    response = web.get(f"{SELLER}/whoami", headers={"Authorization": "Bearer not-a-token"})
    assert (response.status_code, _refusal(response)) == (401, "invalid-token")
    # No credential at all.
    assert WHOAMI.validate_json(web.get(f"{SELLER}/whoami").content).kind == "public"


def test_a_failing_credential_is_refused_before_the_body_is_parsed(web: httpx.Client) -> None:
    url = f"{SELLER}/proposals/demo-wba-2/commit"
    broken = b"{not json"
    json_type = {"Content-Type": "application/json"}

    by_token = web.post(url, content=broken, headers=json_type | {"Authorization": "Bearer wrong"})
    assert (by_token.status_code, _refusal(by_token)) == (401, "invalid-token")

    by_signature = web.post(
        url, content=broken, headers=json_type | {"Signature-Input": "garbage("}
    )
    assert (by_signature.status_code, _refusal(by_signature)) == (400, "parse")

    # With a credential that verifies, the offer logic parses the body and rejects it.
    rejected = web.post(url, content=broken, headers=signed("POST", url, broken))
    assert (rejected.status_code, _codes(rejected)) == (400, ["validation"])
