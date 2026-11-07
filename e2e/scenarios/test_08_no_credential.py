"""8. A commit with no credential is refused, and a bad credential is never treated as none.

The boundary runs before anything parses the body. It reads the body, because
a signature covers it through `Content-Digest`, but it never parses it, so a
failing credential is refused even when the body isn't JSON.
"""

from conftest import SELLER, commit_body, signed


def test_commit_without_a_credential_is_refused(web, seller_records):
    response = web.post(
        f"{SELLER}/proposals/demo-wba-2/commit",
        content=commit_body(160000.0),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 403
    assert response.json()["errors"][0]["code"] == "not_eligible"
    assert seller_records.entries("demo-wba-2") == []


def test_an_invalid_token_is_refused_not_downgraded(web):
    response = web.get(f"{SELLER}/whoami", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid-token"
    assert web.get(f"{SELLER}/whoami").json()["kind"] == "public"  # no credential at all


def test_a_failing_credential_is_refused_before_the_body_is_parsed(web):
    url = f"{SELLER}/proposals/demo-wba-2/commit"
    broken = b"{not json"
    json_type = {"Content-Type": "application/json"}

    by_token = web.post(url, content=broken, headers=json_type | {"Authorization": "Bearer wrong"})
    assert by_token.status_code == 401
    assert by_token.json() | {"detail": ""} == {"error": "invalid-token", "detail": ""}

    by_signature = web.post(
        url, content=broken, headers=json_type | {"Signature-Input": "garbage("}
    )
    assert by_signature.status_code == 400
    assert by_signature.json() | {"detail": ""} == {"error": "parse", "detail": ""}

    # With a credential that verifies, the offer logic parses the body and rejects it.
    rejected = web.post(url, content=broken, headers=signed("POST", url, broken))
    assert rejected.status_code == 400
    assert rejected.json()["errors"][0]["code"] == "validation"
