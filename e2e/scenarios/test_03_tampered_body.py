"""3. A body changed after signing is refused at the boundary, and the handler never runs.

The signature is intact, but `Content-Digest` no longer matches the body. The
library's verifier refuses the request with 403, so the commit handler is
never reached and nothing is written.
"""

from conftest import SELLER, commit_body, signed


def test_tampered_body_is_refused_before_the_handler(web, seller_db):
    url = f"{SELLER}/proposals/demo-wba-2/commit"
    body = commit_body(160000.0)
    headers = signed("POST", url, body)
    tampered = body.replace(b"160000.0", b"1.0")

    response = web.post(url, content=tampered, headers=headers)
    assert response.status_code == 403
    assert response.json() == {
        "refused_at": "identity-boundary",
        "reason": "content-digest",
        "detail": response.json()["detail"],
    }
    assert "signature" in response.headers  # refusals are signed too
    assert "accept-signature" in response.headers

    assert (
        seller_db.execute(
            "SELECT COUNT(*) FROM assent WHERE proposal_id = 'demo-wba-2'"
        ).fetchone()[0]
        == 0
    )
    assert (
        seller_db.execute(
            "SELECT COUNT(*) FROM signed_requests WHERE body = ?", (tampered,)
        ).fetchone()[0]
        == 0
    )
