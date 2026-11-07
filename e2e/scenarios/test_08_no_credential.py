"""8. A commit with no credential is refused, and a bad credential is never treated as none."""

from conftest import SELLER, commit_body


def test_commit_without_a_credential_is_refused(web, seller_db):
    response = web.post(f"{SELLER}/proposals/demo-wba-2/commit", content=commit_body(160000.0),
                        headers={"Content-Type": "application/json"})
    assert response.status_code == 403
    assert response.json()["errors"][0]["code"] == "not_eligible"
    assert seller_db.execute(
        "SELECT COUNT(*) FROM assent WHERE proposal_id = 'demo-wba-2'").fetchone()[0] == 0


def test_an_invalid_token_is_refused_not_downgraded(web):
    response = web.get(f"{SELLER}/whoami", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401
    assert response.json()["reason"] == "invalid-token"
    assert web.get(f"{SELLER}/whoami").json()["kind"] == "public"  # no credential at all
