"""6. cfbot, signing with Cloudflare's library: identity established, no principal, refused.

The seller verifies cfbot's signature and learns its origin, but has no
credentials row for it. The boundary returns a `PublicCaller` with the verified
origin, which may neither read the buyer's issued proposal nor commit to it.
"""

from conftest import CFBOT, CFBOT_RUN


def test_cfbot_is_identity_established_only(web, seller_db):
    whoami = web.post(f"{CFBOT_RUN}/whoami").json()
    assert whoami["status"] == 200
    assert whoami["body"]["kind"] == "public"
    credential = whoami["body"]["credential"]
    assert credential["method"] == "web_bot_auth"
    assert credential["origin"] == CFBOT
    assert credential["body_covered"] is False  # a GET has no body to cover

    # The seller kept the verified request, and the directory it verified against.
    evidence = seller_db.execute(
        "SELECT * FROM signed_requests WHERE id = ?", (credential["evidence_id"],)
    ).fetchone()
    assert evidence["origin"] == CFBOT and evidence["directory_digest"] is not None


def test_cfbot_cannot_read_the_issued_proposal(web):
    read = web.post(f"{CFBOT_RUN}/read?proposal_id=demo-wba-1").json()
    assert read["status"] == 404
    assert read["body"]["errors"][0]["code"] == "not_found"


def test_cfbot_cannot_commit(web, seller_db):
    attempt = web.post(f"{CFBOT_RUN}/commit?proposal_id=demo-wba-2").json()
    assert attempt["status"] == 403
    assert attempt["body"]["errors"][0]["code"] == "not_eligible"
    assert (
        seller_db.execute(
            "SELECT COUNT(*) FROM assent WHERE proposal_id = 'demo-wba-2'"
        ).fetchone()[0]
        == 0
    )
