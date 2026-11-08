"""6. cfbot, signing with Cloudflare's library: identity established, no principal, refused.

The seller verifies cfbot's signature and learns its origin, but has no
credentials row for it. The boundary returns a `PublicCaller` with the verified
signature, which may neither read the buyer's issued proposal nor commit to it.
The boundary writes nothing, so the seller keeps no evidence for cfbot: evidence
is kept only with an entry it carried.
"""

import httpx
from conftest import CFBOT, CFBOT_RUN
from iab_agentic_primitives.web_bot_auth import DIRECTORY_PATH, Origin, thumbprint

from persistence.observe import SellerRecords


def test_cfbot_is_identity_established_only(
    web: httpx.Client, seller_records: SellerRecords
) -> None:
    whoami = web.post(f"{CFBOT_RUN}/whoami").json()
    assert whoami["status"] == 200
    assert whoami["body"]["kind"] == "public"
    signature = whoami["body"]["signature"]
    assert signature["method"] == "web_bot_auth"
    assert signature["origin"] == CFBOT
    published = web.get(f"{CFBOT}{DIRECTORY_PATH}").json()["keys"]
    assert signature["keyid"] in {thumbprint(key) for key in published}
    assert signature["body_covered"] is False  # a GET has no body to cover

    # An origin with no principal writes no row: no request, no directory.
    assert seller_records.requests_from(Origin.parse(CFBOT)) == 0
    assert seller_records.directories_of(Origin.parse(CFBOT)) == 0


def test_cfbot_cannot_read_the_issued_proposal(web: httpx.Client) -> None:
    read = web.post(f"{CFBOT_RUN}/read?proposal_id=demo-wba-1").json()
    assert read["status"] == 404
    assert read["body"]["errors"][0]["code"] == "not_found"


def test_cfbot_cannot_commit(web: httpx.Client, seller_records: SellerRecords) -> None:
    attempt = web.post(f"{CFBOT_RUN}/commit?proposal_id=demo-wba-2").json()
    assert attempt["status"] == 403
    assert attempt["body"]["errors"][0]["code"] == "not_eligible"
    assert seller_records.entries("demo-wba-2") == []
