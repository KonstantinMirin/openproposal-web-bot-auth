"""6. cfbot, signing with Cloudflare's library: identity established, no principal, refused.

The seller verifies cfbot's signature and learns its origin, but has no
credentials row for it. The boundary returns a `PublicCaller` with the verified
signature, which may neither read the buyer's issued proposal nor commit to it.
The boundary writes nothing, so the seller keeps no evidence for cfbot: evidence
is kept only with an entry it carried.
"""

import json

import httpx
from conftest import CFBOT
from iab_agentic_primitives.web_bot_auth import DIRECTORY_PATH, thumbprint

from persistence.observe import SellerRecords
from persistence.values import Origin
from protocol.operations import parse_errors
from protocol.values import objects, read_json
from seller.caller import WHOAMI, PublicCaller
from transport.client import ControlClient
from transport.control import CFBOT_COMMIT, CFBOT_READ, CFBOT_WHOAMI, CfbotRun, CfbotTrigger


def _codes(run: CfbotRun) -> list[str]:
    """The codes of the seller's § 2.4 `errors[]` answer to cfbot."""
    return [e.code for e in parse_errors(json.dumps(run.body).encode())]


def test_cfbot_is_identity_established_only(
    web: httpx.Client, cfbot_control: ControlClient, seller_records: SellerRecords
) -> None:
    whoami = cfbot_control.call(CFBOT_WHOAMI, None)
    assert whoami.status == 200
    caller = WHOAMI.validate_python(whoami.body)
    assert isinstance(caller, PublicCaller) and caller.signature is not None
    signature = caller.signature
    assert (signature.method, str(signature.origin)) == ("web_bot_auth", CFBOT)
    published = objects(read_json(web.get(f"{CFBOT}{DIRECTORY_PATH}").content).get("keys"))
    assert signature.keyid in {thumbprint(key) for key in published}
    assert signature.body_covered is False  # a GET has no body to cover

    # An origin with no principal writes no row: no request, no directory.
    assert seller_records.requests_from(Origin.parse(CFBOT)) == 0
    assert seller_records.directories_of(Origin.parse(CFBOT)) == 0


def test_cfbot_cannot_read_the_issued_proposal(cfbot_control: ControlClient) -> None:
    read = cfbot_control.call(CFBOT_READ, CfbotTrigger(proposal_id="demo-wba-1"))
    assert (read.status, _codes(read)) == (404, ["not_found"])


def test_cfbot_cannot_commit(cfbot_control: ControlClient, seller_records: SellerRecords) -> None:
    attempt = cfbot_control.call(CFBOT_COMMIT, CfbotTrigger(proposal_id="demo-wba-2"))
    assert (attempt.status, _codes(attempt)) == (403, ["not_eligible"])
    assert seller_records.entries("demo-wba-2") == []
