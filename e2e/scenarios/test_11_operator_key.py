"""11. The agents' own controls: never routed by the front, and refused without the party's key.

Each agent's `/operator/` (cfbot's `/run/`) routes are its operator's, not
another agent's, so they sit outside the identity boundary. The front, Caddy
serving the production snippet (deploy/Caddyfile.snippet), answers `404` for
them and for the seller's test-only `/test/`, and the agent refuses a call
inside the network that doesn't carry its own `OPERATOR_KEY`. Each party has a
key of its own, so one party's key is refused at another.
"""

import httpx
import pytest
from conftest import BUYER, BUYER_OPERATOR, CFBOT, CFBOT_RUN, SELLER, SELLER_OPERATOR
from settings import BUYER_CONTROL, OPERATOR_KEYS, SELLER_CONTROL

from transport.control import OPERATOR_HEADER

#: Each party's controls, and another party, whose key they must refuse.
INSIDE = [
    ("GET", f"{BUYER_OPERATOR}/keys", SELLER_CONTROL.host),
    ("POST", f"{SELLER_OPERATOR}/issue", BUYER_CONTROL.host),
    ("POST", f"{CFBOT_RUN}/whoami", BUYER_CONTROL.host),
]


@pytest.mark.parametrize(("method", "url", "other"), INSIDE)
@pytest.mark.parametrize("key", ["none", "a wrong key", "another party's key"])
def test_operator_controls_refuse_a_call_without_the_partys_key(
    method: str, url: str, other: str, key: str
) -> None:
    sent = {"none": None, "a wrong key": "not-the-operator-key"}.get(key, OPERATOR_KEYS[other])
    headers = {} if sent is None else {OPERATOR_HEADER: sent}
    with httpx.Client(timeout=30) as client:  # no operator-key hook
        response = client.request(method, url, headers=headers, json={"principal_id": "buyer-wba"})
    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    "url",
    [
        f"{BUYER}/operator/keys",
        f"{SELLER}/operator/issue",
        f"{SELLER}/test/fault",
        f"{CFBOT}/run/whoami",
    ],
)
def test_the_front_never_routes_operator_controls(web: httpx.Client, url: str) -> None:
    assert web.post(url).status_code == 404


def test_the_seller_issues_a_fresh_proposal_with_the_key(web: httpx.Client) -> None:
    issued = web.post(f"{SELLER_OPERATOR}/issue", json={"principal_id": "buyer-wba"}).json()
    assert issued["proposal_id"].startswith("live-buyer-wba-")
    read = web.post(f"{BUYER_OPERATOR}/read", json={"proposal_id": issued["proposal_id"]}).json()
    assert read["state"] == "read", read
