"""11. The agents' own controls: never routed by the front, and refused without the operator key.

Each agent's `/operator/` (cfbot's `/run/`) routes are its operator's, not
another agent's, so they sit outside the identity boundary. The front answers
`404` for them, and the agent refuses a call inside the network that doesn't
carry its `OPERATOR_KEY`.
"""

import httpx
import pytest
from conftest import BUYER, BUYER_OPERATOR, CFBOT, CFBOT_RUN, SELLER

INSIDE = [
    ("GET", f"{BUYER_OPERATOR}/keys"),
    ("POST", "http://seller:8000/operator/issue"),
    ("POST", f"{CFBOT_RUN}/whoami"),
]


@pytest.mark.parametrize(("method", "url"), INSIDE)
@pytest.mark.parametrize("key", [None, "not-the-operator-key"])
def test_operator_controls_refuse_a_call_without_the_key(method, url, key):
    headers = {"X-Operator-Key": key} if key else {}
    with httpx.Client(timeout=30) as client:  # no operator-key hook
        response = client.request(method, url, headers=headers, json={"principal_id": "buyer-wba"})
    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    "url", [f"{BUYER}/operator/keys", f"{SELLER}/operator/issue", f"{CFBOT}/run/whoami"]
)
def test_the_front_never_routes_operator_controls(web, url):
    assert web.post(url).status_code == 404


def test_the_seller_issues_a_fresh_proposal_with_the_key(web):
    issued = web.post(
        "http://seller:8000/operator/issue", json={"principal_id": "buyer-wba"}
    ).json()
    assert issued["proposal_id"].startswith("live-buyer-wba-")
    read = web.post(f"{BUYER_OPERATOR}/read", json={"proposal_id": issued["proposal_id"]}).json()
    assert read["state"] == "read", read
