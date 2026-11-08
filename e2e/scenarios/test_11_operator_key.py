"""11. The agents' own controls: never routed by the front, and refused without the party's key.

Each agent's `/operator/` (cfbot's `/run/`) routes are its operator's, not
another agent's, so they sit outside the identity boundary. The front, Caddy
serving the production snippet (deploy/Caddyfile.snippet), answers `404` for
them and for the seller's test-only `/test/`, and the agent refuses a call
inside the network that doesn't carry its own `OPERATOR_KEY`. Each party has a
key of its own, so one party's key is refused at another.
"""

from collections.abc import Callable

import httpx
import pytest
from conftest import BUYER, CFBOT, SELLER
from pydantic import SecretStr
from settings import BUYER_CONTROL, CFBOT_CONTROL, OPERATOR_KEYS, SELLER_CONTROL

from transport.client import ControlClient, ControlFailed
from transport.control import (
    CFBOT_WHOAMI,
    FAULT,
    ISSUE,
    KEYS,
    READ,
    ErrorBody,
    IssueRequest,
    Read,
    ReadTrigger,
)

#: Each party's controls, one call to them, and another party, whose key they must refuse.
INSIDE: list[tuple[str, httpx.URL, Callable[[ControlClient], object], httpx.URL]] = [
    ("buyer keys", BUYER_CONTROL, lambda c: c.call(KEYS, None), SELLER_CONTROL),
    (
        "seller issue",
        SELLER_CONTROL,
        lambda c: c.call(ISSUE, IssueRequest(principal_id="buyer-wba")),
        BUYER_CONTROL,
    ),
    ("cfbot whoami", CFBOT_CONTROL, lambda c: c.call(CFBOT_WHOAMI, None), BUYER_CONTROL),
]
KEYS_SENT = {"none": None, "a wrong key": SecretStr("not-the-operator-key")}


@pytest.mark.parametrize(("name", "base", "call", "other"), INSIDE, ids=[r[0] for r in INSIDE])
@pytest.mark.parametrize("key", ["none", "a wrong key", "another party's key"])
def test_operator_controls_refuse_a_call_without_the_partys_key(
    name: str,
    base: httpx.URL,
    call: Callable[[ControlClient], object],
    other: httpx.URL,
    key: str,
) -> None:
    del name
    sent = KEYS_SENT.get(key, OPERATOR_KEYS[other.host])
    with httpx.Client(timeout=30) as client, pytest.raises(ControlFailed) as failed:
        call(ControlClient(client, base, sent))
    assert failed.value.status == 403, failed.value
    assert failed.value.error == ErrorBody(error="operator-key", detail="operator key required")


@pytest.mark.parametrize(
    "url",
    [
        f"{BUYER}{KEYS.path}",
        f"{SELLER}{ISSUE.path}",
        f"{SELLER}{FAULT.path}",
        f"{CFBOT}{CFBOT_WHOAMI.path}",
    ],
)
def test_the_front_never_routes_operator_controls(web: httpx.Client, url: str) -> None:
    assert web.post(url).status_code == 404


def test_the_seller_issues_a_fresh_proposal_with_the_key(
    seller_control: ControlClient, buyer_control: ControlClient
) -> None:
    issued = seller_control.call(ISSUE, IssueRequest(principal_id="buyer-wba"))
    assert issued.proposal_id.startswith("live-buyer-wba-")
    read = buyer_control.call(READ, ReadTrigger(proposal_id=issued.proposal_id))
    assert isinstance(read, Read), read
