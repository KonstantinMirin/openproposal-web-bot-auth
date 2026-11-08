"""10. Key rotation, in the standard order, with the seller following its cache rules.

The seller answers from a cached directory for `max_cache_age` without
fetching it again, even for a keyid it doesn't list. So the buyer:

1. publishes the new key next to the old one, and keeps signing with the old key;
2. switches to the new key once no verifier can still be using a copy without
   it: the directory's `Cache-Control: max-age` plus the profile's 300 s, which
   the buyer derives from its max-age (shared/keyring.py). In this stack the
   buyer serves `max_age=0`, so that is 0 s plus 300 s; in production, 300 s
   plus 300 s;
3. removes the old key once every signature it made has expired
   (`WBA_SIGNATURE_LIFETIME`, 10 s here).

After the next cache refresh (`WBA_MAX_CACHE_AGE`), the seller refuses the old
key. The timing is the stack's own, which e2e/docker-compose.yml passes to the
scenarios service.
"""

import time

import httpx
import pytest

from e2e.scenarios.stack import (
    BUYER,
    MAX_CACHE_AGE,
    ROTATION_WAIT,
    SELLER,
    SIGNATURE_LIFETIME,
    buyer_key,
    signed,
)
from seller.caller import WHOAMI, ResolvedView, SignatureCredential
from transport.client import ControlClient, ControlFailed
from transport.control import ACTIVATE, PUBLISH, READ, RETIRE, ErrorBody, Read, ReadTrigger

URL = f"{SELLER}/whoami"


def _until(moment: float) -> None:
    time.sleep(max(0.0, moment - time.time()))


def _read(buyer_control: ControlClient) -> Read:
    """The buyer reads its proposal, signed with its active key; the seller must answer 200."""
    read = buyer_control.call(READ, ReadTrigger(proposal_id="demo-wba-1"))
    assert isinstance(read, Read), read
    return read


def _resolved(web: httpx.Client, kid: str) -> ResolvedView:
    """What the seller resolved for a request signed with the buyer's key `kid`."""
    whoami = web.get(URL, headers=signed("GET", URL, key=buyer_key(kid)))
    assert whoami.status_code == 200, whoami.text
    caller = WHOAMI.validate_json(whoami.content)
    assert isinstance(caller, ResolvedView), caller
    return caller


def _verified_keyid(web: httpx.Client, kid: str) -> str:
    """The keyid the seller verified for a request signed with the buyer's key `kid`.

    The seller keeps no evidence for a read, so `/whoami` is where it says which key it
    verified: it can only verify `kid` from a directory that lists it.
    """
    credential = _resolved(web, kid).credential
    assert isinstance(credential, SignatureCredential), credential
    assert str(credential.origin) == BUYER
    return credential.keyid


def _too_early(buyer_control: ControlClient, step: str, kid: str) -> int:
    """The status the rotation step `step` on `kid` answers, which must refuse."""
    with pytest.raises(ControlFailed) as failed:
        buyer_control.call(ACTIVATE if step == "activate" else RETIRE, None, kid=kid)
    return failed.value.status


def test_key_rotation(web: httpx.Client, buyer_control: ControlClient) -> None:
    old = buyer_key().thumbprint

    # 1. Publish the new key. Requests still go out signed with the old key, and verify.
    keys = buyer_control.call(PUBLISH, None)
    published_at = time.time()
    new = keys.published_kid
    assert keys.active == old and set(keys.published) == {old, new}
    assert _read(buyer_control).keyid == old
    assert _verified_keyid(web, old) == old
    # The switch waits until no verifier can still be serving a directory without it.
    assert _too_early(buyer_control, "activate", new) == 409

    # 2. Switch. The seller's copy is now stale, so it fetches the directory that lists the new key.
    _until(published_at + ROTATION_WAIT + 1)
    assert buyer_control.call(ACTIVATE, None, kid=new).active == new
    switched_at = time.time()
    assert _read(buyer_control).keyid == new
    assert _verified_keyid(web, new) == new

    # 3. Remove the old key once every signature it made has expired.
    assert _too_early(buyer_control, "retire", old) == 409
    _until(switched_at + SIGNATURE_LIFETIME + 1)
    assert buyer_control.call(RETIRE, None, kid=old).published == [new]

    # After the seller's next refresh, the old key is refused.
    _until(switched_at + MAX_CACHE_AGE + 1)
    retired = buyer_key(old)
    assert retired.thumbprint == old
    refused = web.get(URL, headers=signed("GET", URL, key=retired))
    assert refused.status_code == 403
    assert ErrorBody.model_validate_json(refused.content).code == "key-not-found"

    assert _resolved(web, new).principal.id == "buyer-wba"
