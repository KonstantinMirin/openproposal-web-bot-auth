"""10. Key rotation, in the standard order, with the seller following its cache rules.

The seller answers from a cached directory for `max_cache_age` without
fetching it again, even for a keyid it doesn't list. So the buyer:

1. publishes the new key next to the old one, and keeps signing with the old key;
2. switches to the new key once no verifier can still be using a copy without
   it (`WBA_ROTATION_WAIT`): the directory's `Cache-Control: max-age` plus
   `max_cache_age`. In this stack the buyer serves `max_age=0`, so that is 0 s
   plus 20 s; in production, 300 s plus 300 s;
3. removes the old key once every signature it made has expired
   (`WBA_SIGNATURE_LIFETIME`, 10 s here).

After the next cache refresh (`WBA_MAX_CACHE_AGE`), the seller refuses the old
key. The timing is the stack's own, which e2e/docker-compose.yml passes to the
runner.
"""

import json
import time

from conftest import BUYER, BUYER_OPERATOR, SELLER, buyer_key, signed
from settings import MAX_CACHE_AGE, ROTATION_WAIT, SIGNATURE_LIFETIME

URL = f"{SELLER}/whoami"


def _until(moment: float) -> None:
    time.sleep(max(0.0, moment - time.time()))


def _read(web) -> dict:
    """The buyer reads its proposal, signed with its active key; the seller must answer 200."""
    read = web.post(f"{BUYER_OPERATOR}/read", json={"proposal_id": "demo-wba-1"}).json()
    assert read["state"] == "read" and read["detail"].startswith("status 200"), read
    return read


def _last_signed_by_buyer(seller_db) -> str:
    """The keyid of the last request the seller verified from the buyer's origin."""
    return seller_db.execute(
        "SELECT keyid FROM signed_requests WHERE origin = ? ORDER BY id DESC LIMIT 1", (BUYER,)
    ).fetchone()["keyid"]


def _directories_listing(seller_db, kid: str) -> int:
    rows = seller_db.execute("SELECT body FROM directories WHERE url LIKE 'https://buyer.%'")
    return sum(kid in {k["kid"] for k in json.loads(r["body"])["keys"]} for r in rows)


def test_key_rotation(web, seller_db):
    old = buyer_key().kid

    # 1. Publish the new key. Requests still go out signed with the old key, and verify.
    keys = web.post(f"{BUYER_OPERATOR}/keys").json()
    published_at = time.time()
    new = keys["published_kid"]
    assert keys["active"] == old and set(keys["published"]) == {old, new}
    assert _read(web)["keyid"] == old
    assert _last_signed_by_buyer(seller_db) == old
    # The switch waits until no verifier can still be serving a directory without it.
    early = web.post(f"{BUYER_OPERATOR}/keys/{new}/activate")
    assert early.status_code == 409, early.text

    # 2. Switch. The seller's copy is now stale, so it fetches the directory that lists the new key.
    _until(published_at + ROTATION_WAIT + 1)
    assert web.post(f"{BUYER_OPERATOR}/keys/{new}/activate").json()["active"] == new
    switched_at = time.time()
    assert _read(web)["keyid"] == new
    assert _last_signed_by_buyer(seller_db) == new
    assert _directories_listing(seller_db, new) >= 1

    # 3. Remove the old key once every signature it made has expired.
    assert web.delete(f"{BUYER_OPERATOR}/keys/{old}").status_code == 409  # too early
    _until(switched_at + SIGNATURE_LIFETIME + 1)
    assert web.delete(f"{BUYER_OPERATOR}/keys/{old}").json()["published"] == [new]

    # After the seller's next refresh, the old key is refused.
    _until(switched_at + MAX_CACHE_AGE + 1)
    retired = buyer_key(old)
    assert retired.kid == old
    refused = web.get(URL, headers=signed("GET", URL, key=retired))
    assert refused.status_code == 403
    assert refused.json()["reason"] == "key-not-found"

    accepted = web.get(URL, headers=signed("GET", URL, key=buyer_key()))
    assert accepted.status_code == 200 and accepted.json()["principal"]["id"] == "buyer-wba"
