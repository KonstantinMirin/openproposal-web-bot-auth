"""10. Key rotation: the buyer adds a key, signs with it, and retires the old one.

The seller follows its cache rules. A request with the new key misses the
cache, so the seller fetches the directory again. The retired key still
verifies while that cached directory is valid (the buyer serves it for 20 s in
this stack). Once it expires, the seller fetches again and refuses the old key.
"""

import json
import time

from conftest import BUYER_KEYS, BUYER_OPERATOR, SELLER, buyer_key, signed

LIFETIME = 20


def _directories_listing(seller_db, kid: str) -> int:
    rows = seller_db.execute("SELECT body FROM directories WHERE url LIKE 'https://buyer.%'")
    return sum(kid in {k["kid"] for k in json.loads(r["body"])["keys"]} for r in rows)


def test_key_rotation(web, seller_db):
    url = f"{SELLER}/whoami"
    old = web.get(f"{BUYER_OPERATOR}/keys").json()["active"]
    old_file = max(p.name for p in BUYER_KEYS.glob("*.jwk"))

    keys = web.post(f"{BUYER_OPERATOR}/keys").json()
    new = keys["active"]
    assert new != old and set(keys["published"]) == {old, new}

    # The buyer signs with the new key; the seller fetches the directory again and accepts it.
    assert _directories_listing(seller_db, new) == 0
    read = web.post(f"{BUYER_OPERATOR}/read", json={"proposal_id": "demo-wba-1"}).json()
    fetched_at = time.time()
    assert read["state"] == "read" and read["detail"].startswith("status 200"), read
    assert read["keyid"] == new
    assert _directories_listing(seller_db, new) == 1
    confirmed = web.get(url, headers=signed("GET", url, key=buyer_key()))
    assert confirmed.status_code == 200 and confirmed.json()["principal"]["id"] == "buyer-wba"

    assert web.delete(f"{BUYER_OPERATOR}/keys/{old}").json()["published"] == [new]

    # The cached directory still lists the old key, so it verifies until that copy expires.
    retired = buyer_key(old_file)
    assert retired.kid == old
    response = web.get(url, headers=signed("GET", url, key=retired))
    assert response.status_code == 200 and response.json()["principal"]["id"] == "buyer-wba"

    time.sleep(max(0.0, fetched_at + LIFETIME + 1 - time.time()))
    refused = web.get(url, headers=signed("GET", url, key=retired))
    assert refused.status_code == 403
    assert refused.json()["reason"] == "key-not-found"

    accepted = web.get(url, headers=signed("GET", url, key=buyer_key()))
    assert accepted.status_code == 200
