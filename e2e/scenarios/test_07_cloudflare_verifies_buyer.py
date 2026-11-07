"""7. Cloudflare's verifier accepts the buyer's signature.

The buyer signs a POST to cfbot with the library. cfbot fetches the buyer's
directory, checks its signatures with http-message-sig, and verifies the
request with web-bot-auth's verify().
"""

from conftest import BUYER, BUYER_OPERATOR, buyer_key


def test_cloudflare_accepts_the_buyers_signature(web):
    check = web.post(f"{BUYER_OPERATOR}/cloudflare-check").json()
    assert check["status"] == 200, check
    verdict = check["verdict"]
    assert verdict["ok"] is True
    assert verdict["verifier"] == "web-bot-auth@0.2.0 verify()"
    assert verdict["identity"] == BUYER
    assert verdict["keyid"] == buyer_key().kid
    assert verdict["content_digest_matches"] is True
    # cfbot verified the directory's own signature by that key before using the key.
    assert {"label": "key1", "keyid": buyer_key().kid} in verdict["directory_signatures"]
