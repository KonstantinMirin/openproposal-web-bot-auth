"""7. Cloudflare's verifier accepts the buyer's signature.

The buyer signs a POST to cfbot with the library. cfbot fetches the buyer's
directory, checks its signatures with http-message-sig, and verifies the
request with web-bot-auth's verify().
"""

from conftest import BUYER, buyer_key

from transport.client import ControlClient
from transport.control import CLOUDFLARE_CHECK, CfbotAccepted, DirectorySignature


def test_cloudflare_accepts_the_buyers_signature(buyer_control: ControlClient) -> None:
    check = buyer_control.call(CLOUDFLARE_CHECK, None)
    assert check.status == 200, check
    verdict = check.verdict
    assert isinstance(verdict, CfbotAccepted), verdict
    assert verdict.verifier == "web-bot-auth@0.2.0 verify()"
    assert verdict.identity == BUYER
    assert verdict.keyid == buyer_key().thumbprint
    assert verdict.content_digest_matches is True
    # cfbot verified the directory's own signature by that key before using the key.
    signed_by = DirectorySignature(label="key1", keyid=buyer_key().thumbprint)
    assert signed_by in verdict.directory_signatures
