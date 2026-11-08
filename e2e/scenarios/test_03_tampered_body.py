"""3. A body changed after signing is refused at the boundary, and the handler never runs.

The signature is intact, but `Content-Digest` no longer matches the body. The
library's verifier refuses the request with 403, so the commit handler is
never reached and nothing is written.
"""

import httpx

from e2e.scenarios.stack import SELLER, commit_body, signed
from persistence.observe import SellerRecords
from transport.control import ErrorBody


def test_tampered_body_is_refused_before_the_handler(
    web: httpx.Client, seller_records: SellerRecords
) -> None:
    url = f"{SELLER}/proposals/demo-wba-2/commit"
    body = commit_body(160000.0)
    headers = signed("POST", url, body)
    tampered = body.replace(b"160000.0", b"1.0")

    response = web.post(url, content=tampered, headers=headers)
    assert response.status_code == 403
    assert ErrorBody.model_validate_json(response.content).code == "content-digest"
    assert "signature" in response.headers  # refusals are signed too
    assert "accept-signature" in response.headers

    assert seller_records.entries("demo-wba-2") == []
    assert seller_records.requests_with_body(tampered) == 0
