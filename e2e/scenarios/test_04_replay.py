"""4. The same signed request sent twice: the second one is a replay, refused with 429."""

import httpx
from conftest import SELLER, signed


def test_replayed_request_is_refused(web: httpx.Client) -> None:
    url = f"{SELLER}/proposals/demo-wba-1"
    headers = signed("GET", url)

    first = web.get(url, headers=headers)
    assert first.status_code == 200
    assert first.json()["proposal_id"] == "demo-wba-1"

    again = web.get(url, headers=headers)
    assert again.status_code == 429
    assert again.json()["error"] == "nonce-replayed"
