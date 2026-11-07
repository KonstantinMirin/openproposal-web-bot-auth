"""5. A valid origin with a key its directory doesn't list: refused with 403.

The request names the buyer's origin, but its key isn't in the buyer's
directory. The seller fetches the directory, finds no such key, and refuses.
"""

from conftest import SELLER, signed
from iab_agentic_primitives.web_bot_auth import Ed25519Key


def test_key_not_in_the_directory_is_refused(web):
    url = f"{SELLER}/proposals/demo-wba-1"
    response = web.get(url, headers=signed("GET", url, key=Ed25519Key.generate()))
    assert response.status_code == 403
    assert response.json()["reason"] == "key-not-found"
