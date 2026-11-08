"""What the scenarios read from the runner container's environment, read once.

e2e/docker-compose.yml passes the runner the same origins, secrets, and timing
the agents run with, so no scenario restates a value the stack configures.
"""

from __future__ import annotations

import os

SELLER = os.environ.get("PEER_SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev")
BUYER = os.environ.get("PEER_BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev")
CFBOT = os.environ.get("PEER_CFBOT_ORIGIN", "https://cfbot.wba-demo.noetis.dev")

#: What each agent's own controls require (transport/operator.py), one key per party, by
#: the host its controls answer on inside the network.
OPERATOR_KEYS = {
    "seller": os.environ["SELLER_OPERATOR_KEY"],
    "buyer": os.environ["BUYER_OPERATOR_KEY"],
    "cfbot": os.environ["CFBOT_OPERATOR_KEY"],
}
#: The token the seller issued its bearer buyer.
BEARER_TOKEN = os.environ["DEMO_BEARER_TOKEN"]

#: How long the seller answers from a cached buyer directory (`WBA_MAX_CACHE_AGE`).
MAX_CACHE_AGE = int(os.environ["WBA_MAX_CACHE_AGE"])
#: How long a published buyer key waits before it may sign (`WBA_ROTATION_WAIT`).
ROTATION_WAIT = float(os.environ["WBA_ROTATION_WAIT"])
#: How long the buyer's signatures last (`WBA_SIGNATURE_LIFETIME`).
SIGNATURE_LIFETIME = int(os.environ["WBA_SIGNATURE_LIFETIME"])
