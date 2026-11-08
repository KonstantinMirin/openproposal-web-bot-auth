"""What the scenarios read from their container's environment, read once.

The scenarios observe the stack from inside its network, as the live runner
does, so they read the runner's settings (runner/settings.py): the agents'
origins, their controls, both parties' databases, and each agent's own operator
key. With the same readers (shared/settings.py) they read what only they use:
cfbot's controls and key, the buyer's key directory, the bearer token, and the
timing the agents run with. e2e/docker-compose.yml passes them the values the
agents run with, so no scenario restates a value the stack configures.
"""

from __future__ import annotations

from runner.settings import RunnerSettings
from shared import settings as read

RUNNER = RunnerSettings.from_env()
_ENV = read.environment(None)

SELLER = str(RUNNER.peer_seller_origin)
BUYER = str(RUNNER.peer_buyer_origin)
CFBOT = str(RUNNER.peer_cfbot_origin)

#: Each agent's own controls, inside the network.
SELLER_CONTROL = RUNNER.seller_control
BUYER_CONTROL = RUNNER.buyer_control
CFBOT_CONTROL = read.url(_ENV, "CFBOT_CONTROL", "http://cfbot:8000")
#: What each agent's own controls require (transport/operator.py), one key per party, by
#: the host its controls answer on.
OPERATOR_KEYS = {
    SELLER_CONTROL.host: RUNNER.seller_operator_key,
    BUYER_CONTROL.host: RUNNER.buyer_operator_key,
    CFBOT_CONTROL.host: read.required_secret(_ENV, "CFBOT_OPERATOR_KEY"),
}

#: Both parties' databases, and the buyer's key directory, mounted read-only.
SELLER_DB = RUNNER.seller_db
BUYER_DB = RUNNER.buyer_db
BUYER_KEYS = read.path(_ENV, "BUYER_KEYS_DIR", "/buyer-keys")

#: The token the seller issued its bearer buyer.
BEARER_TOKEN = read.required_secret(_ENV, "DEMO_BEARER_TOKEN").get_secret_value()

# The timing the agents run with, with the agents' own defaults.
#: How long the seller answers from a cached buyer directory (`WBA_MAX_CACHE_AGE`).
MAX_CACHE_AGE = read.integer(_ENV, "WBA_MAX_CACHE_AGE", 300)
#: How long a published buyer key waits before it may sign (`WBA_ROTATION_WAIT`).
ROTATION_WAIT = read.seconds(_ENV, "WBA_ROTATION_WAIT", 600.0)
#: How long the buyer's signatures last (`WBA_SIGNATURE_LIFETIME`).
SIGNATURE_LIFETIME = read.integer(_ENV, "WBA_SIGNATURE_LIFETIME", 300)
