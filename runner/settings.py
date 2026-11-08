"""The live runner's settings: the only code in the runner that reads the environment.

- `PEER_SELLER_ORIGIN`, `PEER_BUYER_ORIGIN`, `PEER_CFBOT_ORIGIN`: the agents it runs the
  flow against, `https://<name>.wba-demo.noetis.dev` by default.
- `SELLER_CONTROL`, `BUYER_CONTROL`: the agents' own controls inside the network,
  `http://seller:8000` and `http://buyer:8000` by default.
- `SELLER_OPERATOR_KEY`, `BUYER_OPERATOR_KEY`: each agent's own operator key, which
  the runner sends to that agent's controls only. Both are required: without
  either, the runner stops at its settings.
- `DEMO_BEARER_TOKEN`: read only so that no report holds it.
- `SELLER_DB`, `BUYER_DB`: both parties' databases, read-only
  (`/seller-data/seller.db`, `/buyer-data/buyer.db`).
- `OUT_DIR`: where the reports go, `/out` by default.
- `RUN_INTERVAL`: seconds between runs, 900 by default; `0` runs once.
- `SSL_CERT_FILE`: the trust store for directory fetches; the system's roots by default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import SecretStr

from persistence.values import Origin
from shared import settings as read
from shared.settings import DEFAULT_ORIGINS

#: Environment variables whose values must never reach a report.
SECRET_VARIABLES = ("SELLER_OPERATOR_KEY", "BUYER_OPERATOR_KEY", "DEMO_BEARER_TOKEN")
#: Shorter values are not searched for in a report: they would match by chance.
_SHORTEST_SECRET = 8


@dataclass(frozen=True)
class RunnerSettings:
    seller: Origin
    buyer: Origin
    cfbot: Origin
    seller_control: str
    buyer_control: str
    seller_db: str
    buyer_db: str
    out_dir: Path
    interval: float
    #: What the seller's controls require; sent to the seller only.
    seller_operator_key: SecretStr
    #: What the buyer's controls require; sent to the buyer only.
    buyer_operator_key: SecretStr
    ca_bundle: Path | None = None
    #: The values `assert_public` keeps out of every report.
    secrets: tuple[str, ...] = field(default=(), repr=False)

    @classmethod
    def from_env(cls, env: read.Environment | None = None) -> RunnerSettings:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value."""
        env = os.environ if env is None else env
        return cls(
            seller=read.origin(env, "PEER_SELLER_ORIGIN", DEFAULT_ORIGINS["seller"]),
            buyer=read.origin(env, "PEER_BUYER_ORIGIN", DEFAULT_ORIGINS["buyer"]),
            cfbot=read.origin(env, "PEER_CFBOT_ORIGIN", DEFAULT_ORIGINS["cfbot"]),
            seller_control=env.get("SELLER_CONTROL", "http://seller:8000"),
            buyer_control=env.get("BUYER_CONTROL", "http://buyer:8000"),
            seller_db=env.get("SELLER_DB", "/seller-data/seller.db"),
            buyer_db=env.get("BUYER_DB", "/buyer-data/buyer.db"),
            out_dir=read.path(env, "OUT_DIR", "/out"),
            interval=read.seconds(env, "RUN_INTERVAL", 900.0),
            seller_operator_key=read.required_secret(env, "SELLER_OPERATOR_KEY"),
            buyer_operator_key=read.required_secret(env, "BUYER_OPERATOR_KEY"),
            ca_bundle=read.optional_path(env, "SSL_CERT_FILE"),
            secrets=tuple(
                env[name] for name in SECRET_VARIABLES if len(env.get(name, "")) >= _SHORTEST_SECRET
            ),
        )
