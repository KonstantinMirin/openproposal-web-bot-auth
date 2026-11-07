"""The live runner's settings: the only code in the runner that reads the environment.

- `PEER_SELLER_ORIGIN`, `PEER_BUYER_ORIGIN`, `PEER_CFBOT_ORIGIN`: the agents it runs the
  flow against, `https://<name>.wba-demo.noetis.dev` by default.
- `SELLER_CONTROL`, `BUYER_CONTROL`: the agents' own controls inside the network,
  `http://seller:8000` and `http://buyer:8000` by default.
- `OPERATOR_KEY`: what the controls require. Without it the runner refuses to start.
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

from iab_agentic_primitives.web_bot_auth import Origin
from pydantic import SecretStr

from shared import settings as read

#: Environment variables whose values must never reach a report.
SECRET_VARIABLES = ("OPERATOR_KEY", "DEMO_BEARER_TOKEN")
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
    ca_bundle: Path | None = None
    operator_key: SecretStr | None = None
    #: The values `assert_public` keeps out of every report.
    secrets: tuple[str, ...] = field(default=(), repr=False)

    @classmethod
    def from_env(cls, env: read.Environment | None = None) -> RunnerSettings:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value."""
        env = os.environ if env is None else env
        return cls(
            seller=read.origin(env, "PEER_SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev"),
            buyer=read.origin(env, "PEER_BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev"),
            cfbot=read.origin(env, "PEER_CFBOT_ORIGIN", "https://cfbot.wba-demo.noetis.dev"),
            seller_control=env.get("SELLER_CONTROL", "http://seller:8000"),
            buyer_control=env.get("BUYER_CONTROL", "http://buyer:8000"),
            seller_db=env.get("SELLER_DB", "/seller-data/seller.db"),
            buyer_db=env.get("BUYER_DB", "/buyer-data/buyer.db"),
            out_dir=read.path(env, "OUT_DIR", "/out"),
            interval=read.seconds(env, "RUN_INTERVAL", 900.0),
            ca_bundle=read.optional_path(env, "SSL_CERT_FILE"),
            operator_key=read.secret(env, "OPERATOR_KEY"),
            secrets=tuple(
                env[name] for name in SECRET_VARIABLES if len(env.get(name, "")) >= _SHORTEST_SECRET
            ),
        )
