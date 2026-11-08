"""The buyer's settings: the only code on the buyer that reads the environment.

The buyer reads every `AgentSettings` variable (shared/settings.py), and these:

| Variable | Default | What it sets |
|---|---|---|
| `PEER_SELLER_ORIGIN` | `https://seller.wba-demo.noetis.dev` | the seller it deals with |
| `PEER_SELLER_LEGAL_NAME` | `Demo Seller Inc.` | that seller's legal name, as the buyer keeps it |
| `PEER_CFBOT_ORIGIN` | `https://cfbot.wba-demo.noetis.dev` | Cloudflare's verifier |
| `WBA_ROTATION_WAIT` | `600` | how long a published key waits before it signs |
| `WBA_SIGNATURE_LIFETIME` | `300` | how long its signatures last |

Its database is `buyer.db` in `DATA_DIR`, and its keyring is `KEYS_DIR`. In
production, the rotation wait is the directory's max-age (300 s) plus the
library's default max_cache_age (300 s), and signatures last the profile's 300 s
maximum (shared/keyring.py).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar, Self

from persistence.values import Origin
from shared import settings as read
from shared.settings import DEFAULT_ORIGINS, AgentSettings, Role


@dataclass(frozen=True, kw_only=True)
class BuyerSettings(AgentSettings):
    role: ClassVar[Role] = "buyer"

    peer_seller_origin: Origin = DEFAULT_ORIGINS["seller"]
    peer_seller_legal_name: str = "Demo Seller Inc."
    peer_cfbot_origin: Origin = DEFAULT_ORIGINS["cfbot"]
    rotation_wait: float = 600.0
    signature_lifetime: int = 300

    @classmethod
    def from_env(cls, env: read.Environment | None = None) -> Self:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value."""
        env = read.environment(env)
        return replace(
            super().from_env(env),
            peer_seller_origin=read.origin(env, "PEER_SELLER_ORIGIN", DEFAULT_ORIGINS["seller"]),
            peer_seller_legal_name=read.text(env, "PEER_SELLER_LEGAL_NAME", "Demo Seller Inc."),
            peer_cfbot_origin=read.origin(env, "PEER_CFBOT_ORIGIN", DEFAULT_ORIGINS["cfbot"]),
            rotation_wait=read.seconds(env, "WBA_ROTATION_WAIT", 600.0),
            signature_lifetime=read.integer(env, "WBA_SIGNATURE_LIFETIME", 300),
        )
