"""The buyer's settings: the only code on the buyer that reads the environment.

The buyer reads every `AgentSettings` variable (shared/settings.py), and these:

| Variable | Default | What it sets |
|---|---|---|
| `PEER_SELLER_ORIGIN` | `https://seller.wba-demo.noetis.dev` | the seller it deals with |
| `PEER_SELLER_LEGAL_NAME` | `Demo Seller Inc.` | that seller's legal name, as the buyer names it |
| `PEER_CFBOT_ORIGIN` | `https://cfbot.wba-demo.noetis.dev` | Cloudflare's verifier |
| `WBA_ROTATION_WAIT` | `600` | how long a published key waits before it signs |
| `WBA_SIGNATURE_LIFETIME` | `300` | how long its signatures last |

Its database is `buyer.db` in `DATA_DIR`, and its keyring is `KEYS_DIR`.
`plan_file` is its plan, the one this package ships by default; the composition
root reads it once. In
production, the rotation wait is the directory's max-age (300 s) plus the
library's default max_cache_age (300 s), and signatures last the profile's 300 s
maximum (shared/keyring.py).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import ClassVar, Self

from pydantic import SecretStr

from persistence.values import Origin
from protocol.values import Value
from shared import settings as read
from shared.settings import DEFAULT_ORIGINS, AgentSettings, Role

#: The § 3.4 writes the buyer commits for each line item it buys.
PLAN_FILE = Path(__file__).resolve().parent / "plan.yaml"


class Counterparty(Value):
    """A seller this buyer deals with: known by its origin, never by a key.

    The settings are its one source of truth: the buyer reads it from them on
    every boot and stores none of it, so a changed setting takes effect on the
    next start.
    """

    origin: Origin
    domain: str
    legal_name: str
    #: The token the seller issued this buyer, for the bearer flow.
    bearer_token: SecretStr | None = None


@dataclass(frozen=True, kw_only=True)
class BuyerSettings(AgentSettings):
    role: ClassVar[Role] = "buyer"

    peer_seller_origin: Origin = DEFAULT_ORIGINS["seller"]
    peer_seller_legal_name: str = "Demo Seller Inc."
    peer_cfbot_origin: Origin = DEFAULT_ORIGINS["cfbot"]
    rotation_wait: float = 600.0
    signature_lifetime: int = 300
    plan_file: Path = PLAN_FILE

    @property
    def counterparties(self) -> tuple[Counterparty, ...]:
        """The sellers this buyer deals with: the one its settings name. Its domain is its
        origin's host, and its legal name and token, the bearer flow's credential, are the
        settings' own."""
        seller = self.peer_seller_origin
        return (
            Counterparty(
                origin=seller,
                domain=seller.host,
                legal_name=self.peer_seller_legal_name,
                bearer_token=self.bearer_token,
            ),
        )

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
