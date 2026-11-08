"""The buyer's settings: the only code on the buyer that reads the environment.

The buyer reads every `AgentSettings` variable (shared/settings.py), and these:

| Variable | Default | What it sets |
|---|---|---|
| `SELF_LEGAL_NAME` | `Demo Buyer Agency LLC` | the legal name it trades under |
| `PEER_SELLER_ORIGIN` | `https://seller.wba-demo.noetis.dev` | the seller it deals with |
| `PEER_SELLER_LEGAL_NAME` | `Demo Seller Inc.` | that seller's legal name, as the buyer names it |
| `PEER_CFBOT_ORIGIN` | `https://cfbot.wba-demo.noetis.dev` | Cloudflare's verifier |
| `WBA_SIGNATURE_LIFETIME` | `300` | how long its signatures last, 1 to 300 s, checked at boot |

Its own party (`own`) is its `SELF_ORIGIN` and its legal name: the buyer
refuses a proposal that names any other buyer domain than its origin's host.
Its database is `buyer.db` in `DATA_DIR`, and its keyring is `KEYS_DIR`.
`plan_file` is its plan, the one this package ships by default; the composition
root reads it once. The sellers it deals with are its settings' own
(`counterparties`), read on every boot; the buyer stores none of them.

A published key waits before it signs for the directory's max-age
(`WBA_DIRECTORY_MAX_AGE`) plus the profile's 300 s (shared/keyring.py), so
production waits 600 s; nothing sets the wait apart from the max-age. Signatures
last the profile's 300 s maximum.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import ClassVar, Self

from pydantic import SecretStr

from persistence.values import Origin
from protocol.values import Value
from shared import settings as read
from shared.party import OwnParty
from shared.settings import DEFAULT_LEGAL_NAMES, DEFAULT_ORIGINS, AgentSettings, Role

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
    self_legal_name: str = DEFAULT_LEGAL_NAMES["buyer"]
    peer_seller_legal_name: str = DEFAULT_LEGAL_NAMES["seller"]
    peer_cfbot_origin: Origin = DEFAULT_ORIGINS["cfbot"]
    signature_lifetime: int = 300
    plan_file: Path = PLAN_FILE

    @property
    def own(self) -> OwnParty:
        """The buyer's own party: every proposal it commits to must name its origin's host as
        the buyer's domain."""
        return OwnParty(origin=self.self_origin, legal_name=self.self_legal_name)

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
            self_legal_name=read.text(env, "SELF_LEGAL_NAME", DEFAULT_LEGAL_NAMES["buyer"]),
            peer_seller_legal_name=read.text(
                env, "PEER_SELLER_LEGAL_NAME", DEFAULT_LEGAL_NAMES["seller"]
            ),
            peer_cfbot_origin=read.origin(env, "PEER_CFBOT_ORIGIN", DEFAULT_ORIGINS["cfbot"]),
            signature_lifetime=read.integer(env, "WBA_SIGNATURE_LIFETIME", 300),
        )
