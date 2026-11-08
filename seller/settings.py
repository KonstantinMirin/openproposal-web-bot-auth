"""The seller's settings: the only code on the seller that reads the environment.

The seller reads every `AgentSettings` variable (shared/settings.py), and these:

| Variable | Default | What it sets |
|---|---|---|
| `SELF_LEGAL_NAME` | `Demo Seller Inc.` | the legal name it issues proposals under |
| `PEER_BUYER_ORIGIN` | `https://buyer.wba-demo.noetis.dev` | the signing buyer it seeds |
| `DEMO_FAULT_INJECTION` | off | TEST ONLY: mounts `PUT /test/fault` |

Its database is `seller.db` in `DATA_DIR`, and its signing key `wba-key.jwk` in
`KEYS_DIR`. `template_file` is the proposal it issues every buyer, the one this
package ships by default; the composition root reads it once.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import ClassVar, Self

from persistence.values import Origin
from shared import settings as read
from shared.party import OwnParty
from shared.settings import DEFAULT_ORIGINS, AgentSettings, Role

#: The proposal every buyer is issued, as the seller's onboarding wrote it.
TEMPLATE_FILE = Path(__file__).resolve().parent / "seed" / "proposal.yaml"


@dataclass(frozen=True, kw_only=True)
class SellerSettings(AgentSettings):
    role: ClassVar[Role] = "seller"

    peer_buyer_origin: Origin = DEFAULT_ORIGINS["buyer"]
    self_legal_name: str = "Demo Seller Inc."
    template_file: Path = TEMPLATE_FILE
    #: TEST ONLY: install seller/faults.py.
    faults: bool = False

    @property
    def own(self) -> OwnParty:
        """The seller's own party, which every proposal it issues names as its seller."""
        return OwnParty(origin=self.self_origin, legal_name=self.self_legal_name)

    @property
    def key_file(self) -> Path:
        """The seller's signing key."""
        return self.keys_dir / "wba-key.jwk"

    @classmethod
    def from_env(cls, env: read.Environment | None = None) -> Self:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value."""
        env = read.environment(env)
        return replace(
            super().from_env(env),
            peer_buyer_origin=read.origin(env, "PEER_BUYER_ORIGIN", DEFAULT_ORIGINS["buyer"]),
            self_legal_name=read.text(env, "SELF_LEGAL_NAME", "Demo Seller Inc."),
            faults=read.flag(env, "DEMO_FAULT_INJECTION"),
        )
