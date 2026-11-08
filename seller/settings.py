"""The seller's settings: the only code on the seller that reads the environment.

| Variable | Default | What it sets |
|---|---|---|
| `SELF_ORIGIN` | `https://seller.wba-demo.noetis.dev` | the seller's own origin |
| `SELF_LEGAL_NAME` | `Demo Seller Inc.` | the legal name it issues proposals under |
| `PEER_BUYER_ORIGIN` | `https://buyer.wba-demo.noetis.dev` | the signing buyer it seeds |
| `DATA_DIR` | `/data` | its database, `seller.db` |
| `KEYS_DIR` | `/keys` | its signing key, `wba-key.jwk`, on a volume no other service mounts |
| `SSL_CERT_FILE` | the system's roots | the trust store for directory fetches |
| `OPERATOR_KEY` | none: operator calls are refused | its own controls (transport/operator.py) |
| `DEMO_BEARER_TOKEN` | none: no bearer buyer | the token it issues the bearer buyer |
| `WBA_DIRECTORY_MAX_AGE` | `300` | its directory's `Cache-Control: max-age` |
| `WBA_MAX_CACHE_AGE` | the library's, 300 | how long a cached directory answers |
| `DEMO_FAULT_INJECTION` | off | TEST ONLY: mounts `PUT /test/fault` |
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from persistence.values import Origin
from shared import settings as read
from shared.party import OwnParty


@dataclass(frozen=True)
class SellerSettings:
    self_origin: Origin
    peer_buyer_origin: Origin
    data_dir: Path
    #: Where its signing key lives; None keeps it in `data_dir`, as a test runs one directory.
    keys_dir: Path | None = None
    ca_bundle: Path | None = None
    operator_key: SecretStr | None = None
    bearer_token: SecretStr | None = None
    directory_max_age: int = 300
    max_cache_age: int | None = None
    self_legal_name: str = "Demo Seller Inc."
    #: TEST ONLY: install seller/faults.py.
    faults: bool = False

    @property
    def own(self) -> OwnParty:
        """The seller's own party, which every proposal it issues names as its seller."""
        return OwnParty(origin=self.self_origin, legal_name=self.self_legal_name)

    @property
    def key_file(self) -> Path:
        """The seller's signing key."""
        return (self.data_dir if self.keys_dir is None else self.keys_dir) / "wba-key.jwk"

    @classmethod
    def from_env(cls, env: read.Environment | None = None) -> SellerSettings:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value."""
        env = os.environ if env is None else env
        return cls(
            self_origin=read.origin(env, "SELF_ORIGIN", "https://seller.wba-demo.noetis.dev"),
            peer_buyer_origin=read.origin(
                env, "PEER_BUYER_ORIGIN", "https://buyer.wba-demo.noetis.dev"
            ),
            data_dir=read.path(env, "DATA_DIR", "/data"),
            keys_dir=read.path(env, "KEYS_DIR", "/keys"),
            ca_bundle=read.optional_path(env, "SSL_CERT_FILE"),
            operator_key=read.secret(env, "OPERATOR_KEY"),
            bearer_token=read.secret(env, "DEMO_BEARER_TOKEN"),
            directory_max_age=read.integer(env, "WBA_DIRECTORY_MAX_AGE", 300),
            max_cache_age=read.optional_integer(env, "WBA_MAX_CACHE_AGE"),
            self_legal_name=read.text(env, "SELF_LEGAL_NAME", "Demo Seller Inc."),
            faults=read.flag(env, "DEMO_FAULT_INJECTION"),
        )
