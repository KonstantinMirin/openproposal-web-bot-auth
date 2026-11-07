"""The buyer's settings: the only code on the buyer that reads the environment.

| Variable | Default | What it sets |
|---|---|---|
| `SELF_ORIGIN` | `https://buyer.wba-demo.noetis.dev` | the buyer's own origin, which it signs as |
| `PEER_SELLER_ORIGIN` | `https://seller.wba-demo.noetis.dev` | the seller it deals with |
| `PEER_CFBOT_ORIGIN` | `https://cfbot.wba-demo.noetis.dev` | Cloudflare's verifier |
| `DATA_DIR` | `/data` | its database, `buyer.db` |
| `KEYS_DIR` | `/keys` | its keyring, on a volume no other service mounts |
| `SSL_CERT_FILE` | the system's roots | the trust store for every call it makes |
| `OPERATOR_KEY` | none: operator calls are refused | its own controls (shared/operator.py) |
| `DEMO_BEARER_TOKEN` | none: no bearer flow | the token the seller issued it |
| `WBA_DIRECTORY_MAX_AGE` | `300` | its directory's `Cache-Control: max-age` |
| `WBA_MAX_CACHE_AGE` | the library's, 300 | how long a cached directory answers |
| `WBA_ROTATION_WAIT` | `600` | how long a published key waits before it signs |
| `WBA_SIGNATURE_LIFETIME` | `300` | how long its signatures last |

In production, the rotation wait is the directory's max-age (300 s) plus the
library's default max_cache_age (300 s), and signatures last the profile's 300 s
maximum (shared/keyring.py).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from iab_agentic_primitives.web_bot_auth import Origin
from pydantic import SecretStr

from shared import settings as read


@dataclass(frozen=True)
class BuyerSettings:
    self_origin: Origin
    peer_seller_origin: Origin
    peer_cfbot_origin: Origin
    data_dir: Path
    #: Where its keyring lives; None keeps it in `data_dir/keys`, as a test runs one directory.
    keys_dir: Path | None = None
    ca_bundle: Path | None = None
    operator_key: SecretStr | None = None
    bearer_token: SecretStr | None = None
    directory_max_age: int = 300
    max_cache_age: int | None = None
    rotation_wait: float = 600.0
    signature_lifetime: int = 300

    @property
    def keyring_dir(self) -> Path:
        """The buyer's keyring."""
        return self.data_dir / "keys" if self.keys_dir is None else self.keys_dir

    @classmethod
    def from_env(cls, env: read.Environment | None = None) -> BuyerSettings:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value."""
        env = os.environ if env is None else env
        return cls(
            self_origin=read.origin(env, "SELF_ORIGIN", "https://buyer.wba-demo.noetis.dev"),
            peer_seller_origin=read.origin(
                env, "PEER_SELLER_ORIGIN", "https://seller.wba-demo.noetis.dev"
            ),
            peer_cfbot_origin=read.origin(
                env, "PEER_CFBOT_ORIGIN", "https://cfbot.wba-demo.noetis.dev"
            ),
            data_dir=read.path(env, "DATA_DIR", "/data"),
            keys_dir=read.path(env, "KEYS_DIR", "/keys"),
            ca_bundle=read.optional_path(env, "SSL_CERT_FILE"),
            operator_key=read.secret(env, "OPERATOR_KEY"),
            bearer_token=read.secret(env, "DEMO_BEARER_TOKEN"),
            directory_max_age=read.integer(env, "WBA_DIRECTORY_MAX_AGE", 300),
            max_cache_age=read.optional_integer(env, "WBA_MAX_CACHE_AGE"),
            rotation_wait=read.seconds(env, "WBA_ROTATION_WAIT", 600.0),
            signature_lifetime=read.integer(env, "WBA_SIGNATURE_LIFETIME", 300),
        )
