"""What every agent's settings hold, and how a settings module reads one variable.

Each agent reads its environment once, in its own `Settings.from_env()`
(seller/settings.py, buyer/settings.py, runner/settings.py). `AgentSettings`
holds what the seller and the buyer both read, read once here; each agent's
settings extend it. The readers take that mapping and the variable's name, and
parse the value once, so a bad value stops the agent at startup with an error
that names the variable. An origin is an `Origin` (persistence/values.py):
exactly `https://<host>`, so `.host` is always a host.

Origins follow one naming scheme in every service: `SELF_ORIGIN` is the agent's
own origin, and `PEER_<ROLE>_ORIGIN` names a counterparty (`PEER_SELLER_ORIGIN`,
`PEER_BUYER_ORIGIN`, `PEER_CFBOT_ORIGIN`). `DEFAULT_ORIGINS` is the one place the
demo's own origins are written, by role.

| Variable | Default | What it sets |
|---|---|---|
| `SELF_ORIGIN` | the role's `DEFAULT_ORIGINS` entry | the agent's own origin |
| `DATA_DIR` | `/data` | its database |
| `KEYS_DIR` | `/keys` | its signing keys, on a volume no other service mounts |
| `SSL_CERT_FILE` | the system's roots | the trust store for every call it makes |
| `OPERATOR_KEY` | none: operator calls are refused | its own controls (transport/operator.py) |
| `DEMO_BEARER_TOKEN` | none: no bearer buyer | the token the seller issued its bearer buyer |
| `WBA_DIRECTORY_MAX_AGE` | `300` | its directory's `Cache-Control: max-age` |
| `WBA_MAX_CACHE_AGE` | the library's, 300 | how long a cached directory answers |
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Self

from pydantic import SecretStr, ValidationError

from persistence.values import Origin

#: The environment an agent reads its settings from.
Environment = Mapping[str, str]
#: The parties of the demo.
Role = Literal["seller", "buyer", "cfbot"]

#: Each party's origin in the demo's own deployment.
DEFAULT_ORIGINS: Mapping[Role, Origin] = {
    "seller": Origin.parse("https://seller.wba-demo.noetis.dev"),
    "buyer": Origin.parse("https://buyer.wba-demo.noetis.dev"),
    "cfbot": Origin.parse("https://cfbot.wba-demo.noetis.dev"),
}


def environment(env: Environment | None) -> Environment:
    """`env`, or the process environment when it is None."""
    return os.environ if env is None else env


class SettingsError(ValueError):
    """A variable whose value can't configure the agent. The message names the variable."""

    def __init__(self, name: str, problem: str) -> None:
        super().__init__(f"{name}: {problem}")
        self.name = name


def origin(env: Environment, name: str, default: Origin) -> Origin:
    """`name` as an origin, `https://<host>` and nothing else, or `default` when it is unset."""
    value = env.get(name)
    if value is None:
        return default
    try:
        return Origin.parse(value)
    except ValidationError as e:
        raise SettingsError(name, f"{value!r} is not an origin https://<host>") from e


def integer(env: Environment, name: str, default: int) -> int:
    """`name` as a whole number of seconds, zero or more."""
    value = optional_integer(env, name)
    return default if value is None else value


def optional_integer(env: Environment, name: str) -> int | None:
    """`name` as a whole number of seconds, or None when it is unset or empty."""
    value = env.get(name, "")
    if not value:
        return None
    if not (value.isascii() and value.isdigit()):
        raise SettingsError(name, f"{value!r} is not a whole number of seconds")
    return int(value)


def seconds(env: Environment, name: str, default: float) -> float:
    """`name` as a number of seconds, zero or more."""
    value = env.get(name)
    if value is None:
        return default
    try:
        number = float(value)
    except ValueError:
        number = -1.0
    if not number >= 0:  # also refuses nan
        raise SettingsError(name, f"{value!r} is not a number of seconds")
    return number


def text(env: Environment, name: str, default: str) -> str:
    """`name` as text, or `default` when it is unset or empty."""
    return env.get(name, "") or default


def secret(env: Environment, name: str) -> SecretStr | None:
    """`name` as a secret, or None when it is unset or empty."""
    value = env.get(name, "")
    return SecretStr(value) if value else None


def required_secret(env: Environment, name: str) -> SecretStr:
    """`name` as a secret, which must be set and not empty."""
    value = secret(env, name)
    if value is None:
        raise SettingsError(name, "is required")
    return value


def path(env: Environment, name: str, default: str) -> Path:
    return Path(env.get(name, default))


def optional_path(env: Environment, name: str) -> Path | None:
    value = env.get(name, "")
    return Path(value) if value else None


def flag(env: Environment, name: str) -> bool:
    """`name` is on only when it is exactly `1`."""
    return env.get(name) == "1"


@dataclass(frozen=True, kw_only=True)
class AgentSettings:
    """What the seller and the buyer each read: their own origin, storage, trust, and keys."""

    #: The role whose default origin `SELF_ORIGIN` falls back to.
    role: ClassVar[Role]

    self_origin: Origin
    data_dir: Path
    #: Where its signing keys live, on a volume no other service mounts.
    keys_dir: Path
    ca_bundle: Path | None = None
    operator_key: SecretStr | None = None
    bearer_token: SecretStr | None = None
    directory_max_age: int = 300
    max_cache_age: int | None = None

    @classmethod
    def from_env(cls, env: Environment | None = None) -> Self:
        """Reads the settings once; raises `SettingsError`, naming the variable, for a bad value.

        An agent's own settings read their own variables on top of these.
        """
        env = environment(env)
        return cls(
            self_origin=origin(env, "SELF_ORIGIN", DEFAULT_ORIGINS[cls.role]),
            data_dir=path(env, "DATA_DIR", "/data"),
            keys_dir=path(env, "KEYS_DIR", "/keys"),
            ca_bundle=optional_path(env, "SSL_CERT_FILE"),
            operator_key=secret(env, "OPERATOR_KEY"),
            bearer_token=secret(env, "DEMO_BEARER_TOKEN"),
            directory_max_age=integer(env, "WBA_DIRECTORY_MAX_AGE", 300),
            max_cache_age=optional_integer(env, "WBA_MAX_CACHE_AGE"),
        )
