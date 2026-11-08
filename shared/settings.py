"""How each agent's settings module reads one variable from its environment.

Each agent reads its environment once, in its own `Settings.from_env()`
(seller/settings.py, buyer/settings.py, runner/settings.py). These readers take
that mapping and the variable's name, and parse the value once, so a bad value
stops the agent at startup with an error that names the variable. An origin is
an `Origin` (persistence/values.py): exactly `https://<host>`, so `.host` is
always a host.

Origins follow one naming scheme in every service: `SELF_ORIGIN` is the agent's
own origin, and `PEER_<ROLE>_ORIGIN` names a counterparty (`PEER_SELLER_ORIGIN`,
`PEER_BUYER_ORIGIN`, `PEER_CFBOT_ORIGIN`).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from pydantic import SecretStr, ValidationError

from persistence.values import Origin

#: The environment an agent reads its settings from.
Environment = Mapping[str, str]


class SettingsError(ValueError):
    """A variable whose value can't configure the agent. The message names the variable."""

    def __init__(self, name: str, problem: str) -> None:
        super().__init__(f"{name}: {problem}")
        self.name = name


def origin(env: Environment, name: str, default: str) -> Origin:
    """`name` as an origin, `https://<host>` and nothing else."""
    value = env.get(name, default)
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


def secret(env: Environment, name: str) -> SecretStr | None:
    """`name` as a secret, or None when it is unset or empty."""
    value = env.get(name, "")
    return SecretStr(value) if value else None


def path(env: Environment, name: str, default: str) -> Path:
    return Path(env.get(name, default))


def optional_path(env: Environment, name: str) -> Path | None:
    value = env.get(name, "")
    return Path(value) if value else None


def flag(env: Environment, name: str) -> bool:
    """`name` is on only when it is exactly `1`."""
    return env.get(name) == "1"
