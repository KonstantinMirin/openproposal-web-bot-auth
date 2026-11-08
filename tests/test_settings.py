"""Each agent reads its environment once, and a bad value stops it with the variable's name."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from buyer.settings import BuyerSettings
from persistence.values import Origin
from runner.settings import RunnerSettings
from seller.settings import SellerSettings
from shared.settings import SettingsError

Reader = Callable[[Mapping[str, str]], object]

#: The runner's required secrets, so a test of another variable reaches that variable.
RUNNER_KEYS = {"SELLER_OPERATOR_KEY": "seller-secret-value", "BUYER_OPERATOR_KEY": "buyer-key"}


def runner(env: Mapping[str, str]) -> RunnerSettings:
    return RunnerSettings.from_env({**RUNNER_KEYS, **env})


#: Every origin variable, with the settings reader that parses it.
ORIGINS: list[tuple[str, Reader]] = [
    ("SELF_ORIGIN", SellerSettings.from_env),
    ("PEER_BUYER_ORIGIN", SellerSettings.from_env),
    ("SELF_ORIGIN", BuyerSettings.from_env),
    ("PEER_SELLER_ORIGIN", BuyerSettings.from_env),
    ("PEER_CFBOT_ORIGIN", BuyerSettings.from_env),
    ("PEER_SELLER_ORIGIN", runner),
    ("PEER_BUYER_ORIGIN", runner),
    ("PEER_CFBOT_ORIGIN", runner),
]

NOT_ORIGINS = [
    "buyer.wba-demo.noetis.dev",  # no scheme
    "http://buyer.wba-demo.noetis.dev",  # not https
    "https://buyer.wba-demo.noetis.dev/agent",  # a path
    "https://buyer.wba-demo.noetis.dev/",  # a trailing slash
    "https://",  # an empty host
    "https://buyer.wba-demo.noetis.dev:8443",  # a port
]


def test_the_seller_defaults_to_the_demo_deployment() -> None:
    settings = SellerSettings.from_env({})
    assert settings == SellerSettings(
        self_origin=Origin.parse("https://seller.wba-demo.noetis.dev"),
        peer_buyer_origin=Origin.parse("https://buyer.wba-demo.noetis.dev"),
        data_dir=Path("/data"),
        keys_dir=Path("/keys"),
    )
    # The key lives on its own volume, apart from the database.
    assert settings.key_file == Path("/keys/wba-key.jwk")


def test_the_seller_reads_every_variable() -> None:
    settings = SellerSettings.from_env(
        {
            "SELF_ORIGIN": "https://seller.example",
            "PEER_BUYER_ORIGIN": "https://buyer.example",
            "DATA_DIR": "/srv/seller",
            "KEYS_DIR": "/srv/seller-keys",
            "SSL_CERT_FILE": "/certs/bundle.pem",
            "OPERATOR_KEY": "operator-key",
            "DEMO_BEARER_TOKEN": "bearer-token",
            "WBA_DIRECTORY_MAX_AGE": "0",
            "WBA_MAX_CACHE_AGE": "20",
            "DEMO_FAULT_INJECTION": "1",
        }
    )
    assert settings.self_origin == Origin.parse("https://seller.example")
    assert settings.peer_buyer_origin.host == "buyer.example"
    assert settings.data_dir == Path("/srv/seller")
    assert settings.key_file == Path("/srv/seller-keys/wba-key.jwk")
    assert settings.ca_bundle == Path("/certs/bundle.pem")
    assert settings.operator_key is not None
    assert settings.operator_key.get_secret_value() == "operator-key"
    assert settings.bearer_token is not None
    assert settings.bearer_token.get_secret_value() == "bearer-token"
    assert (settings.directory_max_age, settings.max_cache_age, settings.faults) == (0, 20, True)
    assert "operator-key" not in repr(settings) and "bearer-token" not in repr(settings)


@pytest.mark.parametrize("value", ["", "0", "true", "yes"])
def test_only_1_turns_the_fault_switch_on(value: str) -> None:
    assert SellerSettings.from_env({"DEMO_FAULT_INJECTION": value}).faults is False


def test_the_buyer_reads_every_variable() -> None:
    settings = BuyerSettings.from_env(
        {
            "SELF_ORIGIN": "https://buyer.example",
            "PEER_SELLER_ORIGIN": "https://seller.example",
            "PEER_CFBOT_ORIGIN": "https://cfbot.example",
            "DATA_DIR": "/srv/buyer",
            "KEYS_DIR": "/srv/buyer-keys",
            "WBA_DIRECTORY_MAX_AGE": "0",
            "WBA_ROTATION_WAIT": "20",
            "WBA_SIGNATURE_LIFETIME": "10",
        }
    )
    assert str(settings.self_origin) == "https://buyer.example"
    assert str(settings.peer_seller_origin) == "https://seller.example"
    assert str(settings.peer_cfbot_origin) == "https://cfbot.example"
    assert (settings.directory_max_age, settings.rotation_wait, settings.signature_lifetime) == (
        0,
        20.0,
        10,
    )
    assert settings.operator_key is None and settings.bearer_token is None
    assert settings.max_cache_age is None  # the library's default
    assert (settings.data_dir, settings.keyring_dir) == (
        Path("/srv/buyer"),
        Path("/srv/buyer-keys"),
    )


def test_the_buyer_defaults_to_the_production_rotation() -> None:
    settings = BuyerSettings.from_env({})
    assert settings.keyring_dir == Path("/keys")  # apart from the database
    assert (settings.rotation_wait, settings.signature_lifetime, settings.directory_max_age) == (
        600.0,
        300,
        300,
    )


def test_the_runner_keeps_its_secrets_out_of_its_repr() -> None:
    settings = runner({"DEMO_BEARER_TOKEN": "short", "RUN_INTERVAL": "0"})
    assert settings.secrets == ("seller-secret-value", "buyer-key")  # too short: skipped
    assert settings.interval == 0
    assert "seller-secret-value" not in repr(settings)
    assert settings.seller_operator_key.get_secret_value() == "seller-secret-value"
    assert settings.buyer_operator_key.get_secret_value() == "buyer-key"
    assert str(settings.seller) == "https://seller.wba-demo.noetis.dev"


@pytest.mark.parametrize("value", NOT_ORIGINS)
@pytest.mark.parametrize(("name", "read"), ORIGINS)
def test_an_origin_that_is_not_https_host_fails_naming_the_variable(
    name: str, read: Reader, value: str
) -> None:
    with pytest.raises(SettingsError) as e:
        read({name: value})
    assert e.value.name == name
    assert str(e.value).startswith(f"{name}: ")


def test_a_buyer_origin_without_a_scheme_stops_the_seller_at_its_settings() -> None:
    """The seller stops at its settings, naming the variable, before it seeds anything."""
    with pytest.raises(SettingsError, match="^PEER_BUYER_ORIGIN: "):
        SellerSettings.from_env({"PEER_BUYER_ORIGIN": "buyer.wba-demo.noetis.dev"})


@pytest.mark.parametrize(
    ("name", "value", "read"),
    [
        ("WBA_DIRECTORY_MAX_AGE", "soon", SellerSettings.from_env),
        ("WBA_DIRECTORY_MAX_AGE", "-1", BuyerSettings.from_env),
        ("WBA_MAX_CACHE_AGE", "2.5", SellerSettings.from_env),
        ("WBA_MAX_CACHE_AGE", "²", BuyerSettings.from_env),
        ("WBA_SIGNATURE_LIFETIME", "ten", BuyerSettings.from_env),
        ("WBA_ROTATION_WAIT", "-1", BuyerSettings.from_env),
        ("WBA_ROTATION_WAIT", "nan", BuyerSettings.from_env),
        ("WBA_ROTATION_WAIT", "later", BuyerSettings.from_env),
        ("RUN_INTERVAL", "hourly", runner),
        ("SELLER_OPERATOR_KEY", "", runner),
        ("BUYER_OPERATOR_KEY", "", runner),
    ],
)
def test_a_bad_number_fails_naming_the_variable(name: str, value: str, read: Reader) -> None:
    with pytest.raises(SettingsError) as e:
        read({name: value})
    assert e.value.name == name


@pytest.mark.parametrize("name", ["OPERATOR_KEY", "DEMO_BEARER_TOKEN", "WBA_MAX_CACHE_AGE"])
def test_an_empty_optional_variable_is_unset(name: str) -> None:
    settings = SellerSettings.from_env({name: ""})
    assert (settings.operator_key, settings.bearer_token, settings.max_cache_age) == (
        None,
        None,
        None,
    )
