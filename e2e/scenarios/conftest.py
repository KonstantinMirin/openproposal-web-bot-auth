"""The scenarios' fixtures: a client of the stack, each agent's controls, and each party's
records. What they use besides is in e2e/scenarios/stack.py."""

from __future__ import annotations

import ssl
from collections.abc import Iterator

import httpx
import pytest

from e2e.scenarios.stack import (
    BUYER_CONTROL,
    BUYER_DB,
    CFBOT_CONTROL,
    SELLER_CONTROL,
    SELLER_DB,
    control,
)
from persistence.observe import BuyerRecords, SellerRecords
from transport.client import ControlClient


@pytest.fixture
def web() -> Iterator[httpx.Client]:
    """A client that trusts the public roots plus the demo CA, as every container does."""
    with httpx.Client(verify=ssl.create_default_context(), timeout=30) as client:
        yield client


@pytest.fixture
def seller_control(web: httpx.Client) -> ControlClient:
    return control(web, SELLER_CONTROL)


@pytest.fixture
def buyer_control(web: httpx.Client) -> ControlClient:
    return control(web, BUYER_CONTROL)


@pytest.fixture
def cfbot_control(web: httpx.Client) -> ControlClient:
    return control(web, CFBOT_CONTROL)


@pytest.fixture
def seller_records() -> Iterator[SellerRecords]:
    """The seller's records, read-only."""
    with SellerRecords.open(SELLER_DB) as records:
        yield records


@pytest.fixture
def buyer_records() -> Iterator[BuyerRecords]:
    """The buyer's records, read-only."""
    with BuyerRecords.open(BUYER_DB) as records:
        yield records
