"""The identity values (seller/caller.py) refuse what their config promises.

The boundary's confirmed identity is passed on frozen: no value gives an
amended copy, and a value the types don't allow never constructs.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import BaseModel, ValidationError

from tests import factories


@pytest.mark.parametrize(
    "value",
    [
        factories.principal(),
        factories.signature_credential(),
        factories.bearer_credential(),
        factories.resolved_caller(),
        factories.public_caller(),
    ],
    ids=type,
)
def test_no_identity_value_gives_an_amended_copy(value: BaseModel) -> None:
    with pytest.raises(TypeError, match="never amended"):
        value.model_copy(update={"credential": {"method": "nope"}})


@pytest.mark.parametrize(
    "build",
    [
        lambda: factories.bearer_credential(origin="https://buyer.example"),
        lambda: factories.public_caller(signature=factories.bearer_credential()),
        lambda: factories.signature_credential(body_covered="yes"),
        lambda: factories.principal(kind="seller"),
        lambda: factories.resolved_caller(credential={"method": "nope"}),
        lambda: factories.resolved_caller(attributed=1),
    ],
    ids=[
        "a bearer credential with an origin",
        "a public caller with a bearer credential",
        "a coerced boolean",
        "a principal of another kind",
        "an unknown credential method",
        "a coerced attribution",
    ],
)
def test_an_illegal_identity_does_not_construct(build: Callable[[], BaseModel]) -> None:
    with pytest.raises(ValidationError):
        build()
