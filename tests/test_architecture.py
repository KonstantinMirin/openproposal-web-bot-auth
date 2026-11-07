"""The identity boundary's invariants, read from the source with `ast`; no app is imported.

- The identity types are frozen, strict, and refuse unknown members.
- Only the boundary module and the test factory build them.
- No route declares a `Request`.
- The offer logic reads no attribute of the caller's credential.
- No test imports a `_`-private name from the seller.

Each check is a function over source text, so the tests below also run it on a
planted violation and expect it to fire. The last tests hold the types to what
their config promises: no amended copy, no coercion, no illegal credential.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from tests import factories

REPO = Path(__file__).resolve().parent.parent
#: Where the identity types live, and the only modules that build them.
IDENTITY_MODULE = "seller/caller.py"
BUILDERS = frozenset({"seller/boundary.py", "tests/factories.py"})
IDENTITY_TYPES = frozenset(
    {
        "Principal",
        "DirectoryEvidence",
        "SignedMessage",
        "SignatureCredential",
        "BearerCredential",
        "ResolvedCaller",
        "PublicCaller",
    }
)
SCANNED = ("seller", "buyer", "shared", "runner", "tests", "e2e")
ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete"})
ROUTERS = frozenset({"api", "operator"})


def _source(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def _tree_sources() -> dict[str, str]:
    return {
        str(p.relative_to(REPO)): p.read_text(encoding="utf-8")
        for top in SCANNED
        for p in (REPO / top).rglob("*.py")
    }


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def frozen_config(source: str) -> dict[str, bool]:
    """For each identity type, whether it inherits a config with frozen=True,
    extra='forbid', and strict=True."""
    classes = {n.name: n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.ClassDef)}

    def own(node: ast.ClassDef) -> bool:
        for stmt in node.body:
            if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
                continue
            if [t.id for t in stmt.targets if isinstance(t, ast.Name)] != ["model_config"]:
                continue
            frozen, extra = _keyword(stmt.value, "frozen"), _keyword(stmt.value, "extra")
            strict = _keyword(stmt.value, "strict")
            return (
                isinstance(frozen, ast.Constant)
                and frozen.value is True
                and isinstance(extra, ast.Constant)
                and extra.value == "forbid"
                and isinstance(strict, ast.Constant)
                and strict.value is True
            )
        return False

    def inherited(name: str) -> bool:
        node = classes.get(name)
        if node is None:
            return False
        bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
        return own(node) or any(inherited(b) for b in bases)

    return {name: inherited(name) for name in IDENTITY_TYPES}


def identity_constructions(path: str, source: str) -> list[int]:
    """Lines where `source` builds an identity type, outside the modules allowed to."""
    if path in BUILDERS:
        return []
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"model_validate", "model_construct"}:
            func = func.value
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name in IDENTITY_TYPES:
            lines.append(node.lineno)
    return lines


def request_routes(path: str, source: str) -> set[tuple[str, str]]:
    """(module, route) for each route function with a parameter annotated `Request`."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        routed = any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and d.func.attr in ROUTE_DECORATORS
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id in ROUTERS
            for d in node.decorator_list
        )
        params = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        typed = any(
            isinstance(a.annotation, ast.Name) and a.annotation.id == "Request" for a in params
        )
        if routed and typed:
            found.add((path, node.name))
    return found


def credential_reads(source: str) -> list[int]:
    """Lines that read an attribute of a `credential`: `x.credential.<attr>`."""
    return [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "credential"
    ]


# ── The tree ───────────────────────────────────────────────────────────────


def test_identity_types_are_frozen_and_closed() -> None:
    assert frozen_config(_source(IDENTITY_MODULE)) == dict.fromkeys(IDENTITY_TYPES, True)


def test_only_the_boundary_and_the_factory_build_identity_types() -> None:
    built = {
        p: lines for p, s in _tree_sources().items() if (lines := identity_constructions(p, s))
    }
    assert built == {}


def test_no_route_declares_request() -> None:
    routes = set().union(*(request_routes(p, s) for p, s in _tree_sources().items()))
    assert routes == set()


def test_the_offer_logic_reads_no_credential_attribute() -> None:
    offers = sorted((REPO / "seller" / "offers").glob("*.py"))
    assert offers
    assert {p.name: credential_reads(p.read_text()) for p in offers} == {p.name: [] for p in offers}


def private_imports(source: str) -> list[str]:
    """`_`-private names `source` imports from the seller."""
    return [
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("seller")
        for alias in node.names
        if alias.name.startswith("_")
    ]


def test_no_test_imports_a_private_seller_name() -> None:
    tests = {
        str(p.relative_to(REPO)): private_imports(p.read_text())
        for p in (REPO / "tests").glob("*.py")
    }
    assert {path: names for path, names in tests.items() if names} == {}


def test_a_planted_private_import_fires() -> None:
    assert private_imports("from seller.offers.checks import _live_names\n") == ["_live_names"]


# ── Each check fires on a planted violation ────────────────────────────────


def test_a_planted_construction_in_the_seller_app_fires() -> None:
    planted = _source("seller/app.py") + (
        "\n\nPLANTED = Principal(id='x', kind='buyer', legal_name='X', domain='x.example')\n"
    )
    lines = identity_constructions("seller/app.py", planted)
    assert lines == [planted.count("\n")]


@pytest.mark.parametrize(
    "call", ["identity.ResolvedCaller(**row)", "PublicCaller.model_validate(row)"]
)
def test_qualified_and_validated_constructions_fire(call: str) -> None:
    assert identity_constructions("seller/offers.py", f"x = {call}\n") == [1]


def test_a_thawed_identity_type_fires() -> None:
    for setting in ("frozen=True", "strict=True"):
        thawed = _source(IDENTITY_MODULE).replace(setting, setting.replace("True", "False"))
        assert not all(frozen_config(thawed).values()), setting


def test_a_planted_request_route_fires() -> None:
    planted = "@operator.get('/x')\nasync def x(request: Request) -> None:\n    pass\n"
    assert request_routes("seller/app.py", planted) == {("seller/app.py", "x")}


def test_a_planted_credential_read_fires() -> None:
    planted = "def f(caller):\n    return caller.credential.method\n"
    assert credential_reads(planted) == [2]


# ── The types refuse what their config promises ─────────────────────────────


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
