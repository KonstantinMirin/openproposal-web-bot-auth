"""The identity boundary's invariants, read from the source with `ast`; no app is imported.

- The identity types are frozen and refuse unknown members.
- Only the boundary module builds them.
- No route declares a `Request`, except the one allowlisted route, which Step 4
  removes. The allowlist is matched exactly, so it can only shrink.
- The offer logic reads no attribute of the caller's credential.

Each check is a function over source text, so the tests below also run it on a
planted violation and expect it to fire.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BOUNDARY = "seller/identity.py"
IDENTITY_TYPES = frozenset({"Principal", "Credential", "ResolvedCaller", "PublicCaller"})
SCANNED = ("seller", "buyer", "shared", "runner", "tests", "e2e")
ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete"})
ROUTERS = frozenset({"api", "operator"})
#: (module, route) pairs allowed to declare `Request`. Step 4 empties it.
REQUEST_ALLOWLIST = frozenset({("seller/app.py", "commit")})


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
    """For each identity type, whether it inherits a config with frozen=True, extra='forbid'."""
    classes = {n.name: n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.ClassDef)}

    def own(node: ast.ClassDef) -> bool:
        for stmt in node.body:
            if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
                continue
            if [t.id for t in stmt.targets if isinstance(t, ast.Name)] != ["model_config"]:
                continue
            frozen, extra = _keyword(stmt.value, "frozen"), _keyword(stmt.value, "extra")
            return (
                isinstance(frozen, ast.Constant)
                and frozen.value is True
                and isinstance(extra, ast.Constant)
                and extra.value == "forbid"
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
    """Lines where `source` builds an identity type, outside the boundary module."""
    if path == BOUNDARY:
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
    assert frozen_config(_source(BOUNDARY)) == dict.fromkeys(IDENTITY_TYPES, True)


def test_only_the_boundary_builds_identity_types() -> None:
    built = {
        p: lines for p, s in _tree_sources().items() if (lines := identity_constructions(p, s))
    }
    assert built == {}


def test_no_route_declares_request_beyond_the_allowlist() -> None:
    routes = set().union(*(request_routes(p, s) for p, s in _tree_sources().items()))
    assert routes == REQUEST_ALLOWLIST


def test_the_offer_logic_reads_no_credential_attribute() -> None:
    assert credential_reads(_source("seller/offers.py")) == []


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
    thawed = _source(BOUNDARY).replace("frozen=True", "frozen=False")
    assert not all(frozen_config(thawed).values())


def test_a_planted_request_route_fires() -> None:
    planted = "@operator.get('/x')\nasync def x(request: Request) -> None:\n    pass\n"
    assert request_routes("seller/app.py", planted) == {("seller/app.py", "x")}


def test_a_planted_credential_read_fires() -> None:
    planted = "def f(caller):\n    return caller.credential.method\n"
    assert credential_reads(planted) == [2]
