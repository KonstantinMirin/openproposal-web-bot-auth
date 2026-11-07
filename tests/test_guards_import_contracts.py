"""Proof that each committed import contract breaks on a planted import, and only then.

`make guards` runs lint-imports over the packages. Each case here builds a tree
of empty packages with the committed `.importlinter`, plants one import, and
expects exactly the named contract to break. The clean tree keeps every contract.
"""

from __future__ import annotations

import configparser
import shutil
from pathlib import Path

import pytest

from tests._tools import run, tool

REPO = Path(__file__).resolve().parent.parent
LINT_IMPORTS = tool("lint-imports")
CONFIG = configparser.ConfigParser()
CONFIG.read(REPO / ".importlinter")
PACKAGES = CONFIG["importlinter"]["root_packages"].split()
CONTRACTS = {
    section.removeprefix("importlinter:contract:"): CONFIG[section]["name"]
    for section in CONFIG.sections()
    if section.startswith("importlinter:contract:")
}

# (the contracts the import breaks, module that imports, the import it plants). The
# layers contract marks the parties `seller | buyer | runner`, independent siblings,
# so an import between parties breaks it as well.
CASES = (
    ({"parties-independent", "layers"}, "seller/planted.py", "import buyer.planted\n"),
    ({"parties-independent", "layers"}, "runner/planted.py", "from seller import planted\n"),
    ({"layers"}, "shared/planted.py", "import seller.planted\n"),
    ({"layers"}, "protocol/planted.py", "import shared.planted\n"),
    ({"offers-framework-free"}, "seller/offers.py", "import httpx\n"),
    # Through the identity types the offer logic takes: the chain Step 4 removed.
    ({"offers-framework-free"}, "seller/caller.py", "import iab_agentic_primitives\n"),
)
#: Modules present in every tree: the offer logic and the identity types it takes, and
#: seller.errors with the one import the offers contract ignores, so its ignore line matches.
NAMED = {
    "seller/offers.py": "from . import caller\n",
    "seller/caller.py": "",
    "seller/errors.py": "import fastapi\n",
}


def _lint(tree: Path, planted: tuple[str, str] | None) -> str:
    for package in PACKAGES:
        (tree / package).mkdir(parents=True)
        (tree / package / "__init__.py").write_text("")
        (tree / package / "planted.py").write_text("")
    for path, source in NAMED.items():
        (tree / path).write_text(source)
    if planted is not None:
        path, source = planted
        (tree / path).write_text(source)
    shutil.copy(REPO / ".importlinter", tree)
    # lint-imports finds the root packages in its working directory.
    return run([str(LINT_IMPORTS), "--no-cache"], cwd=tree).stdout


def _broken(output: str) -> set[str]:
    return {key for key, name in CONTRACTS.items() if f"{name} BROKEN" in output}


@pytest.mark.parametrize(("contracts", "path", "source"), CASES, ids=[c[1] for c in CASES])
def test_contract_breaks_on_a_planted_import(
    tmp_path: Path, contracts: set[str], path: str, source: str
) -> None:
    assert _broken(_lint(tmp_path, (path, source))) == contracts


def test_a_clean_tree_keeps_every_contract(tmp_path: Path) -> None:
    output = _lint(tmp_path, None)
    assert all(f"{name} KEPT" in output for name in CONTRACTS.values()), output


def test_every_committed_contract_has_a_proof() -> None:
    assert set().union(*(c[0] for c in CASES)) == set(CONTRACTS)
