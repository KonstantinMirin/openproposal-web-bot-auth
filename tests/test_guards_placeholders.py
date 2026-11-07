"""Proof that `make placeholders` fails on a placeholder left in the tree, and only then."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests._tools import run

REPO = Path(__file__).resolve().parent.parent
#: The words the check looks for, built here so that this file holds none of them.
WORDS = ["LIBRARY" + "_URL", "SPEC" + "_URL", "PLACE" + "HOLDER"]


def _placeholders(tree: Path, path: str, text: str) -> int:
    shutil.copy(REPO / "Makefile", tree / "Makefile")
    planted = tree / path
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(text)
    return run(["make", "-s", "placeholders"], cwd=tree).returncode


@pytest.mark.parametrize("word", WORDS)
def test_a_planted_placeholder_fails(tmp_path: Path, word: str) -> None:
    assert _placeholders(tmp_path, "README.md", f"See the [library]({word}).\n") != 0


def test_the_seed_templates_own_placeholders_pass(tmp_path: Path) -> None:
    template = f'proposal_id: "{WORDS[2]}"\n'
    assert _placeholders(tmp_path, "seller/seed/proposal.yaml", template) == 0


def test_the_tree_holds_no_placeholder() -> None:
    assert run(["make", "-s", "placeholders"], cwd=REPO).returncode == 0
