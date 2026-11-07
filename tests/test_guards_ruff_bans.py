"""Proof that each ruff layer table bans what it names, and that every exemption is still needed.

`make lint` runs each ruff-*.toml table as its own stage. Each case copies one
table into a temporary tree, plants a banned use at a path the table covers,
and expects TID251 there and nowhere in the clean twin.

The exemption lists only shrink. The second half of this module enforces it: an
exemption entry whose codes no longer fire in its file fails here, so the entry
is deleted in the change that made it unnecessary.
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path
from typing import TypedDict

import pytest
from pydantic import TypeAdapter

from tests._tools import run, tool

REPO = Path(__file__).resolve().parent.parent
RUFF = tool("ruff")

# (table, planted path, violation, clean twin)
CASES = (
    ("ruff-domain.toml", "protocol/record.py", "import sqlite3\n", "import json\n"),
    ("ruff-domain.toml", "protocol/values.py", "from fastapi import Request\n", "import re\n"),
    (
        "ruff-environment.toml",
        "seller/offers.py",
        "import os\n\nORIGIN = os.environ['SELLER_ORIGIN']\n",
        "ORIGIN = 'https://seller.example'\n",
    ),
    (
        # The settings module is the one sanctioned reader: no hit there.
        "ruff-environment.toml",
        "seller/settings.py",
        "import os\n\nORIGIN = os.getenv('SELLER_ORIGIN')\n",
        None,
    ),
    ("ruff-buyer.toml", "buyer/flow.py", "import httpx\n", "import json\n"),
    ("ruff-digest.toml", "runner/live.py", "import hashlib\n", "import json\n"),
    ("ruff-digest.toml", "seller/offers.py", "from rfc8785 import dumps\n", "import json\n"),
)


class _Location(TypedDict):
    row: int


class _Finding(TypedDict):
    code: str
    filename: str
    location: _Location


_FINDINGS = TypeAdapter(list[_Finding])
_IGNORES = TypeAdapter(dict[str, list[str]])


def _ruff(cwd: Path, *args: str) -> list[_Finding]:
    check = run([str(RUFF), "check", "--no-cache", "--output-format", "json", *args], cwd=cwd)
    assert check.returncode in (0, 1), check.stderr
    return _FINDINGS.validate_json(check.stdout or "[]")


def _bans(tree: Path, table: str, path: str, source: str) -> list[int]:
    tree.mkdir()
    shutil.copy(REPO / table, tree)
    planted = tree / path
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(source)
    return [f["location"]["row"] for f in _ruff(tree, "--config", table) if f["code"] == "TID251"]


@pytest.mark.parametrize(("table", "path", "bad", "good"), CASES, ids=[c[1] for c in CASES])
def test_table_bans_the_planted_use(
    tmp_path: Path, table: str, path: str, bad: str, good: str | None
) -> None:
    expected = [] if path.endswith("settings.py") else [bad.count("\n")]
    assert _bans(tmp_path / "bad", table, path, bad) == expected
    if good is not None:
        assert _bans(tmp_path / "good", table, path, good) == []


def test_every_table_has_a_proof() -> None:
    assert {c[0] for c in CASES} == {p.name for p in REPO.glob("ruff-*.toml")}


# ── Exemptions only shrink ─────────────────────────────────────────────────

#: Per-file ignores that are policy, not exemptions.
POLICY = {"tests/**", "e2e/scenarios/**", "*/settings.py", "protocol/**"}


def _fired(*config: str) -> set[tuple[str, str]]:
    """(file, code) for every finding with the per-file ignores emptied."""
    return {
        (str(Path(f["filename"]).relative_to(REPO)), f["code"])
        for f in _ruff(REPO, *config, "--config", "lint.per-file-ignores = {}")
    }


def _exemptions(table: dict[str, object]) -> list[tuple[str, str]]:
    ignores = _IGNORES.validate_python(table["per-file-ignores"])
    return [(f, code) for f, codes in ignores.items() if f not in POLICY for code in codes]


def test_every_rule_set_exemption_still_fires() -> None:
    lint = tomllib.loads((REPO / "pyproject.toml").read_text())["tool"]["ruff"]["lint"]
    fired = _fired()
    assert [e for e in _exemptions(lint) if e not in fired] == []


@pytest.mark.parametrize("table", sorted(p.name for p in REPO.glob("ruff-*.toml")))
def test_every_table_exemption_still_fires(table: str) -> None:
    lint = tomllib.loads((REPO / table).read_text())["lint"]
    if "per-file-ignores" not in lint:
        return
    fired = _fired("--config", table)
    assert [e for e in _exemptions(lint) if e not in fired] == []
