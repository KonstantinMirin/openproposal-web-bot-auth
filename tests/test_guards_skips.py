"""Proof that a skipped test fails the unit suite (tests/conftest.py)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from tests._tools import run

CONFTEST = Path(__file__).resolve().parent / "conftest.py"


def _suite(tree: Path, test: str) -> int:
    tree.mkdir()
    shutil.copy(CONFTEST, tree)
    (tree / "test_planted.py").write_text(test)
    suite = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "."], cwd=tree)
    return suite.returncode


@pytest.mark.parametrize(
    "test",
    [
        "import pytest\n\n\ndef test_planted():\n    pytest.skip('planted')\n",
        "import pytest\n\n\n@pytest.mark.skip\ndef test_planted():\n    pass\n",
    ],
    ids=["skip-call", "skip-mark"],
)
def test_a_skip_fails_the_suite(tmp_path: Path, test: str) -> None:
    assert _suite(tmp_path / "suite", test) == pytest.ExitCode.TESTS_FAILED


def test_a_strict_xfail_does_not(tmp_path: Path) -> None:
    test = (
        "import pytest\n\n\n@pytest.mark.xfail(strict=True)\n"
        "def test_planted():\n    raise AssertionError\n"
    )
    assert _suite(tmp_path / "suite", test) == pytest.ExitCode.OK
