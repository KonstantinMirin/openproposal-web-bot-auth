"""Running this venv's own tools (ast-grep, lint-imports, ruff, pytest) from a guard test."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path


def tool(name: str) -> Path:
    """The console script `name` installed beside this interpreter."""
    return Path(sys.executable).parent / name


def run(
    args: list[str], *, cwd: Path, env: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Runs a tool and captures its output; the caller judges the exit code."""
    # Not untrusted input: every argument is a venv tool or a path the test built.
    return subprocess.run(  # noqa: S603
        args, cwd=cwd, env=env, capture_output=True, text=True, check=False
    )
