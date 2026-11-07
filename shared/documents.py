"""Reading OpenProposal documents carried as YAML (§ 4.1.1: YAML 1.2, core schema)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


def load_yaml(path: str | Path) -> dict[str, Any]:
    """One YAML 1.2 document as plain JSON values. A duplicate key is an error."""
    yaml = YAML(typ="safe", pure=True)
    return yaml.load(Path(path).read_text(encoding="utf-8"))
