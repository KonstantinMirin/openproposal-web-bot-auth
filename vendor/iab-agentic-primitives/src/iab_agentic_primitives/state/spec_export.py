"""Export the canonical transition tables to ``spec/jsonschema/state/``.

The exported JSON (JavaScript Object Notation) files are the normative,
language-neutral artifacts for the lifecycle machines — non-Python
implementers consume the transition tables and the reconciliation
equivalence tables without importing this package. The generated files are
checked in; ``tests/test_state_spec_drift.py`` fails if they ever diverge
from the machines.

Usage:

    uv run python -m iab_agentic_primitives.state.spec_export
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .change_request_lifecycle import CHANGE_REQUEST_LIFECYCLE
from .deal_lifecycle import DEAL_LIFECYCLE
from .order_lifecycle import ORDER_LIFECYCLE
from .reconciliation import AUTHORITATIVE_SIDE, comparison_table

STATE_SPEC_DIR = Path(__file__).parents[3] / "spec" / "jsonschema" / "state"

_LIFECYCLES = (DEAL_LIFECYCLE, ORDER_LIFECYCLE, CHANGE_REQUEST_LIFECYCLE)


def _reconciliation_spec() -> dict[str, Any]:
    """The FD-8 reconciliation contract: authority rule + outcome matrices.

    ``outcomes[lifecycle][buyer_status][seller_status]`` is the
    classification a conforming implementation must produce for that
    (buyer-side, seller-side) status pair.
    """
    outcomes: dict[str, dict[str, dict[str, str]]] = {}
    for machine in _LIFECYCLES:
        table = comparison_table(machine)
        matrix: dict[str, dict[str, str]] = {}
        for (buyer, seller), outcome in table.items():
            matrix.setdefault(buyer, {})[seller] = outcome.value
        outcomes[machine.name] = matrix
    return {
        "name": "reconciliation",
        "description": (
            "FD-8 cross-agent state reconciliation: both agents track state "
            "independently; the seller's record is authoritative for every "
            "shared lifecycle; divergence is reported, not silently resolved."
        ),
        "authoritative_side": {name: side.value for name, side in AUTHORITATIVE_SIDE.items()},
        "outcomes": outcomes,
    }


def state_spec_documents() -> dict[str, dict[str, Any]]:
    """All spec documents, keyed by file stem."""
    docs: dict[str, dict[str, Any]] = {
        "DealLifecycle": DEAL_LIFECYCLE.to_spec_dict(),
        "OrderLifecycle": ORDER_LIFECYCLE.to_spec_dict(),
        "ChangeRequestLifecycle": CHANGE_REQUEST_LIFECYCLE.to_spec_dict(),
        "Reconciliation": _reconciliation_spec(),
    }
    return docs


def render_document(document: dict[str, Any]) -> str:
    """Render a spec document as stable, diff-friendly JSON text."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main() -> None:
    STATE_SPEC_DIR.mkdir(parents=True, exist_ok=True)
    for stem, document in state_spec_documents().items():
        path = STATE_SPEC_DIR / f"{stem}.json"
        path.write_text(render_document(document))
        print(f"wrote {path.relative_to(STATE_SPEC_DIR.parents[2])}")


if __name__ == "__main__":
    main()


__all__ = ["STATE_SPEC_DIR", "main", "render_document", "state_spec_documents"]
