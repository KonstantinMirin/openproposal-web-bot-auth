"""The vendored SDK is the recorded one, and it accepts every demo document strictly.

vendor/openproposal-sdk/pyproject.toml records where the SDK comes from.

This is the variant check: if a later lock separates the as-written and
proposed variants on the demo's documents, these validations fail on re-vendoring.
"""

from __future__ import annotations

import copy
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import openproposal
import pytest
from openproposal import LineItem, LineItemWrites, Proposal

from protocol.operations import acceptance_for, compose_commit
from protocol.record import compose, line_items_of
from tests._tools import PLAN, plan_writes, seed_document

REPO = Path(__file__).resolve().parent.parent
RECORDED = tomllib.loads((REPO / "vendor" / "openproposal-sdk" / "pyproject.toml").read_text())
NAMED = ["business-daily-display"]
#: The schema tree the vendored types match (the with-our-stack lock, as-written).
SCHEMA_RELEASE = "fbab39049a573adb36643a6f5e0f2f821cdd91b94ed12ed82eaf6887d30611ff"


def test_the_vendored_sdk_is_the_recorded_one() -> None:
    sdk = RECORDED["tool"]["openproposal-sdk"]
    assert openproposal.LOCK == sdk["lock"] == "with-our-stack"
    assert openproposal.VARIANT == sdk["variant"] == "as-written"
    assert openproposal.SCHEMA_RELEASE == sdk["schema-release"] == SCHEMA_RELEASE
    version = RECORDED["project"]["version"]
    assert version == f"0.0.0+{sdk['commit'][:7]}"


def test_the_issued_seed_proposal_validates_strictly() -> None:
    issued = seed_document()
    Proposal.model_validate(issued)
    for item in line_items_of(issued):
        LineItem.model_validate(item)


@pytest.mark.parametrize("name", sorted(PLAN))
def test_each_plan_entry_validates_strictly(name: str) -> None:
    LineItemWrites.model_validate(PLAN[name])


def test_the_composed_and_agreed_documents_validate_strictly() -> None:
    issued = seed_document()
    writes = plan_writes(*NAMED)
    composed = compose(issued, writes)
    Proposal.model_validate(composed)

    now = datetime(2027, 1, 1, tzinfo=UTC)
    commit = compose_commit(Proposal.model_validate(issued), issued, writes, at=now, key="k-1")
    agreed = copy.deepcopy(composed)
    for item in line_items_of(agreed):
        if item["line_item_id"] in NAMED:
            item["status"] = "agreed"
    # The other line item is still published, so the proposal stays published (§ 4.3.3).
    entry = commit.commit.entry
    agreed["assent"] = [openproposal.dump(entry), openproposal.dump(acceptance_for(entry, now))]
    Proposal.model_validate(agreed)
