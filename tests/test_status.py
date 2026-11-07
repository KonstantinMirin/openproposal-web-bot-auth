"""§ 4.3.3, Proposal status: the first of the spec's five rules that applies.

`protocol.status.proposal_status` is the rule both parties share. Each row is a
set of line item statuses and the status the rule names, so every rule, and
the order between them, is checked once.
"""

from __future__ import annotations

import pytest
from openproposal import LineItemStatus, ProposalStatus

from protocol.status import COMMITTABLE, proposal_status

ROWS: list[tuple[str, list[LineItemStatus], ProposalStatus]] = [
    ("1. every line item is draft", ["draft", "draft"], "draft"),
    ("2. any line item is under_review", ["draft", "under_review", "agreed"], "under_review"),
    ("3. any is draft, published, or sold_out", ["sold_out", "agreed"], "published"),
    ("3. published beside agreed", ["published", "agreed"], "published"),
    ("4. any line item is agreed", ["agreed", "expired", "withdrawn"], "agreed"),
    ("5. otherwise expired when any is", ["withdrawn", "expired"], "expired"),
    ("5. else withdrawn", ["withdrawn"], "withdrawn"),
]


@pytest.mark.parametrize(("statuses", "status"), [r[1:] for r in ROWS], ids=[r[0] for r in ROWS])
def test_the_first_rule_that_applies_names_the_status(
    statuses: list[LineItemStatus], status: ProposalStatus
) -> None:
    assert proposal_status(statuses) == status


def test_a_commit_can_name_a_published_or_under_review_line_item_only() -> None:
    # § 4.3.2: `commit` moves a published or under_review line item to agreed.
    assert frozenset({"published", "under_review"}) == COMMITTABLE
