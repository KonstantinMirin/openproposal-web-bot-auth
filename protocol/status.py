"""Line item and proposal statuses (§ 4.3.2, § 4.3.3)."""

from __future__ import annotations

from collections.abc import Sequence

from openproposal import LineItemStatus, LineItemStatuses, ProposalStatus, ProposalStatuses

#: The statuses a `commit` can name (§ 4.3.2).
COMMITTABLE: frozenset[LineItemStatus] = frozenset(
    {LineItemStatuses.PUBLISHED, LineItemStatuses.UNDER_REVIEW}
)

_OPEN: frozenset[LineItemStatus] = frozenset(
    {LineItemStatuses.DRAFT, LineItemStatuses.PUBLISHED, LineItemStatuses.SOLD_OUT}
)


def proposal_status(statuses: Sequence[LineItemStatus]) -> ProposalStatus:
    """§ 4.3.3: the proposal's status from its line items', by the first rule that applies."""
    if all(s == LineItemStatuses.DRAFT for s in statuses):
        return ProposalStatuses.DRAFT
    if LineItemStatuses.UNDER_REVIEW in statuses:
        return ProposalStatuses.UNDER_REVIEW
    if any(s in _OPEN for s in statuses):
        return ProposalStatuses.PUBLISHED
    if LineItemStatuses.AGREED in statuses:
        return ProposalStatuses.AGREED
    if LineItemStatuses.EXPIRED in statuses:
        return ProposalStatuses.EXPIRED
    return ProposalStatuses.WITHDRAWN
