"""What a replayed `idempotency_key` gets (§ 5.6.1)."""

from __future__ import annotations

from openproposal import CommitResult, Proposal

from protocol.operations import result_for
from seller.errors import Rejected
from seller.ports import OfferStore, StoredProposal


def replay(
    store: OfferStore, principal_id: str, key: str, canonical: bytes, issued: StoredProposal
) -> CommitResult | Rejected | None:
    """The answer to a commit this seller already processed, or None for a new one.

    A replay writes nothing. The same key with another commit, or on another
    proposal, is `idempotency_conflict`. A stored rejection is returned as
    stored. Otherwise the result is returned as it now stands.
    """
    processed = store.processed(principal_id, key)
    if processed is None:
        return None
    proposal_id = issued.proposal_id
    if processed.canonical != canonical or processed.proposal_id != proposal_id:
        version = Proposal.model_validate(issued.document).version
        return Rejected.of(
            "idempotency_conflict", "the idempotency_key names another commit", version=version
        )
    if processed.error is not None:
        return Rejected(processed.error)
    return result_for(store.assent(proposal_id), key)
