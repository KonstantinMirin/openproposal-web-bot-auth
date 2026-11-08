"""Answering a buyer's `commit` (§ 5.6.1). This seller accepts every commit that passes."""

from __future__ import annotations

from datetime import datetime

from openproposal import Commit, CommitResult, dump

from protocol.operations import acceptance_for, agreed_document, result_for
from protocol.values import canonical, commitment_key
from seller.errors import Rejected
from seller.ports import EntryWriter, OfferStore, StoredProposal

from .checks import Accepted, CheckContext, decide
from .ledger import replay
from .reading import issued_to, not_found


def answer_commit(
    store: OfferStore,
    writer: EntryWriter | None,
    proposal_id: str,
    request: Commit,
    now: datetime,
) -> CommitResult | Rejected:
    """The answer to `request`, decided and stored in one transaction, and returned.

    `writer` writes the caller's entries, None for a caller with no principal.
    Only its principal id decides; the writer keeps the buyer's entry with what
    the boundary confirmed, which the offer logic never sees.

    In order: the caller must be a principal this seller knows; a replayed key
    gets its stored answer; otherwise the checks decide. An acceptance writes
    the buyer's entry, the seller's matching `acceptance`, and the agreed
    record. A rejection whose `retry` isn't `same` is a stored result.
    """
    if writer is None:
        return Rejected.of("not_eligible", "a commit needs a buyer this seller knows")
    principal_id, key = writer.principal_id, commitment_key(request.entry)
    request_bytes = canonical(dump(request))
    with store.transaction():
        issued = issued_to(store, principal_id, proposal_id)
        if issued is None:
            return not_found(proposal_id)
        replayed = replay(store, principal_id, key, request_bytes, issued)
        if replayed is not None:
            return replayed
        ctx = CheckContext.of(issued.document, store.assent(proposal_id), request, now)
        decision = decide(ctx)
        if isinstance(decision, Rejected):
            if decision.stored:
                store.record(principal_id, key, proposal_id, request_bytes, decision.error)
            return decision
        _agree(store, writer, issued, ctx, decision)
        store.record(principal_id, key, proposal_id, request_bytes, None)
        return result_for(store.assent(proposal_id), key)


def _agree(
    store: OfferStore,
    writer: EntryWriter,
    issued: StoredProposal,
    ctx: CheckContext,
    accepted: Accepted,
) -> None:
    """Writes the buyer's entry, the seller's matching `acceptance`, the agreed record, and
    the agreed proposal: a new document, so `issued`, which the checks read, stays as it was.

    The buyer's entry is about the issued record, so a signature attributes it to that
    record's buyer party (§ 4.1.2), whatever the principal's records say now."""
    entry, proposal_id = ctx.request.entry, issued.proposal_id
    writer.append(proposal_id, entry, record_buyer=ctx.record_buyer)
    acceptance = acceptance_for(entry, ctx.now)
    store.append_own_entry(proposal_id, acceptance)
    store.save_agreed(
        proposal_id, acceptance.record_digest, accepted.composed.digest_input, [entry, acceptance]
    )
    agreed = agreed_document(issued.document, accepted.composed.items, entry.line_item_ids)
    store.save_proposal(StoredProposal(issued.buyer_principal_id, agreed))
