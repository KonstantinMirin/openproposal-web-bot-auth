"""Answering a buyer's `commit` (§ 5.6.1). This seller accepts every commit that passes."""

from __future__ import annotations

from datetime import datetime

from openproposal import Commit, CommitResult, dump

from protocol.operations import acceptance_for, agreed_document, result_for
from protocol.values import canonical, commitment_key
from seller.caller import Caller, ResolvedCaller
from seller.errors import Rejected
from seller.ports import OfferStore, StoredProposal

from .checks import Accepted, CheckContext, decide
from .ledger import replay
from .reading import issued_to, not_found


def answer_commit(
    store: OfferStore, caller: Caller, proposal_id: str, request: Commit, now: datetime
) -> CommitResult | Rejected:
    """The answer to `request`, decided and stored in one transaction, and returned.

    In order: the caller must be a principal this seller knows; a replayed key
    gets its stored answer; otherwise the checks decide. An acceptance writes
    the buyer's entry, the seller's matching `acceptance`, and the agreed
    record. A rejection whose `retry` isn't `same` is a stored result.
    """
    if not isinstance(caller, ResolvedCaller):
        return Rejected.of("not_eligible", "a commit needs a buyer this seller knows")
    principal_id, key = caller.principal.id, commitment_key(request.entry)
    request_bytes = canonical(dump(request))
    with store.transaction():
        issued = issued_to(store, caller, proposal_id)
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
        _agree(store, caller, issued, ctx, decision)
        store.record(principal_id, key, proposal_id, request_bytes, None)
        return result_for(store.assent(proposal_id), key)


def _agree(
    store: OfferStore,
    caller: ResolvedCaller,
    issued: StoredProposal,
    ctx: CheckContext,
    accepted: Accepted,
) -> None:
    """Writes the buyer's entry, the seller's matching `acceptance`, the agreed record, and
    the agreed proposal: a new document, so `issued`, which the checks read, stays as it was."""
    entry, proposal_id = ctx.request.entry, issued.proposal_id
    # The caller goes to storage with the entry, which keeps how it authenticated; its
    # credential is unread here.
    store.append_assent(proposal_id, entry, caller)
    acceptance = acceptance_for(entry, ctx.now)
    store.append_assent(proposal_id, acceptance, None)
    store.save_agreed(
        proposal_id, acceptance.record_digest, accepted.composed.digest_input, [entry, acceptance]
    )
    agreed = agreed_document(issued.document, accepted.composed.items, entry.line_item_ids)
    store.save_proposal(StoredProposal(issued.buyer_principal_id, agreed))
