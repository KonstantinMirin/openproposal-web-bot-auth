"""The real logic: reading an issued proposal and answering a buyer's `commit`.

Nothing here reads a header or a credential. Each function takes the frozen
caller that the identity boundary (seller/boundary.py) returned. Decisions read the generated types,
parsed once from the stored raw JSON; the raw JSON stays the digest input.
"""

from __future__ import annotations

from datetime import UTC, datetime

from openproposal import (
    AssentEntry,
    AssentEntryRoles,
    Commit,
    CommitResult,
    LineItemStatus,
    LineItemStatuses,
    Proposal,
    ProposalStatus,
    ProposalStatuses,
    dump,
)
from pydantic import ValidationError

from protocol.operations import ProtocolViolation, acceptance_for, result_for
from protocol.operations import parse_commit as parse_commit_body
from protocol.record import (
    WriteError,
    canonical,
    committed_entry,
    compose,
    digest_input,
    digest_of,
    items_by_id,
    line_items_of,
    proposal_items,
)
from protocol.values import JsonObject, JsonValue, commitment_key, instant, matches

from .caller import Caller, ResolvedCaller
from .errors import OfferError
from .ports import OfferRepository, OfferStore, StoredProposal

#: The statuses a `commit` can name (§ 4.3.2).
COMMITTABLE: frozenset[LineItemStatus] = frozenset(
    {LineItemStatuses.PUBLISHED, LineItemStatuses.UNDER_REVIEW}
)


def parse_commit(body: bytes) -> Commit:
    """The request body as a `Commit` (§ 5.6.1), or a `validation` error (§ 2.4)."""
    try:
        return parse_commit_body(body)
    except ValidationError as e:
        detail = "; ".join(f"{'/'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors())
        raise OfferError("validation", detail or "the body is not a Commit", retry="none") from e
    except ProtocolViolation as e:
        raise OfferError("validation", str(e), retry="none") from e


def _issued_to(store: OfferRepository, caller: Caller, proposal_id: str) -> StoredProposal:
    """The stored proposal, when it is issued to the caller's principal (§ 4.3)."""
    found = store.issued(proposal_id)
    if (
        found is None
        or not isinstance(caller, ResolvedCaller)
        or found.buyer_principal_id != caller.principal.id
    ):
        # An issued proposal exists only for its buyer (§ 2.4 `not_found`).
        raise OfferError("not_found", f"no proposal {proposal_id} for this caller", retry="none")
    return found


def full_representation(store: OfferRepository, caller: Caller, proposal_id: str) -> JsonObject:
    """The Full Representation (§ 2.1) of an issued proposal, for its buyer only."""
    document = _issued_to(store, caller, proposal_id).document
    assent: list[JsonValue] = [dump(e) for e in store.assent(proposal_id)]
    return {**document, "assent": assent} if assent else document


def proposal_status(statuses: list[LineItemStatus]) -> ProposalStatus:
    """§ 4.3.3: the proposal's status from its line items', by the first rule that applies."""
    if all(s == LineItemStatuses.DRAFT for s in statuses):
        return ProposalStatuses.DRAFT
    if LineItemStatuses.UNDER_REVIEW in statuses:
        return ProposalStatuses.UNDER_REVIEW
    open_statuses = (LineItemStatuses.DRAFT, LineItemStatuses.PUBLISHED, LineItemStatuses.SOLD_OUT)
    if any(s in open_statuses for s in statuses):
        return ProposalStatuses.PUBLISHED
    if LineItemStatuses.AGREED in statuses:
        return ProposalStatuses.AGREED
    if LineItemStatuses.EXPIRED in statuses:
        return ProposalStatuses.EXPIRED
    return ProposalStatuses.WITHDRAWN


def _result(store: OfferRepository, proposal_id: str, key: str) -> CommitResult:
    """§ 5.6.1: the buyer's entry, then each matching entry written after it."""
    return result_for(store.assent(proposal_id), key)


def _live_names(assent: list[AssentEntry]) -> set[str]:
    """The line items a live `commitment` entry names (§ 4.1.2).

    A matching `withdrawal` or `decline` ends an entry. An accepted entry stays live:
    once a matching `acceptance` exists, nothing ends it.
    """
    ending = (AssentEntryRoles.WITHDRAWAL, AssentEntryRoles.DECLINE)
    names: set[str] = set()
    for i, entry in enumerate(assent):
        if entry.role == AssentEntryRoles.COMMITMENT and not any(
            e.role in ending and matches(e, entry) for e in assent[i + 1 :]
        ):
            names.update(entry.line_item_ids)
    return names


def _checks(
    document: JsonObject, assent: list[AssentEntry], commit: Commit, now: datetime
) -> tuple[JsonObject, bytes]:
    """The § 5.6.1 checks of a new `commit`. Returns the composed record and the digest input.

    The order follows § 5.6.1: "The rejection MUST carry `expired` when
    `offer_window.end` or `price_valid_until` has passed, `stale_version` when the
    `commit` is stale, `not_committable` when a ground of that code applies (§ 2.4),
    and otherwise `record_mismatch`, so the buyer can fetch it again."
    A commit that names no such line item, or writes outside § 3.4, fits none of
    those codes; it is checked after staleness, so a stale commit always gets
    `stale_version` and is told to fetch again.
    """
    proposal = Proposal.model_validate(document)
    entry, version, window = commit.entry, proposal.version, proposal.offer_window
    items, raw_items = proposal_items(proposal), items_by_id(document)
    stamp = instant(now)

    # 1. expired: offer_window.end, then each committed entry's price_valid_until.
    if window is not None and stamp > window.end:
        raise OfferError("expired", "offer_window.end has passed", retry="none", version=version)
    for name in entry.line_item_ids:
        if name in raw_items:
            commitment = dump(commit.writes[name].commitment)
            priced = committed_entry({**raw_items[name], "commitment": commitment})
            valid_until = priced.get("price_valid_until", stamp) if priced is not None else stamp
            if isinstance(valid_until, str) and stamp > valid_until:
                raise OfferError(
                    "expired",
                    f"{name}: price_valid_until has passed",
                    retry="none",
                    version=version,
                )

    # 2. stale_version. The seller keeps one version per proposal, so another is stale (§ 4.1.3).
    if entry.version != version:
        raise OfferError(
            "stale_version",
            f"the commit names version {entry.version}",
            retry="refetch",
            version=version,
        )

    # The commit names line items of this version and writes only § 3.4 paths.
    for name in entry.line_item_ids:
        if name not in items:
            raise OfferError("not_found", f"no line item {name}", retry="none", version=version)
    try:
        composed = compose(document, commit.writes)
    except WriteError as e:
        raise OfferError("validation", str(e), retry="none", version=version) from e
    composed_items = items_by_id(composed)
    for name in entry.line_item_ids:
        if committed_entry(composed_items[name]) is None:
            raise OfferError(
                "validation",
                f"{name}: the commitment names no pricing[] entry",
                retry="none",
                version=version,
            )

    # 3. not_committable.
    for name in entry.line_item_ids:
        if items[name].status not in COMMITTABLE:
            raise OfferError(
                "not_committable",
                f"{name} is {items[name].status}",
                retry="none",
                version=version,
            )
    if window is not None and stamp < window.start:
        raise OfferError(
            "not_committable", "offer_window.start is in the future", retry="same", version=version
        )
    if _live_names(assent) & set(entry.line_item_ids):
        raise OfferError(
            "not_committable",
            "a live commitment already names a line item",
            retry="same",
            version=version,
        )

    # 4. Otherwise record_mismatch.
    data = digest_input(composed, entry.line_item_ids)
    if digest_of(data) != entry.record_digest:
        raise OfferError(
            "record_mismatch",
            "record_digest differs from the seller's",
            retry="refetch",
            version=version,
        )
    return composed, data


def commit(
    store: OfferStore,
    caller: Caller,
    proposal_id: str,
    commit: Commit,
    now: datetime | None = None,
) -> CommitResult:
    """Answers a `commit` (§ 5.6.1). This seller accepts every commit that passes the checks."""
    if not isinstance(caller, ResolvedCaller):
        raise OfferError("not_eligible", "a commit needs a buyer this seller knows", retry="none")
    now = now or datetime.now(UTC)
    request = canonical(dump(commit))
    key = commitment_key(commit.entry)
    rejection: OfferError | None = None
    with store.transaction():
        issued = _issued_to(store, caller, proposal_id)
        document = issued.document

        # A replay returns the result as it now stands, and writes nothing (§ 5.6.1).
        processed = store.processed(caller.principal.id, key)
        if processed is not None:
            if processed.canonical != request or processed.proposal_id != proposal_id:
                raise OfferError(
                    "idempotency_conflict",
                    "the idempotency_key names another commit",
                    retry="none",
                    version=Proposal.model_validate(document).version,
                )
            if processed.error is not None:
                raise OfferError.stored(processed.error)
            return _result(store, proposal_id, key)

        assent = store.assent(proposal_id)
        try:
            composed, data = _checks(document, assent, commit, now)
        except OfferError as e:
            rejection = e
            if e.error["retry"] != "same":  # a rejection that is a stored result
                store.record(caller.principal.id, key, proposal_id, request, e.error_object())
        else:
            _accept(store, caller, issued, composed, data, commit, now)
            store.record(caller.principal.id, key, proposal_id, request, None)
    if rejection is not None:
        raise rejection
    return _result(store, proposal_id, key)


def _accept(
    store: OfferRepository,
    caller: ResolvedCaller,
    issued: StoredProposal,
    composed: JsonObject,
    data: bytes,
    commit: Commit,
    now: datetime,
) -> None:
    """Writes the buyer's entry and the seller's matching `acceptance` (§ 4.1.2)."""
    # The caller goes to storage with the entry, which keeps how it authenticated; its
    # credential is unread here.
    document, proposal_id = issued.document, issued.proposal_id
    store.append_assent(proposal_id, commit.entry, caller)
    acceptance = acceptance_for(commit.entry, now)
    store.append_assent(proposal_id, acceptance, None)
    store.save_agreed(proposal_id, acceptance.record_digest, data, [commit.entry, acceptance])

    # The stored line items now hold the commit's writes, and they are agreed. `document`
    # is this transaction's own copy, read from storage, so it is updated in place.
    composed_items = items_by_id(composed)
    for item in line_items_of(document):
        name = str(item["line_item_id"])
        if name in commit.entry.line_item_ids:
            item.clear()
            item.update(composed_items[name], status=LineItemStatuses.AGREED)
    agreed = proposal_items(Proposal.model_validate(document))
    document["status"] = proposal_status([i.status for i in agreed.values()])
    store.save_proposal(issued)
