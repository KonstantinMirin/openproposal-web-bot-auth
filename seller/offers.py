"""The real logic: reading an issued proposal and answering a buyer's `commit`.

Nothing here reads a header or a credential. Each function takes the frozen
caller that `resolve_caller` returned.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import rfc8785
from openproposal import LineItemStatuses, ProposalStatuses, dump

from demo_types.stack import AssentEntry, Commit, CommitResult
from shared.attribution import attributes
from shared.record import (
    WriteError,
    committed_entry,
    compose,
    digest_input,
    digest_of,
    line_items_of,
)

from .errors import OfferError
from .identity import Caller, ResolvedCaller
from .store import Store

#: The statuses a `commit` can name (§ 4.3.2).
COMMITTABLE = {LineItemStatuses.PUBLISHED, LineItemStatuses.UNDER_REVIEW}


def instant(moment: datetime) -> str:
    """A § 2.2 `Instant`."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _issued_to(store: Store, caller: Caller, proposal_id: str) -> dict[str, Any]:
    """The stored proposal, when it is issued to the caller's principal (§ 4.3)."""
    found = store.proposal(proposal_id)
    if (
        found is None
        or not isinstance(caller, ResolvedCaller)
        or found[0] != caller.principal.id
    ):
        # An issued proposal exists only for its buyer (§ 2.4 `not_found`).
        raise OfferError("not_found", f"no proposal {proposal_id} for this caller", retry="none")
    return found[1]


def full_representation(store: Store, caller: Caller, proposal_id: str) -> dict[str, Any]:
    """The Full Representation (§ 2.1) of an issued proposal, for its buyer only."""
    document = _issued_to(store, caller, proposal_id)
    assent = store.assent(proposal_id)
    return {**document, "assent": assent} if assent else document


def proposal_status(document: dict[str, Any]) -> str:
    """§ 4.3.3: the first rule that applies."""
    statuses = [i["status"] for i in line_items_of(document)]
    if all(s == "draft" for s in statuses):
        return ProposalStatuses.DRAFT
    if "under_review" in statuses:
        return ProposalStatuses.UNDER_REVIEW
    if any(s in ("draft", "published", "sold_out") for s in statuses):
        return ProposalStatuses.PUBLISHED
    if "agreed" in statuses:
        return ProposalStatuses.AGREED
    return ProposalStatuses.EXPIRED if "expired" in statuses else ProposalStatuses.WITHDRAWN


def _result(store: Store, proposal_id: str, idempotency_key: str) -> CommitResult:
    """§ 5.6.1: the buyer's entry, then each matching entry written after it."""
    entries = [AssentEntry.model_validate(e) for e in store.assent(proposal_id)]
    start = next(i for i, e in enumerate(entries)
                 if e.role == "commitment" and e.idempotency_key == idempotency_key)
    first = entries[start]
    later = [e for e in entries[start + 1:] if e.role != "commitment" and e.matches(first)]
    return CommitResult(entries=[first, *later])


def _live_names(assent: list[AssentEntry]) -> set[str]:
    """The line items a live `commitment` entry names (§ 4.1.2).

    A matching `withdrawal` or `decline` ends an entry. An accepted entry stays live:
    once a matching `acceptance` exists, nothing ends it.
    """
    names: set[str] = set()
    for i, entry in enumerate(assent):
        if entry.role == "commitment" and not any(
            e.role in ("withdrawal", "decline") and e.matches(entry) for e in assent[i + 1:]
        ):
            names.update(entry.line_item_ids)
    return names


def _checks(document: dict[str, Any], assent: list[AssentEntry], commit: Commit,
            now: datetime) -> tuple[dict[str, Any], bytes]:
    """The § 5.6.1 checks of a new `commit`. Returns the composed record and the digest input."""
    entry, version = commit.entry, document["version"]
    items = {i["line_item_id"]: i for i in line_items_of(document)}
    for name in entry.line_item_ids:
        if name not in items:
            raise OfferError("not_found", f"no line item {name}", retry="none", version=version)
    stamp = instant(now)
    window = document.get("offer_window") or {}
    if "end" in window and stamp > window["end"]:
        raise OfferError("expired", "offer_window.end has passed", retry="none", version=version)
    try:
        composed = compose(document, commit.writes)
    except WriteError as e:
        raise OfferError("validation", str(e), retry="none", version=version) from e
    composed_items = {i["line_item_id"]: i for i in line_items_of(composed)}
    for name in entry.line_item_ids:
        priced = committed_entry(composed_items[name])
        if priced is None:
            raise OfferError("validation", f"{name}: the commitment names no pricing[] entry",
                             retry="none", version=version)
        if "price_valid_until" in priced and stamp > priced["price_valid_until"]:
            raise OfferError("expired", f"{name}: price_valid_until has passed",
                             retry="none", version=version)
    # The seller keeps one version per proposal, so another version is stale (§ 4.1.3).
    if entry.version != version:
        raise OfferError("stale_version", f"the commit names version {entry.version}",
                         retry="refetch", version=version)
    for name in entry.line_item_ids:
        if items[name]["status"] not in COMMITTABLE:
            raise OfferError("not_committable", f"{name} is {items[name]['status']}",
                             retry="none", version=version)
    if "start" in window and stamp < window["start"]:
        raise OfferError("not_committable", "offer_window.start is in the future",
                         retry="same", version=version)
    if _live_names(assent) & set(entry.line_item_ids):
        raise OfferError("not_committable", "a live commitment already names a line item",
                         retry="same", version=version)
    data = digest_input(composed, entry.line_item_ids)
    if digest_of(data) != entry.record_digest:
        raise OfferError("record_mismatch", "record_digest differs from the seller's",
                         retry="refetch", version=version)
    return composed, data


def commit(store: Store, caller: Caller, proposal_id: str, commit: Commit,
           now: datetime | None = None) -> CommitResult:
    """Answers a `commit` (§ 5.6.1). This seller accepts every commit that passes the checks."""
    if not isinstance(caller, ResolvedCaller):
        raise OfferError("not_eligible", "a commit needs a buyer this seller knows", retry="none")
    now = now or datetime.now(UTC)
    canonical = rfc8785.dumps(dump(commit))
    key = commit.entry.idempotency_key
    rejection: OfferError | None = None
    with store.transaction():
        document = _issued_to(store, caller, proposal_id)

        # A replay returns the result as it now stands, and writes nothing (§ 5.6.1).
        processed = store.processed_commit(caller.principal.id, key)
        if processed is not None:
            if processed["canonical"] != canonical or processed["proposal_id"] != proposal_id:
                raise OfferError("idempotency_conflict", "the idempotency_key names another commit",
                                 retry="none", version=document["version"])
            if processed["errors"] is not None:
                raise OfferError.stored(processed["errors"])
            return _result(store, proposal_id, key)

        assent = [AssentEntry.model_validate(e) for e in store.assent(proposal_id)]
        try:
            composed, data = _checks(document, assent, commit, now)
        except OfferError as e:
            rejection = e
            if e.error["retry"] != "same":  # a rejection that is a stored result
                store.record_commit(caller.principal.id, key, proposal_id, canonical, e.stored_form())
        else:
            _accept(store, caller, document, composed, data, commit, now)
            store.record_commit(caller.principal.id, key, proposal_id, canonical)
    if rejection is not None:
        raise rejection
    return _result(store, proposal_id, key)


def _accept(store: Store, caller: ResolvedCaller, document: dict[str, Any],
            composed: dict[str, Any], data: bytes, commit: Commit, now: datetime) -> None:
    """Writes the buyer's entry and the seller's matching `acceptance` (§ 4.1.2)."""
    attributed = caller.authentication_method == "web_bot_auth" and attributes(
        caller.host, document["buyer"]["domain"], body_covered=caller.body_covered
    )
    store.append_assent(
        document["proposal_id"], commit.entry.wire(), principal_id=caller.principal.id,
        authentication_method=caller.authentication_method, evidence_id=caller.evidence_id,
        attributed=attributed,
    )
    acceptance = AssentEntry(
        role="acceptance", version=commit.entry.version, record_digest=commit.entry.record_digest,
        line_item_ids=list(commit.entry.line_item_ids), at=instant(now),
    )
    store.append_assent(document["proposal_id"], acceptance.wire())
    store.add_agreed_record(document["proposal_id"], acceptance.record_digest, data,
                            [commit.entry.wire(), acceptance.wire()])

    # The stored line items now hold the commit's writes, and they are agreed.
    stored = copy.deepcopy(document)
    composed_items = {i["line_item_id"]: i for i in line_items_of(composed)}
    for item in line_items_of(stored):
        name = item["line_item_id"]
        if name in commit.entry.line_item_ids:
            item.clear()
            item.update(composed_items[name], status=LineItemStatuses.AGREED)
    stored["status"] = proposal_status(stored)
    store.save_proposal(stored)
