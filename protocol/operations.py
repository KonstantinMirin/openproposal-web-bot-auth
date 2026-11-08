"""The § 5.6.1 `commit` steps both parties run, over the generated types.

The generated `Commit`, `CommitResult`, and `AssentEntry` check each member, but
not the rules that tie members together. `check_commit` and `parse_result` add
those, so the seller and the buyer refuse the same documents. The buyer composes
with `compose_commit` and checks the answer with `check_result`; the seller
answers with `acceptance_for` and `result_for`, and builds the proposal it saves
with `agreed_document`. Each pair rule has one implementation, here.

The SDK's values are mutable. Nothing here assigns to one: each step builds
fresh values, and the raw JSON a caller passes is left as it was.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final

from openproposal import (
    AssentEntry,
    AssentEntryRoles,
    Commit,
    CommitResult,
    ErrorObject,
    LineItemStatuses,
    LineItemWrites,
    Proposal,
    dump,
)
from pydantic import BaseModel, ConfigDict, Field

from .record import compose, digest_input, digest_of, line_items_of, proposal_items
from .status import proposal_status
from .values import JsonObject, commitment_key, instant, matches, read_json

#: The validation context of the SDK's receive mode, in the form its `MODE_KEY`
#: documents: a closed object ignores the members it doesn't name.
RECEIVE: Final = {"openproposal_mode": "receive"}


class Rule(StrEnum):
    """A § 4.1.2 or § 5.6.1 rule the generated classes don't state."""

    COMMIT_ENTRY = "a Commit carries a commitment entry (§ 5.6.1)"
    WRITES_KEYS = "writes are keyed by exactly the line items the entry names (§ 5.6.1)"
    LINE_ITEMS = "an entry names at least one line item (§ 4.1.2)"
    GROUND = "ground is present on a decline entry and only there (§ 4.1.2)"
    ENTRIES = "a CommitResult holds at least one entry (§ 5.6.1)"
    FIRST_ENTRY = "the CommitResult doesn't start with the commit's entry (§ 5.6.1)"
    ACCEPTANCE = "the CommitResult holds no acceptance that matches the commit (§ 4.1.2)"
    DIGEST = "record_digest doesn't recompute from the agreed record (§ 4.1.1)"


class ProtocolViolation(ValueError):
    """A document the SDK accepts but § 4.1.2 or § 5.6.1 forbids."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule.value)
        self.rule = rule


class ResultMismatch(ProtocolViolation):
    """The seller's `CommitResult` doesn't answer the buyer's `commit`."""


class MissingCommitmentError(LookupError):
    """No `commitment` entry in `assent[]` carries the key a result was asked for."""


# ── Reading ────────────────────────────────────────────────────────────────


def _check_entry(entry: AssentEntry) -> None:
    if not entry.line_item_ids:
        raise ProtocolViolation(Rule.LINE_ITEMS)
    if (entry.role == AssentEntryRoles.DECLINE) != (entry.ground is not None):
        raise ProtocolViolation(Rule.GROUND)


def check_commit(commit: Commit) -> Commit:
    """The `commit` rules the generated `Commit` doesn't state; returns `commit`."""
    _check_entry(commit.entry)
    if commit.entry.role != AssentEntryRoles.COMMITMENT:
        raise ProtocolViolation(Rule.COMMIT_ENTRY)
    commitment_key(commit.entry)  # the generated class requires it; this narrows it
    if set(commit.writes) != set(commit.entry.line_item_ids):
        raise ProtocolViolation(Rule.WRITES_KEYS)
    return commit


def parse_commit(raw: bytes) -> Commit:
    """A request body as a `Commit` (§ 5.6.1), checked strictly.

    Raises `MalformedJsonError` for a body that isn't a JSON object in the
    RFC 8785 number domain (`protocol.values.read_json`), pydantic's
    `ValidationError` for one the SDK refuses, and `ProtocolViolation` for one
    it accepts but § 5.6.1 forbids.
    """
    read_json(raw)
    return check_commit(Commit.model_validate_json(raw))


def parse_result(raw: bytes) -> CommitResult:
    """A seller's answer as a `CommitResult`, read as a receiver (§ 5.6.1)."""
    read_json(raw)
    result = CommitResult.model_validate_json(raw, context=RECEIVE)
    if not result.entries:
        raise ProtocolViolation(Rule.ENTRIES)
    for entry in result.entries:
        _check_entry(entry)
    return result


class ErrorEnvelope(BaseModel):
    """The § 2.4 `errors[]` envelope, which the SDK generates no type for.

    § 2.4: "An ErrorObject is open", so each one is read as a receiver.
    """

    model_config = ConfigDict(frozen=True, strict=True, extra="ignore")

    errors: Annotated[list[ErrorObject], Field(min_length=1)]


def parse_errors(raw: bytes) -> list[ErrorObject]:
    """The `errors[]` of a rejection (§ 2.4)."""
    read_json(raw)
    return ErrorEnvelope.model_validate_json(raw, context=RECEIVE).errors


def is_stored_result(errors: Sequence[ErrorObject]) -> bool:
    """Whether a rejection is a stored result: a later `commit` with the same key gets it
    again (§ 5.6.1). An error with `retry: same` says the request may succeed as sent, so
    a rejection that holds one is not stored (§ 2.4)."""
    return all(error.retry != "same" for error in errors)


# ── The buyer's steps ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class ComposedCommit:
    """A `commit` and the digest input its entry's `record_digest` is over."""

    commit: Commit
    digest_input: bytes


def compose_commit(
    proposal: Proposal,
    raw: JsonObject,
    writes: Mapping[str, LineItemWrites],
    *,
    at: datetime,
    key: str,
) -> ComposedCommit:
    """The buyer's `commit` (§ 5.6.1) on `proposal`, whose raw JSON is `raw`.

    The entry names the line items `writes` is keyed by, in its order. The digest
    is over the composed raw JSON (§ 4.1.1), so that members the buyer's SDK
    doesn't know still count; `proposal` gives the version.
    """
    line_item_ids = list(writes)
    data = digest_input(compose(raw, writes), line_item_ids)
    entry = AssentEntry(
        role=AssentEntryRoles.COMMITMENT,
        version=proposal.version,
        record_digest=digest_of(data),
        line_item_ids=line_item_ids,
        at=instant(at),
        idempotency_key=key,
    )
    commit = Commit(entry=entry, writes=dict(writes))
    return ComposedCommit(check_commit(commit), data)


def check_result(commit: Commit, result: CommitResult, digest_input: bytes) -> AssentEntry:
    """The buyer's check of the seller's answer (§ 4.1.2, § 5.6.1); returns the acceptance.

    The first entry is the commit's own, a later acceptance matches it, and its
    `record_digest` recomputes from the digest input the buyer kept. Raises
    `ResultMismatch` with the rule that failed.
    """
    if dump(result.entries[0]) != dump(commit.entry):
        raise ResultMismatch(Rule.FIRST_ENTRY)
    acceptance = next(
        (
            e
            for e in result.entries[1:]
            if e.role == AssentEntryRoles.ACCEPTANCE and matches(e, commit.entry)
        ),
        None,
    )
    if acceptance is None:
        raise ResultMismatch(Rule.ACCEPTANCE)
    if digest_of(digest_input) != acceptance.record_digest:
        raise ResultMismatch(Rule.DIGEST)
    return acceptance


# ── The seller's steps ─────────────────────────────────────────────────────


def acceptance_for(entry: AssentEntry, at: datetime) -> AssentEntry:
    """The seller's `acceptance` that matches `entry` (§ 4.1.2)."""
    return AssentEntry(
        role=AssentEntryRoles.ACCEPTANCE,
        version=entry.version,
        record_digest=entry.record_digest,
        line_item_ids=list(entry.line_item_ids),
        at=instant(at),
    )


def result_for(assent: Sequence[AssentEntry], key: str) -> CommitResult:
    """§ 5.6.1: the buyer's entry with `key`, then each matching entry written after it."""
    start = next(
        (
            i
            for i, e in enumerate(assent)
            if e.role == AssentEntryRoles.COMMITMENT and e.idempotency_key == key
        ),
        None,
    )
    if start is None:
        raise MissingCommitmentError(key)
    first = assent[start]
    later = [
        e
        for e in assent[start + 1 :]
        if e.role != AssentEntryRoles.COMMITMENT and matches(e, first)
    ]
    return CommitResult(entries=[first, *later])


def agreed_document(
    document: JsonObject, composed_items: Mapping[str, JsonObject], line_item_ids: Sequence[str]
) -> JsonObject:
    """The proposal once a commit to `line_item_ids` is agreed, as a new document.

    Each named line item is its composed form from `composed_items`, the buyer's
    writes applied (§ 4.1.1), with `status: agreed`. The proposal's `status`
    follows from its line items' statuses (§ 4.3.3). `document` and
    `composed_items` are left as they were.
    """
    agreed = copy.deepcopy(document)
    for item in line_items_of(agreed):
        name = str(item["line_item_id"])
        if name in line_item_ids:
            composed = copy.deepcopy(composed_items[name])
            item.clear()
            item.update(composed, status=LineItemStatuses.AGREED)
    items = proposal_items(Proposal.model_validate(agreed))
    agreed["status"] = proposal_status([item.status for item in items.values()])
    return agreed
