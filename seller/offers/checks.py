"""The § 5.6.1 checks of a new `commit`, as an ordered list of named steps.

§ 5.6.1: "The rejection MUST carry `expired` when `offer_window.end` or
`price_valid_until` has passed, `stale_version` when the `commit` is stale,
`not_committable` when a ground of that code applies (§ 2.4), and otherwise
`record_mismatch`, so the buyer can fetch it again."

A commit that names no line item of this version, or writes outside § 3.4,
fits none of those codes. It is checked after staleness, so a stale commit
always gets `stale_version` and is told to fetch again, and before the
`not_committable` grounds, which read the composed record.

`decide` runs `BEFORE`, then composes the record once, then runs `AFTER` over
it. The first check that rejects decides; otherwise the commit is `Accepted`
with the composed record and its digest input.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from openproposal import (
    AssentEntry,
    AssentEntryRoles,
    Commit,
    ErrorObjectCode,
    ErrorObjectRetry,
    LineItem,
    Proposal,
    dump,
)

from protocol.record import (
    WriteError,
    committed_entry,
    compose,
    digest_input,
    digest_of,
    items_by_id,
    proposal_items,
)
from protocol.status import COMMITTABLE
from protocol.values import JsonObject, instant, matches
from seller.errors import Rejected


@dataclass(frozen=True)
class CheckContext:
    """What every check reads: the issued proposal, its assent log, the commit, and now."""

    raw: JsonObject
    proposal: Proposal
    items: Mapping[str, LineItem]
    assent: tuple[AssentEntry, ...]
    request: Commit
    now: datetime

    @classmethod
    def of(
        cls, raw: JsonObject, assent: list[AssentEntry], request: Commit, now: datetime
    ) -> CheckContext:
        proposal = Proposal.model_validate(raw)
        return cls(raw, proposal, proposal_items(proposal), tuple(assent), request, now)

    @property
    def version(self) -> int:
        return self.proposal.version

    @property
    def record_buyer(self) -> str | None:
        """The `buyer.domain` the issued record names (§ 4.3): the party the buyer's entry
        is about."""
        buyer = self.proposal.buyer
        return None if buyer is None else buyer.domain

    @property
    def stamp(self) -> str:
        """Now, as a § 2.2 `Instant`, which orders like the instants it is compared with."""
        return instant(self.now)

    @property
    def names(self) -> list[str]:
        return list(self.request.entry.line_item_ids)

    def reject(
        self, code: ErrorObjectCode, detail: str, *, retry: ErrorObjectRetry = "none"
    ) -> Rejected:
        return Rejected.of(code, detail, retry=retry, version=self.version)


@dataclass(frozen=True)
class Composed:
    """The composed record (§ 4.1.1) and its digest input, built once."""

    document: JsonObject
    items: Mapping[str, JsonObject]
    digest_input: bytes


@dataclass(frozen=True)
class Accepted:
    """The commit passed every check, over this composed record."""

    composed: Composed


Check = Callable[[CheckContext], Rejected | None]
ComposedCheck = Callable[[CheckContext, Composed], Rejected | None]


# 1. expired


def window_ended(ctx: CheckContext) -> Rejected | None:
    window = ctx.proposal.offer_window
    if window is not None and ctx.stamp > window.end:
        return ctx.reject("expired", "offer_window.end has passed")
    return None


def _price_valid_until(ctx: CheckContext, name: str) -> str | None:
    """The `price_valid_until` of the pricing entry the commit's commitment names."""
    raw_item = items_by_id(ctx.raw).get(name)
    if raw_item is None:
        return None
    commitment = dump(ctx.request.writes[name].commitment)
    priced = committed_entry({**raw_item, "commitment": commitment})
    valid_until = None if priced is None else priced.get("price_valid_until")
    return valid_until if isinstance(valid_until, str) else None


def price_expired(ctx: CheckContext) -> Rejected | None:
    for name in ctx.names:
        valid_until = _price_valid_until(ctx, name)
        if valid_until is not None and ctx.stamp > valid_until:
            return ctx.reject("expired", f"{name}: price_valid_until has passed")
    return None


# 2. stale_version. The seller keeps one version per proposal, so another is stale (§ 4.1.3).


def stale(ctx: CheckContext) -> Rejected | None:
    version = ctx.request.entry.version
    if version != ctx.version:
        return ctx.reject("stale_version", f"the commit names version {version}", retry="refetch")
    return None


# The commit names line items of this version, and writes only § 3.4 paths.


def names_known(ctx: CheckContext) -> Rejected | None:
    unknown = [name for name in ctx.names if name not in ctx.items]
    return ctx.reject("not_found", f"no line item {unknown[0]}") if unknown else None


def composed(ctx: CheckContext) -> Composed | Rejected:
    """The composed record, or `validation` when the writes break § 3.4 or name no price."""
    try:
        document = compose(ctx.raw, ctx.request.writes)
    except WriteError as e:
        return ctx.reject("validation", str(e))
    items = items_by_id(document)
    for name in ctx.names:
        if committed_entry(items[name]) is None:
            return ctx.reject("validation", f"{name}: the commitment names no pricing[] entry")
    return Composed(document, items, digest_input(document, ctx.names))


# 3. not_committable


def status_committable(ctx: CheckContext, _composed: Composed) -> Rejected | None:
    for name in ctx.names:
        status = ctx.items[name].status
        if status not in COMMITTABLE:
            return ctx.reject("not_committable", f"{name} is {status}")
    return None


def window_open(ctx: CheckContext, _composed: Composed) -> Rejected | None:
    window = ctx.proposal.offer_window
    if window is not None and ctx.stamp < window.start:
        return ctx.reject("not_committable", "offer_window.start is in the future", retry="same")
    return None


def _live_names(assent: tuple[AssentEntry, ...]) -> set[str]:
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


def no_live_commitment(ctx: CheckContext, _composed: Composed) -> Rejected | None:
    if _live_names(ctx.assent) & set(ctx.names):
        return ctx.reject(
            "not_committable", "a live commitment already names a line item", retry="same"
        )
    return None


# 4. Otherwise record_mismatch.


def record_mismatch(ctx: CheckContext, composed: Composed) -> Rejected | None:
    if digest_of(composed.digest_input) != ctx.request.entry.record_digest:
        return ctx.reject(
            "record_mismatch", "record_digest differs from the seller's", retry="refetch"
        )
    return None


#: The checks before the record is composed, in § 5.6.1 order.
BEFORE: tuple[Check, ...] = (window_ended, price_expired, stale, names_known)
#: The checks over the composed record, in § 5.6.1 order.
AFTER: tuple[ComposedCheck, ...] = (
    status_committable,
    window_open,
    no_live_commitment,
    record_mismatch,
)


def decide(ctx: CheckContext) -> Accepted | Rejected:
    """The first check that rejects, or `Accepted` when none does."""
    for check in BEFORE:
        if (rejected := check(ctx)) is not None:
            return rejected
    record = composed(ctx)
    if isinstance(record, Rejected):
        return record
    for composed_check in AFTER:
        if (rejected := composed_check(ctx, record)) is not None:
            return rejected
    return Accepted(record)
