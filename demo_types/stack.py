"""STOPGAP: the three OpenProposal 3.0 types this demo needs that the SDK doesn't generate yet.

The vendored SDK (vendor/openproposal-sdk) is generated from an earlier
specification. `Commit`, `CommitResult`, and `AssentEntry` exist only in the
current text (spec/openproposal-3.0.md at the tip of the pull-request stack).
When the schema pipeline generates the stack's types, import them from
`openproposal` and delete this module.

Each field cites the section that defines it. The models use the SDK's base
class, so they refuse null and unknown members the way the generated types do.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from openproposal import Count, dump
from openproposal._runtime import Closed
from pydantic import Field, model_validator

#: § 2.2 `Digest`: `sha256:` and the 64 lowercase hexadecimal characters of the SHA-256.
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
#: § 2.2 `Instant`: an RFC 3339 date-time in whole seconds, ending in `Z`.
Instant = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]
#: § 2.2 `VocabularyTerm`: a bare core term, or `<domain>:<term>`.
VocabularyTerm = Annotated[str, Field(pattern=r"^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+:)?[A-Za-z0-9_-]+$")]

#: § 4.1.2 `role`.
AssentRole = Literal["commitment", "acceptance", "withdrawal", "decline"]


class AssentEntry(Closed):
    """One party's act (§ 4.1.2). Entries are written whole and never edited."""

    role: AssentRole
    """§ 4.1.2: what the entry does. It implies the party."""
    version: Count
    """§ 4.1.2: the `version` of the record the digest was computed over."""
    record_digest: Digest
    """§ 4.1.2: of the binding record for the line items in `line_item_ids[]` (§ 4.1.1)."""
    line_item_ids: Annotated[list[str], Field(min_length=1)]
    """§ 4.1.2: the line items the entry names. MUST be non-empty."""
    at: Instant
    """§ 4.1.2: when the party wrote the entry, by its own statement."""
    idempotency_key: str | None = None
    """§ 4.1.2: REQUIRED when `role` is `commitment`. Opaque; the seller never interprets it (§ 5.6.1)."""
    ground: VocabularyTerm | None = None
    """§ 4.1.2: REQUIRED when `role` is `decline`, absent on any other entry."""

    @model_validator(mode="after")
    def _role_rules(self) -> AssentEntry:
        if self.role == "commitment" and self.idempotency_key is None:
            raise ValueError("a commitment entry carries idempotency_key (§ 4.1.2)")
        if (self.role == "decline") != (self.ground is not None):
            raise ValueError("ground is present on a decline entry and only there (§ 4.1.2)")
        return self

    def matches(self, other: AssentEntry) -> bool:
        """§ 4.1.2: equal `version` and `record_digest`, and `line_item_ids[]` equal as sets."""
        return (
            self.version == other.version
            and self.record_digest == other.record_digest
            and set(self.line_item_ids) == set(other.line_item_ids)
        )

    def wire(self) -> dict[str, Any]:
        return dump(self)


class Commit(Closed):
    """A buyer's `commit` (§ 5.6.1): its entry and its writes."""

    entry: AssentEntry
    """§ 5.6.1: the buyer's entry (§ 4.1.2), with `role: commitment`."""
    writes: dict[str, dict[str, Any]]
    """§ 5.6.1: the buyer's writes (§ 3.4), keyed by each `line_item_id` that `entry.line_item_ids[]`
    names. Each value is a `LineItemWrites`, which this stopgap leaves untyped."""

    @model_validator(mode="after")
    def _entry_and_writes(self) -> Commit:
        if self.entry.role != "commitment":
            raise ValueError("a Commit carries a commitment entry (§ 5.6.1)")
        if set(self.writes) != set(self.entry.line_item_ids):
            raise ValueError("writes are keyed by exactly the line items the entry names (§ 5.6.1)")
        for name, writes in self.writes.items():
            if not isinstance(writes.get("commitment"), dict):
                # ValueError, not TypeError: pydantic turns only ValueError into a validation error.
                raise ValueError(  # noqa: TRY004
                    f"writes for {name} carry a commitment object (§ 3.4 LineItemWrites)")
        return self


class CommitResult(Closed):
    """The result of a `commit` that wrote an entry, as it stands (§ 5.6.1)."""

    entries: Annotated[list[AssentEntry], Field(min_length=1)]
    """§ 5.6.1: the buyer's `commitment` entry, then each matching `acceptance`, `decline`, or
    `withdrawal` entry written after it in `assent[]`."""
    availability: dict[str, dict[str, Any]] | None = None
    """§ 5.6.1: REQUIRED when `entries[]` holds a `decline` for lack of availability, keyed by
    `line_item_id`. Each value is an `Availability` (§ 5.6), which this stopgap leaves untyped."""
