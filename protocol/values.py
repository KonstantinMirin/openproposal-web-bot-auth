"""The values both parties share: JSON, the § 2.2 `Instant`, and the § 4.1.2 entry rules."""

from __future__ import annotations

from datetime import UTC, datetime

from openproposal import AssentEntry, AssentEntryRoles, Instant

# A JSON value, as `json.loads` returns it: pydantic's own recursive alias, so that
# a model field can hold one too. The § 4.1.1 binding record and the digest input
# are computed over raw JSON, so that members a receiver doesn't know survive and
# every value stays exact.
from pydantic import JsonValue

#: A JSON object.
JsonObject = dict[str, JsonValue]

__all__ = ["JsonObject", "JsonValue", "commitment_key", "instant", "matches", "objects", "strings"]


def objects(value: JsonValue) -> list[JsonObject]:
    """The objects of a JSON array, or nothing when `value` isn't an array."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def strings(value: JsonValue) -> list[str]:
    """The strings of a JSON array, or nothing when `value` isn't an array."""
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def instant(moment: datetime) -> Instant:
    """A § 2.2 `Instant`: UTC, whole seconds, ending in `Z`."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class NotACommitmentError(ValueError):
    """An entry that a `commit` key was asked of is not a commitment with a key."""

    def __init__(self, entry: AssentEntry) -> None:
        super().__init__(f"a {entry.role} entry carries no idempotency_key (§ 4.1.2)")


def commitment_key(entry: AssentEntry) -> str:
    """The `idempotency_key` of a `commitment` entry (§ 4.1.2).

    The generated `AssentEntry` is one object for every role, so the key is
    optional on it. `protocol.operations.parse_commit` refuses a commit whose
    entry has none; this narrows the type once, where a caller needs the key.
    """
    if entry.role != AssentEntryRoles.COMMITMENT or entry.idempotency_key is None:
        raise NotACommitmentError(entry)
    return entry.idempotency_key


def matches(a: AssentEntry, b: AssentEntry) -> bool:
    """§ 4.1.2: equal `version` and `record_digest`, and `line_item_ids[]` equal as sets."""
    return (
        a.version == b.version
        and a.record_digest == b.record_digest
        and set(a.line_item_ids) == set(b.line_item_ids)
    )
