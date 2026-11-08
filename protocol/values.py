"""The values both parties share: JSON and how it is read, the value base, the § 2.2
`Instant`, and the § 4.1.2 entry rules."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import NoReturn

import rfc8785
from openproposal import AssentEntry, AssentEntryRoles, Instant

# A JSON value, as `json.loads` returns it: pydantic's own recursive alias, so that
# a model field can hold one too. The § 4.1.1 binding record and the digest input
# are computed over raw JSON, so that members a receiver doesn't know survive and
# every value stays exact.
from pydantic import BaseModel, ConfigDict, JsonValue, TypeAdapter, ValidationError

#: A JSON object.
JsonObject = dict[str, JsonValue]

__all__ = [
    "AmendedValueError",
    "JsonObject",
    "JsonValue",
    "MalformedJsonError",
    "Value",
    "canonical",
    "commitment_key",
    "instant",
    "matches",
    "objects",
    "read_json",
    "strings",
    "validation_detail",
]


class AmendedValueError(TypeError):
    """A value was asked for an amended copy. Its next state is a new value, built and checked."""

    def __init__(self, kind: str, instead: str = "build a new one") -> None:
        super().__init__(f"{kind} is never amended; {instead}")


class Value(BaseModel):
    """The base of a value: strict, so nothing is coerced; frozen, with unknown members refused.

    `model_copy` raises, because a copy with `update` skips validation. The
    next state of a value is a constructor call, which checks every field.
    """

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    def model_copy(
        self, *, update: Mapping[str, object] | None = None, deep: bool = False
    ) -> NoReturn:
        """Refused: a copy with `update` would skip validation."""
        del update, deep
        raise AmendedValueError(type(self).__name__)


def canonical(value: JsonValue) -> bytes:
    """The RFC 8785 serialization of a JSON value, as UTF-8."""
    return rfc8785.dumps(value)


class MalformedJsonError(ValueError):
    """Untrusted bytes that aren't a JSON object, or hold a number RFC 8785 can't serialize."""


_JSON_OBJECT: TypeAdapter[JsonObject] = TypeAdapter(JsonObject)


def _unique_members(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    """An object's members, as `json.loads` hands them over; a name given twice raises."""
    members: dict[str, object] = {}
    for name, value in pairs:
        if name in members:
            detail = f"the body names the member {name!r} twice"
            raise MalformedJsonError(detail)
        members[name] = value
    return members


def read_json(raw: bytes) -> JsonObject:
    """Untrusted bytes as a JSON object, in the number domain RFC 8785 serializes (§ 4.1.1).

    A body that one party digests has to canonicalize at the other, so `NaN`,
    `Infinity`, a number beyond a double such as `1e400`, and an integer beyond
    2**53 are refused here, where the body is read, and not later where it is
    digested. So is an object that names one member twice: readers disagree on
    which of the two counts, so two parties could read different documents from
    the same signed bytes. Raises `MalformedJsonError`.
    """
    try:
        value = _JSON_OBJECT.validate_json(raw)
    except ValidationError as e:
        reason = "; ".join(error["msg"] for error in e.errors())
        detail = f"the body is not a JSON object: {reason}"
        raise MalformedJsonError(detail) from e
    # The parse above keeps the last of two members of one name; this one refuses them. It
    # reads only what the stricter parse above accepted.
    try:
        json.loads(raw, object_pairs_hook=_unique_members)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        detail = f"the body is not a JSON object: {e}"
        raise MalformedJsonError(detail) from e
    try:
        canonical(value)
    except rfc8785.CanonicalizationError as e:
        detail = f"the body holds a number with no RFC 8785 form: {e}"
        raise MalformedJsonError(detail) from e
    return value


def validation_detail(errors: Iterable[Mapping[str, object]]) -> str:
    """One line from pydantic's error list: `loc: msg` for each error, joined by `; `."""
    parts = []
    for error in errors:
        loc = error.get("loc", ())
        path = "/".join(map(str, loc)) if isinstance(loc, tuple | list) else str(loc)
        parts.append(f"{path}: {error.get('msg', '')}")
    return "; ".join(parts)


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
