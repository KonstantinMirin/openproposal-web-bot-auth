"""The buyer's plan: the § 3.4 writes it commits for each line item it buys.

The buyer's composition root (buyer/app.py) reads the plan file its settings
name once and passes the parsed document in; the plan checks it strictly as
`LineItemWrites`. A trigger names line items; the plan gives their writes, or
refuses a line item it has none for.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from openproposal import LineItemWrites
from pydantic import TypeAdapter

from protocol.values import JsonObject

from .refusal import Reason, Refusal

_PLAN: TypeAdapter[dict[str, LineItemWrites]] = TypeAdapter(dict[str, LineItemWrites])


class Plan:
    def __init__(self, writes: Mapping[str, LineItemWrites]) -> None:
        self._writes = dict(writes)

    @classmethod
    def of(cls, document: JsonObject) -> Plan:
        """The plan `document` holds; raises pydantic's `ValidationError`."""
        return cls(_PLAN.validate_python(document))

    def writes_for(self, line_item_ids: Sequence[str]) -> dict[str, LineItemWrites] | Refusal:
        """The writes for each named line item, in the order named; refuses an unknown one."""
        unknown = [name for name in line_item_ids if name not in self._writes]
        if unknown:
            return Refusal(
                Reason.UNKNOWN_LINE_ITEM, f"the plan has no writes for {', '.join(unknown)}"
            )
        return {name: self._writes[name] for name in line_item_ids}
