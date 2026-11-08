"""The ONE structured error envelope and canonical error-code vocabulary.

Every protocol error crosses the wire as an :class:`ErrorEnvelope`:

.. code-block:: json

    {"detail": {"error": "<ErrorCode>", "message": "...", "unsupported": [...]}}

This is the shape the two repos already share on their one conformant
surface — the quote->book path — where the seller raises FastAPI
``HTTPException(detail=<dict>)`` (seller ``interfaces/api/main.py``, e.g.
the ``audience_plan_unsupported`` rejection) and the buyer's
``DealsClient._build_error_from_response`` parses the wrapped ``detail``
dict, including its ``unsupported`` list. The buyer's legacy *flat*
fallback shape (``{"error": ..., "detail": ...}``) is retired: canonical
errors are always wrapped.

Canonical codes replace the seller's ad-hoc per-endpoint strings. Mapping
from the retired values (NOT valid on the wire):

- ``invalid_deal_type``, ``pg_requires_impressions``,
  ``below_minimum_impressions`` -> ``validation``
- ``product_not_found``, ``quote_not_found`` -> ``not_found``
- ``quote_expired`` -> ``quote_expired`` (kept; HTTP 410)
- ``quote_already_booked`` -> ``contention`` (HTTP 409)
- ``audience_plan_unsupported`` -> ``unsupported_capability``
  (the FD-6 structured rejection; the specific unsupported parts ride in
  ``unsupported``)

Acronyms: FD = flagged decision (register in the remediation plan §7.2);
HTTP = Hypertext Transfer Protocol; UUID = universally unique identifier.
"""

from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from ..primitives import WireModel


class ErrorCode(str, Enum):
    """Canonical machine-readable error codes for the shared contract.

    - ``validation``: request failed schema or business validation
      (bad enum value, missing required field, below product minimums)
    - ``unsupported_capability``: the counterparty cannot honor a
      requested capability (linear TV, an audience-plan role, ...) —
      the FD-6 structured rejection; specifics ride in ``unsupported``
    - ``not_found``: referenced resource does not exist
    - ``quote_expired``: the referenced quote's TTL (time to live) has
      elapsed; request a new quote (HTTP 410)
    - ``contention``: concurrent-state conflict — e.g. the quote was
      already booked, or the resource changed under the request (HTTP 409)
    - ``ceiling_exceeded``: the request would breach a hard money
      guardrail (buyer budget/CPM — cost per mille — ceiling, seller floor)
    - ``negotiation_closed``: the negotiation is terminal
      (accepted/rejected/expired); no further rounds are possible
    - ``idempotency_conflict``: an ``idempotency_key`` was reused with a
      different request body (FD-12)
    - ``unauthorized``: missing or invalid credentials (HTTP 401)
    - ``forbidden``: authenticated but not allowed — e.g. a blocked agent
      per registry trust status (HTTP 403)
    - ``internal``: unexpected server-side failure (HTTP 5xx)
    """

    VALIDATION = "validation"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    NOT_FOUND = "not_found"
    QUOTE_EXPIRED = "quote_expired"
    CONTENTION = "contention"
    CEILING_EXCEEDED = "ceiling_exceeded"
    NEGOTIATION_CLOSED = "negotiation_closed"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    INTERNAL = "internal"


class UnsupportedItem(WireModel):
    """One capability the counterparty cannot honor (FD-6 rejection detail).

    Generalizes the seller's ``audience_plan_unsupported`` entries
    (``{"path": ..., "reason": ...}``) so the same shape also serves the
    linear-TV rejection: ``{"capability": "linear_tv"}``.
    """

    capability: str = Field(
        description=(
            'What cannot be honored, e.g. "linear_tv", '
            '"audience_plan.extensions[0]", "deal_type:PG".'
        )
    )
    path: str | None = Field(
        default=None,
        description="Optional JSON path into the request pinpointing the item.",
    )
    reason: str = Field(default="", description="Human-readable explanation.")


class ErrorDetail(WireModel):
    """The inner error object carried in every :class:`ErrorEnvelope`."""

    error: ErrorCode
    message: str = Field(default="", description="Human-readable detail.")
    unsupported: list[UnsupportedItem] = Field(
        default_factory=list,
        description=(
            "Populated when error == unsupported_capability (FD-6): the "
            "specific capabilities the counterparty cannot honor, so the "
            "requester can degrade and retry precisely."
        ),
    )

    @field_validator("unsupported", mode="before")
    @classmethod
    def _coerce_unsupported(cls, value: Any) -> Any:
        """Accept legacy shorthand entries and normalize to UnsupportedItem.

        - Bare strings (the FD-6 example ``unsupported: ["linear_tv"]``)
          become ``{"capability": "linear_tv"}``.
        - The seller's legacy audience-plan entries (``{"path", "reason"}``
          with no ``capability``) reuse ``path`` as the capability.
        """
        if not isinstance(value, list):
            return value
        normalized: list[Any] = []
        for item in value:
            if isinstance(item, str):
                normalized.append({"capability": item})
            elif isinstance(item, dict) and "capability" not in item and "path" in item:
                normalized.append({**item, "capability": item["path"]})
            else:
                normalized.append(item)
        return normalized


class ErrorEnvelope(WireModel):
    """The one wire shape for every protocol error: ``{"detail": {...}}``.

    Matches the FastAPI ``HTTPException(detail=<dict>)`` encoding already
    used on the quote->book path, so conformant servers keep their
    framework defaults and conformant clients parse one shape.
    """

    detail: ErrorDetail


__all__ = ["ErrorCode", "ErrorDetail", "ErrorEnvelope", "UnsupportedItem"]
