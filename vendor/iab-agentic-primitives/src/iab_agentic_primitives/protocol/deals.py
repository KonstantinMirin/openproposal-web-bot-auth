"""Deal-booking surface of the Deals API quote->book flow, plus
post-booking change requests.

- ``POST /api/v1/deals`` — book a deal from a quote; body is
  :class:`DealBookingRequest`, success response is
  :class:`DealBookingResponse` (wrapping the shared
  :class:`~iab_agentic_primitives.primitives.Deal` primitive).
- ``GET /api/v1/deals/{deal_id}`` — retrieve; response is
  :class:`DealBookingResponse`.
- ``POST /api/v1/change-requests`` — post-booking modification; body is
  :class:`ChangeRequestCreate`, response is :class:`ChangeRequestResponse`
  (wrapping the ChangeRequest primitive).

Error envelope: failures use the ONE structured shape defined in
:mod:`iab_agentic_primitives.protocol.errors` —
``{"detail": {"error": <code>, "message": ..., "unsupported": [...]}}`` —
which is exactly the symmetric quote->book error encoding the repos
already share (buyer ``clients/deals_client.py`` parses the wrapped
``detail`` dict incl. ``unsupported``; seller ``interfaces/api/main.py``
raises ``HTTPException(detail={"error": ..., "unsupported": [...]})``).

Makegood / cancellation (FD-6): the buyer's dead endpoints
``POST /api/v1/deals/{id}/makegoods`` and ``POST /api/v1/deals/{id}/cancel``
had no server-side implementation. Canonical decision: both are typed
:class:`~iab_agentic_primitives.primitives.ChangeRequest` subtypes sent to
``POST /api/v1/change-requests`` — ``change_type == "makegood"`` with a
:class:`~iab_agentic_primitives.primitives.MakegoodDetails` payload, and
``change_type == "cancellation"`` with the cancellation fields in
``proposed_values`` (``cancel_pct``, ``reason``, ``effective_date``). The
per-deal sub-routes are retired.

Idempotency (FD-12): booking and change requests are money-mutating —
both bodies require ``idempotency_key``; replay semantics per
:mod:`iab_agentic_primitives.protocol._base`.

Acronyms: FD = flagged decision (remediation plan §7.2 register);
GRP = gross rating point.
"""

from pydantic import Field, model_validator

from ..primitives import (
    BuyerIdentity,
    ChangeRequest,
    ChangeSeverity,
    ChangeType,
    ConsentContext,
    Deal,
    MakegoodDetails,
    WireModel,
)
from ._base import IdempotentRequest


class DealBookingRequest(IdempotentRequest):
    """Request body for ``POST /api/v1/deals`` (money-mutating: FD-12).

    This is the commit point — the referenced quote becomes bound. The
    seller mints ``deal_id`` in the response.
    """

    quote_id: str = Field(description="Seller-issued quote being booked.")
    buyer_identity: BuyerIdentity | None = Field(
        default=None,
        description="Must be consistent with the identity the quote was "
        "priced for; the seller re-verifies tier at booking.",
    )
    notes: str | None = None
    audience_plan: dict | None = Field(
        default=None,
        description="Audience plan frozen with the booking (open object; "
        "typed model lands with the audience-plan bead). Unsupported parts "
        "are rejected structurally (FD-6) so the buyer can degrade and retry.",
    )
    consent_context: ConsentContext | None = Field(
        default=None,
        description="Privacy consent signals riding with the booking (FD-10).",
    )


class DealBookingResponse(WireModel):
    """Success envelope for the deal endpoints: wraps the Deal primitive."""

    deal: Deal
    audience_plan_snapshot: dict | None = Field(
        default=None,
        description="Verbatim snapshot of the audience plan the booking "
        "carried, authoritative for the deal's lifetime. None for "
        "non-audience bookings.",
    )
    audience_match_summary: dict | None = Field(
        default=None,
        description="Per-role match summary for the frozen plan (open "
        "object; typed model lands with the audience-plan bead).",
    )


class ChangeRequestCreate(IdempotentRequest):
    """Request body for ``POST /api/v1/change-requests`` (money-mutating: FD-12).

    The seller mints ``change_request_id`` and owns the request's
    lifecycle. Makegoods (GRP shortfall replacement, linear TV) and
    cancellations are typed subtypes of this one surface — see the
    module docstring for the retired per-deal sub-routes.
    """

    order_id: str | None = Field(
        default=None, description="Order being modified; at least one of order_id/deal_id."
    )
    deal_id: str | None = Field(
        default=None, description="Deal being modified; at least one of order_id/deal_id."
    )
    change_type: ChangeType
    severity: ChangeSeverity = ChangeSeverity.MATERIAL
    reason: str = ""
    proposed_values: dict = Field(
        default_factory=dict,
        description="Field -> proposed new value. For change_type "
        "'cancellation': cancel_pct (0.0-1.0), reason, effective_date.",
    )
    makegood: MakegoodDetails | None = Field(
        default=None, description="Required when change_type == 'makegood' (FD-6)."
    )

    @model_validator(mode="after")
    def _consistency(self) -> "ChangeRequestCreate":
        if self.order_id is None and self.deal_id is None:
            raise ValueError("ChangeRequestCreate requires order_id or deal_id")
        if self.change_type == ChangeType.MAKEGOOD and self.makegood is None:
            raise ValueError("change_type 'makegood' requires makegood details")
        if self.change_type != ChangeType.MAKEGOOD and self.makegood is not None:
            raise ValueError("makegood details require change_type 'makegood'")
        return self


class ChangeRequestResponse(WireModel):
    """Success envelope wrapping the ChangeRequest primitive."""

    change_request: ChangeRequest


__all__ = [
    "ChangeRequestCreate",
    "ChangeRequestResponse",
    "DealBookingRequest",
    "DealBookingResponse",
]
