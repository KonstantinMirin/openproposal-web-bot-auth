"""Negotiation messages: offer / counter / accept / decline (FD-5).

ONE endpoint, ONE message model each way:

- ``POST /api/v1/negotiations/messages`` — the buyer sends a
  :class:`NegotiationMessage`; the seller answers a
  :class:`NegotiationRoundResponse`.
- ``GET /api/v1/negotiations/{negotiation_id}`` — full history; response
  is the :class:`~iab_agentic_primitives.primitives.Negotiation` primitive.

Why this exists — the historical 422: the buyer's
``negotiation/client.py`` POSTed ``{"price": <float>}`` to
``/proposals/{id}/counter`` while the seller's ``CounterOfferRequest``
required ``buyer_price`` and had no ``action`` field at all, so every
round failed validation (HTTP 422) and accept/decline were structurally
inexpressible. The canonical message makes that impossible by
construction: ``action`` is a REQUIRED enum
(:class:`~iab_agentic_primitives.primitives.NegotiationAction`), the money
field is ``buyer_price`` (a
:class:`~iab_agentic_primitives.primitives.Money`, exact micros — FD-11),
and both sides validate against this same model. The
``/proposals/{id}/counter`` route and its bare-``price`` payload are
retired.

Action semantics (buyer's retired verbs map onto the shared enum):

- opening **offer**: ``action="counter"`` with ``negotiation_id=None`` —
  the seller creates the negotiation and mints ``negotiation_id``
- **counter**: ``action="counter"`` with the ``negotiation_id``
- **accept**: ``action="accept"`` — TERMINAL; accepts the counterparty's
  last stated price (``buyer_price`` optional as an echo)
- **decline / walk away**: ``action="reject"`` — TERMINAL; the walk-away
  is recorded as a round on the Negotiation primitive, not silently
  dropped
- **final offer**: ``action="final_offer"`` — a counter flagged as the
  last round before walking away

Termination: once a negotiation's status is ``accepted``, ``rejected``,
or ``expired``, further messages MUST be refused with the
``negotiation_closed`` error code
(:mod:`iab_agentic_primitives.protocol.errors`). Transition rules and the
full state machine are EP-1.4 (``iab_agentic_primitives.state``).

Idempotency (FD-12): every negotiation message can move money and
requires ``idempotency_key`` — a retried counter must not consume an
extra round.

Acronyms: FD = flagged decision (remediation plan §7.2 register);
HTTP = Hypertext Transfer Protocol.
"""

from pydantic import Field, model_validator

from ..primitives import (
    BuyerIdentity,
    Money,
    NegotiationAction,
    NegotiationRound,
    NegotiationStatus,
    WireModel,
)
from ._base import IdempotentRequest

#: Actions that end the negotiation. ``final_offer`` is NOT terminal — it
#: invites exactly one more response.
TERMINAL_ACTIONS: frozenset[NegotiationAction] = frozenset(
    {NegotiationAction.ACCEPT, NegotiationAction.REJECT}
)

#: Actions that must carry a price.
PRICED_ACTIONS: frozenset[NegotiationAction] = frozenset(
    {NegotiationAction.COUNTER, NegotiationAction.FINAL_OFFER}
)


class NegotiationMessage(IdempotentRequest):
    """A buyer negotiation move (money-mutating: FD-12).

    Exactly one negotiation context is required: ``negotiation_id`` to
    continue, or ``proposal_id``/``quote_id`` to open (the seller mints
    ``negotiation_id`` on open).
    """

    action: NegotiationAction = Field(
        description="REQUIRED move discriminator: 'accept', 'counter', "
        "'reject' (walk-away), or 'final_offer'. No default — the "
        "action-less bare-price payload that caused the historical 422 "
        "does not validate."
    )
    negotiation_id: str | None = Field(
        default=None,
        description="Seller-issued id of the negotiation to continue; None "
        "opens a new negotiation on proposal_id/quote_id.",
    )
    proposal_id: str | None = Field(
        default=None, description="Proposal under negotiation, if proposal-led."
    )
    quote_id: str | None = Field(default=None, description="Quote under negotiation, if quote-led.")
    round_number: int | None = Field(
        default=None,
        ge=1,
        description="The round the sender believes it is answering, for "
        "optimistic concurrency; a mismatch is a 'contention' error. The "
        "seller's numbering is authoritative.",
    )
    buyer_price: Money | None = Field(
        default=None,
        description="The buyer's price this round (exact micros; FD-11). "
        "REQUIRED for 'counter'/'final_offer'; optional echo on 'accept'; "
        "omitted on 'reject'.",
    )
    buyer_identity: BuyerIdentity | None = None
    rationale: str = Field(default="", description="Optional human-readable rationale.")

    @model_validator(mode="after")
    def _consistency(self) -> "NegotiationMessage":
        if self.negotiation_id is None and self.proposal_id is None and self.quote_id is None:
            raise ValueError("NegotiationMessage requires negotiation_id, proposal_id, or quote_id")
        if self.action in PRICED_ACTIONS and self.buyer_price is None:
            raise ValueError(f"action '{self.action.value}' requires buyer_price")
        if self.action is NegotiationAction.REJECT and self.buyer_price is not None:
            raise ValueError("action 'reject' must not carry buyer_price")
        return self


class NegotiationRoundResponse(WireModel):
    """The seller's answer to a :class:`NegotiationMessage`.

    Embeds the shared
    :class:`~iab_agentic_primitives.primitives.NegotiationRound` primitive
    — the same record appended to the Negotiation history — so the two
    sides cannot disagree about what a round contains. ``round.action`` is
    the SELLER's move (accept/counter/reject/final_offer); when
    ``status`` is terminal the round is the last one.
    """

    negotiation_id: str = Field(description="Seller-issued negotiation identifier.")
    status: NegotiationStatus = Field(
        description="'active' or terminal ('accepted'/'rejected'/'expired'); "
        "terminal negotiations refuse further messages (negotiation_closed)."
    )
    round: NegotiationRound
    rounds_remaining: int | None = Field(
        default=None,
        ge=0,
        description="Rounds left before the seller walks away, if disclosed.",
    )


__all__ = [
    "PRICED_ACTIONS",
    "TERMINAL_ACTIONS",
    "NegotiationMessage",
    "NegotiationRoundResponse",
]
