"""Decision-audit wire primitive: DecisionRecord (EP-10.1).

A :class:`DecisionRecord` is a durable, first-class record of WHY a
money/state decision was made — the object that makes "why did money move"
reconstructable after the fact. It is DISTINCT from the event envelope in
:mod:`iab_agentic_primitives.events`: an :class:`~iab_agentic_primitives.events.Event`
is a transient bus message, whereas a DecisionRecord is a persisted domain
object with its own identity. A booking emits BOTH — an event onto the bus
and a DecisionRecord into the audit store.

Privacy rule: the record stores REFERENCES and HASHES of the inputs that
drove the decision (which counterparty message, which model output), never
raw prompts or counterparty text. This keeps the audit trail replayable
without fossilising sensitive payloads into it.

See RECONCILIATION.md at the repo root for the classification decision.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._util import Money, WireModel, utc_now


class DecisionType(str, Enum):
    """Category of money/state decision being recorded."""

    BOOKING = "booking"
    NEGOTIATION_CONCESSION = "negotiation_concession"
    APPROVAL = "approval"
    REJECTION = "rejection"
    PRICING = "pricing"
    MAKEGOOD = "makegood"
    CANCELLATION = "cancellation"
    OTHER = "other"


class ActorKind(str, Enum):
    """Whether the deciding actor is a human or a machine agent."""

    HUMAN = "human"
    MACHINE = "machine"


class DecisionActor(WireModel):
    """Who made the decision."""

    agent_id: str = Field(
        description="Registry-issued id of the agent (or a 'human:<id>' actor id)."
    )
    kind: ActorKind = Field(
        default=ActorKind.MACHINE,
        description="Human-or-machine discriminator for the acting party.",
    )
    on_behalf_of: str | None = Field(
        default=None,
        description="Org/human id the actor acted for, when a machine acts on behalf of one.",
    )


class DecisionInputRef(WireModel):
    """A reference/hash to ONE input that drove the decision.

    Never the raw content: ``ref`` is an id/URI pointer and ``digest`` is a
    content hash (e.g. ``sha256:...``). Store one or both; the raw
    counterparty prompt or model output stays out of the record.
    """

    kind: str = Field(
        description="Input kind, e.g. 'counterparty_message', 'model_output', "
        "'quote', 'rate_card', 'negotiation_round'."
    )
    ref: str | None = Field(
        default=None, description="Opaque id/URI reference to the input, if addressable."
    )
    digest: str | None = Field(
        default=None,
        description="Content hash of the raw input (e.g. 'sha256:...'); never the raw content.",
    )
    description: str | None = Field(
        default=None, description="Short human-readable label for the input."
    )


class DecisionRationale(WireModel):
    """Structured rationale — not free-text-only.

    ``summary`` is a one-line human summary; ``factors`` and ``policy_refs``
    make the reasoning machine-inspectable so an auditor can filter by
    factor or applied policy rather than parsing prose.
    """

    summary: str = Field(description="One-line human summary of the decision.")
    factors: list[str] = Field(
        default_factory=list,
        description="Named factors that drove the decision (machine-inspectable).",
    )
    policy_refs: list[str] = Field(
        default_factory=list, description="Ids of policies/rules applied."
    )
    notes: str | None = Field(default=None, description="Optional additional detail.")


class DecisionRecord(WireModel):
    """A durable record of why a money/state decision was made (EP-10.1).

    Persisted domain object (distinct from the transient Event envelope).
    References its subject by id — it is never embedded on the Deal/Order/
    Quote; those objects point back to nothing, and the audit store joins
    on ``subject_id`` / ``correlation_id``.

    ID minting: ``decision_id`` is minted by the agent that made the
    decision when the record is written to its audit store.
    """

    decision_id: str = Field(description="Id of this decision record (minted by the decider).")
    subject_type: str = Field(
        description="Type of the subject: 'deal', 'quote', 'order', 'negotiation', "
        "'change_request'."
    )
    subject_id: str = Field(description="Id of the deal/quote/order/... the decision concerns.")
    decision_type: DecisionType
    actor: DecisionActor
    inputs: list[DecisionInputRef] = Field(
        default_factory=list,
        description="References/hashes of the counterparty inputs and model outputs that "
        "drove the decision (never raw prompts).",
    )
    rationale: DecisionRationale
    money_effect: Money | None = Field(
        default=None,
        description="Money movement this decision caused, if any (exact micros; FD-11).",
    )
    occurred_at: datetime = Field(
        default_factory=utc_now,
        description="Timezone-aware UTC timestamp of when the decision was made.",
    )
    correlation_id: str | None = Field(
        default=None, description="Correlation id linking related records/events."
    )
    session_id: str | None = Field(
        default=None, description="Session the decision occurred in, if any."
    )
    negotiation_id: str | None = Field(
        default=None, description="Negotiation the decision belongs to, if any."
    )
    ext: dict[str, Any] | None = Field(default=None, description="Extension slot.")


__all__ = [
    "ActorKind",
    "DecisionActor",
    "DecisionInputRef",
    "DecisionRationale",
    "DecisionRecord",
    "DecisionType",
]
