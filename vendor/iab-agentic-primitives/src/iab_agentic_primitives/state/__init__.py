"""Canonical lifecycle state machines for exchanged primitives.

Home of the single canonical lifecycle machine per exchanged primitive.
Each primitive with lifecycle state -- Deal, Order, ChangeRequest -- has
exactly one status enum (defined in ``iab_agentic_primitives.primitives``)
and exactly one lifecycle machine, defined here and imported by both
agents. There is no buyer-vocabulary/seller-vocabulary split, so there is
nothing to map and nothing to disagree about on VOCABULARY; the two agents
still track state independently, and ``reconciliation`` (flagged decision
FD-8) classifies any disagreement between their records -- with the
seller's record authoritative for order/fulfillment state.

State transitions are pure, deterministic functions: booking and state
changes never involve a large language model, per the deterministic-core /
LLM-at-the-edges principle. The engine (``machine``) is storage-free;
persistence and audit-log storage remain the agents' concern.

The transition tables and the reconciliation equivalence tables are
exported as language-neutral JSON (JavaScript Object Notation) under
``spec/jsonschema/state/`` (see ``spec_export``); the full source-repo
mapping audit trail is ``STATE_RECONCILIATION.md`` at the repo root.
"""

from .change_request_lifecycle import (
    CHANGE_REQUEST_LIFECYCLE,
    CHANGE_REQUEST_TERMINAL_STATES,
)
from .deal_lifecycle import DEAL_LIFECYCLE, DEAL_TERMINAL_STATES
from .machine import (
    AuditEntry,
    GuardFn,
    InvalidTransitionError,
    StateMachine,
    TransitionRule,
    utc_now,
)
from .order_lifecycle import (
    AD_SERVER_SYNC_STARTED,
    ORDER_LIFECYCLE,
    ORDER_TERMINAL_STATES,
)
from .reconciliation import (
    AUTHORITATIVE_SIDE,
    CHANGE_REQUEST_COMPARISON_TABLE,
    DEAL_COMPARISON_TABLE,
    ORDER_COMPARISON_TABLE,
    AuthoritativeSide,
    DisagreementReport,
    ReconciliationOutcome,
    ReconciliationResult,
    classify,
    comparison_table,
    reconcile,
    reconcile_change_request,
    reconcile_deal,
    reconcile_order,
)

__all__ = [
    "AD_SERVER_SYNC_STARTED",
    "AUTHORITATIVE_SIDE",
    "AuditEntry",
    "AuthoritativeSide",
    "CHANGE_REQUEST_COMPARISON_TABLE",
    "CHANGE_REQUEST_LIFECYCLE",
    "CHANGE_REQUEST_TERMINAL_STATES",
    "DEAL_COMPARISON_TABLE",
    "DEAL_LIFECYCLE",
    "DEAL_TERMINAL_STATES",
    "DisagreementReport",
    "GuardFn",
    "InvalidTransitionError",
    "ORDER_COMPARISON_TABLE",
    "ORDER_LIFECYCLE",
    "ORDER_TERMINAL_STATES",
    "ReconciliationOutcome",
    "ReconciliationResult",
    "StateMachine",
    "TransitionRule",
    "classify",
    "comparison_table",
    "reconcile",
    "reconcile_change_request",
    "reconcile_deal",
    "reconcile_order",
    "utc_now",
]
