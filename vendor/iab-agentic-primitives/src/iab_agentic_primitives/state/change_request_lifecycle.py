"""Canonical ChangeRequest lifecycle machine over ``ChangeRequestStatus``.

Formalizes the 7-value change-request flow that both repos documented (in
``docs/state-machines/change-request-flow.md``) but enforced only with
ad-hoc if-statements in the seller's API (Application Programming
Interface) handlers:

    pending -> validating -> {failed | approved | pending_approval}
    pending_approval -> {approved | rejected}
    approved -> applied

Severity routing (minor auto-approves out of ``validating``;
material/critical go through ``pending_approval`` for human review) is
policy the seller applies when CHOOSING a transition — it is not encoded
as guard logic here, because the machine defines what moves are legal, not
which one an agent should pick.

One transition is ADDED relative to the documented flow:
``approved -> failed`` — applying an approved change to the order can
fail, and the ad-hoc code had no legal state to express that (it would
have had to lie with ``applied`` or mutate back illegally). Documented in
``STATE_RECONCILIATION.md``.

Makegoods (flagged decision FD-6) are a typed ChangeRequest subtype
(``change_type == "makegood"``) and follow this same machine — no extra
states.

Terminal states are explicit: ``applied``, ``rejected``, ``failed``.
The change-request lifecycle is seller-owned (the seller mints the
identifier and runs validation/approval/application), so per flagged
decision FD-8 the seller's record is authoritative; see
``reconciliation.py``.
"""

from __future__ import annotations

from ..primitives.lifecycle import ChangeRequestStatus
from .machine import StateMachine, TransitionRule

_S = ChangeRequestStatus

CHANGE_REQUEST_TERMINAL_STATES: frozenset[ChangeRequestStatus] = frozenset(
    {_S.APPLIED, _S.REJECTED, _S.FAILED}
)

_TRANSITIONS: list[tuple[ChangeRequestStatus, ChangeRequestStatus, str]] = [
    (_S.PENDING, _S.VALIDATING, "Validation begins"),
    (_S.VALIDATING, _S.FAILED, "Validation errors found"),
    (_S.VALIDATING, _S.APPROVED, "Minor severity, auto-approved"),
    (_S.VALIDATING, _S.PENDING_APPROVAL, "Material/critical severity, human review"),
    (_S.PENDING_APPROVAL, _S.APPROVED, "Reviewer approved"),
    (_S.PENDING_APPROVAL, _S.REJECTED, "Reviewer rejected"),
    (_S.APPROVED, _S.APPLIED, "Changes applied to the order"),
    (_S.APPROVED, _S.FAILED, "Applying the approved change failed"),
]

CHANGE_REQUEST_LIFECYCLE: StateMachine[ChangeRequestStatus] = StateMachine(
    name="change_request",
    states=ChangeRequestStatus,
    initial=ChangeRequestStatus.PENDING,
    terminal=CHANGE_REQUEST_TERMINAL_STATES,
    rules=[TransitionRule(from_state=f, to_state=t, description=d) for f, t, d in _TRANSITIONS],
)

__all__ = ["CHANGE_REQUEST_LIFECYCLE", "CHANGE_REQUEST_TERMINAL_STATES"]
