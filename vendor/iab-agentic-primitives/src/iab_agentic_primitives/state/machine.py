"""Generic lifecycle state-machine engine.

One small, storage-free engine drives every canonical lifecycle in this
package (Deal, Order, ChangeRequest). Design constraints, in order:

- **Pure**: :meth:`StateMachine.transition` is ``(current, to) -> to``.
  The machine holds no entity state and no audit log — persistence is the
  agents' concern. This is deliberately different from both source repos,
  whose machines carried mutable ``_status`` plus an in-memory audit log
  that production flows simply bypassed.
- **Explicit transition table**: allowed moves are an explicit
  ``{(from, to): TransitionRule}`` index built at construction, validated
  eagerly (unknown states, duplicate rules, and outgoing edges from
  terminal states are construction-time errors, not runtime surprises).
- **Good error ergonomics**: :class:`InvalidTransitionError` carries the
  machine name, the current state, the attempted state, and the full
  ``allowed`` list, and renders to a payload dict — the seller agent's
  HTTP (Hypertext Transfer Protocol) 409-with-allowed-transitions response
  pattern, made portable.
- **Audit shape, not audit storage**: :class:`AuditEntry` standardizes the
  record both agents write (from, to, actor, occurred_at, reason) with a
  timezone-aware UTC (Coordinated Universal Time) timestamp, but the
  engine never accumulates entries.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

StateT = TypeVar("StateT", bound=Enum)

# Guard signature: (current, to, context) -> bool. Guards must be pure
# predicates over the supplied context; they must not perform input/output.
GuardFn = Callable[[Enum, Enum, Mapping[str, Any]], bool]


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


@dataclass(frozen=True)
class TransitionRule:
    """One permitted move in a lifecycle, with an optional guard predicate.

    ``rework=True`` marks a transition that returns the entity to an
    earlier state (counter-offer re-propose, reset-to-draft recovery,
    resume-after-makegood). Rework edges are just as legal as any other
    transition; the flag only excludes them from the forward-progress
    partial order used by lifecycle precedence queries
    (:meth:`StateMachine.can_progress_to`) and by FD-8 reconciliation —
    without it, recovery loops would make almost every state pair mutually
    reachable and precedence meaningless. The progress subgraph (non-rework
    edges) is required to be acyclic, and that is validated at
    construction.
    """

    from_state: Enum
    to_state: Enum
    description: str = ""
    guard: GuardFn | None = None
    rework: bool = False


@dataclass(frozen=True)
class AuditEntry:
    """Immutable record of one executed transition.

    The engine does not store these — it only defines the shape, so both
    agents persist lifecycle history in the same vocabulary. ``actor``
    follows the shared convention: ``"system"``, ``"human:<id>"``, or
    ``"agent:<id>"``.
    """

    machine: str
    from_state: str
    to_state: str
    actor: str = "system"
    occurred_at: datetime = field(default_factory=utc_now)
    reason: str = ""

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("AuditEntry.occurred_at must be timezone-aware (UTC)")
        object.__setattr__(self, "occurred_at", self.occurred_at.astimezone(UTC))


class InvalidTransitionError(Exception):
    """Raised when a transition is not in the table (or its guard rejects it).

    Carries everything an agent needs to build a useful conflict response:
    the machine name, ``current``, ``attempted``, and the ``allowed`` list
    of states reachable from ``current``. :meth:`as_dict` renders the
    seller agent's HTTP 409 payload shape directly.
    """

    def __init__(
        self,
        machine: str,
        current: Enum,
        attempted: Enum,
        allowed: Iterable[Enum],
        reason: str = "",
    ) -> None:
        self.machine = machine
        self.current = current
        self.attempted = attempted
        self.allowed: tuple[Enum, ...] = tuple(allowed)
        self.reason = reason
        allowed_values = [state.value for state in self.allowed]
        message = (
            f"{machine}: cannot transition from {current.value!r} to "
            f"{attempted.value!r}; allowed: {allowed_values}"
        )
        if reason:
            message += f" ({reason})"
        super().__init__(message)

    def as_dict(self) -> dict[str, Any]:
        """Render a structured conflict payload (for an HTTP 409 body or log)."""
        return {
            "error": "invalid_transition",
            "machine": self.machine,
            "current": self.current.value,
            "attempted": self.attempted.value,
            "allowed": [state.value for state in self.allowed],
            "reason": self.reason,
        }


class StateMachine(Generic[StateT]):
    """A validated, immutable transition table over one status enum.

    Construct once at import time; share the instance. All query and
    transition methods take the current state as an argument — the machine
    itself never holds entity state.
    """

    def __init__(
        self,
        *,
        name: str,
        states: type[StateT],
        initial: StateT,
        terminal: frozenset[StateT],
        rules: Iterable[TransitionRule],
    ) -> None:
        self.name = name
        self.states = states
        self.initial = initial
        self.terminal = frozenset(terminal)
        self._rules: tuple[TransitionRule, ...] = tuple(rules)
        self._index: dict[tuple[StateT, StateT], TransitionRule] = {}
        self._reachability: dict[tuple[StateT, bool], frozenset[StateT]] = {}
        self._validate()

    # -- construction-time validation ------------------------------------

    def _validate(self) -> None:
        members = set(self.states)
        if self.initial not in members:
            raise ValueError(f"{self.name}: initial state {self.initial!r} not in {self.states}")
        if not self.terminal <= members:
            raise ValueError(f"{self.name}: terminal states must be members of {self.states}")
        if self.initial in self.terminal:
            raise ValueError(f"{self.name}: initial state cannot be terminal")
        for rule in self._rules:
            if rule.from_state not in members or rule.to_state not in members:
                raise ValueError(
                    f"{self.name}: rule {rule.from_state!r} -> {rule.to_state!r} "
                    f"references a state outside {self.states}"
                )
            if rule.from_state in self.terminal:
                raise ValueError(
                    f"{self.name}: terminal state {rule.from_state.value!r} "
                    "must not have outgoing transitions"
                )
            key = (rule.from_state, rule.to_state)
            if key in self._index:
                raise ValueError(
                    f"{self.name}: duplicate rule "
                    f"{rule.from_state.value!r} -> {rule.to_state.value!r}"
                )
            self._index[key] = rule
        unreachable = members - self._reachable_from(self.initial) - {self.initial}
        if unreachable:
            names = sorted(state.value for state in unreachable)
            raise ValueError(f"{self.name}: states unreachable from initial: {names}")
        for state in members:
            if state in self._reachable_from(state, progress_only=True):
                raise ValueError(
                    f"{self.name}: forward-progress cycle through {state.value!r}; "
                    "mark the returning transition(s) rework=True"
                )

    # -- queries ----------------------------------------------------------

    @property
    def rules(self) -> tuple[TransitionRule, ...]:
        return self._rules

    def is_terminal(self, state: StateT) -> bool:
        return state in self.terminal

    def allowed_from(self, current: StateT) -> tuple[StateT, ...]:
        """States reachable from ``current`` in one step (guards not evaluated)."""
        return tuple(rule.to_state for rule in self._rules if rule.from_state == current)

    def rule_for(self, current: StateT, to: StateT) -> TransitionRule | None:
        return self._index.get((current, to))

    def can_transition(
        self, current: StateT, to: StateT, context: Mapping[str, Any] | None = None
    ) -> bool:
        """Whether ``current -> to`` is allowed, including the guard check."""
        rule = self._index.get((current, to))
        if rule is None:
            return False
        if rule.guard is not None:
            return rule.guard(current, to, context or {})
        return True

    def _reachable_from(self, start: StateT, progress_only: bool = False) -> frozenset[StateT]:
        """All states reachable from ``start`` via one or more transitions."""
        key = (start, progress_only)
        cached = self._reachability.get(key)
        if cached is not None:
            return cached

        def successors(state: StateT) -> list[StateT]:
            return [
                rule.to_state
                for rule in self._rules
                if rule.from_state == state and not (progress_only and rule.rework)
            ]

        seen: set[StateT] = set()
        queue: deque[StateT] = deque(successors(start))
        while queue:
            state = queue.popleft()
            if state in seen:
                continue
            seen.add(state)
            queue.extend(successors(state))
        result = frozenset(seen)
        self._reachability[key] = result
        return result

    def can_reach(self, start: StateT, target: StateT) -> bool:
        """Whether ``target`` is reachable from ``start`` via >= 1 transition."""
        return target in self._reachable_from(start)

    def can_progress_to(self, start: StateT, target: StateT) -> bool:
        """Whether ``target`` is reachable from ``start`` via forward progress only.

        Uses only non-rework transitions; because the progress subgraph is
        validated acyclic, this induces a strict partial order over states
        ("``start`` precedes ``target`` in the lifecycle") — the basis of
        FD-8 reconciliation precedence.
        """
        return target in self._reachable_from(start, progress_only=True)

    # -- transitions -------------------------------------------------------

    def transition(
        self, current: StateT, to: StateT, context: Mapping[str, Any] | None = None
    ) -> StateT:
        """Validate ``current -> to`` and return ``to``. Pure; no storage.

        Raises :class:`InvalidTransitionError` (carrying the allowed list)
        if the move is not in the table or its guard rejects the context.
        """
        rule = self._index.get((current, to))
        if rule is None:
            raise InvalidTransitionError(
                self.name, current, to, self.allowed_from(current), "no matching transition rule"
            )
        if rule.guard is not None and not rule.guard(current, to, context or {}):
            raise InvalidTransitionError(
                self.name, current, to, self.allowed_from(current), "guard condition failed"
            )
        return to

    def entry(
        self,
        current: StateT,
        to: StateT,
        *,
        actor: str = "system",
        reason: str = "",
        occurred_at: datetime | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Validate ``current -> to`` and return the audit record for it.

        Convenience over :meth:`transition` for agents that persist history:
        the returned :class:`AuditEntry` defaults its reason to the rule's
        description. The engine still stores nothing.
        """
        self.transition(current, to, context)
        rule = self._index[(current, to)]
        return AuditEntry(
            machine=self.name,
            from_state=current.value,
            to_state=to.value,
            actor=actor,
            occurred_at=occurred_at if occurred_at is not None else utc_now(),
            reason=reason or rule.description,
        )

    # -- spec export -------------------------------------------------------

    def to_spec_dict(self) -> dict[str, Any]:
        """Language-neutral description of this machine (for spec export)."""
        return {
            "name": self.name,
            "initial": self.initial.value,
            "states": [state.value for state in self.states],
            "terminal": sorted(state.value for state in self.terminal),
            "transitions": [
                {
                    "from": rule.from_state.value,
                    "to": rule.to_state.value,
                    "description": rule.description,
                    "rework": rule.rework,
                }
                for rule in self._rules
            ],
        }


__all__ = [
    "AuditEntry",
    "GuardFn",
    "InvalidTransitionError",
    "StateMachine",
    "TransitionRule",
    "utc_now",
]
