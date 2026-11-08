"""The buyer's refusal: what it says when it won't act on a trigger or on a seller's answer.

The buyer mirrors the seller's identity boundary. Whatever it can't verify,
parse, or match, it refuses, and a refusal is a value the flow returns, never
an exception that escapes as a 500. A refusal keeps nothing.

Its reason is closed: the buyer's own `Reason`, or the library's `Refusal` of
the seller's answer. The control plane (transport/control.py) owns both, so the
outcome a route answers carries the same type, and the code string is written
only on the wire.
"""

from __future__ import annotations

from dataclasses import dataclass

from transport.control import BuyerReason, Reason

__all__ = ["Reason", "Refusal"]


@dataclass(frozen=True)
class Refusal:
    """The buyer won't go on: `reason` is a `Reason` or the library's `Refusal`."""

    reason: BuyerReason
    detail: str
