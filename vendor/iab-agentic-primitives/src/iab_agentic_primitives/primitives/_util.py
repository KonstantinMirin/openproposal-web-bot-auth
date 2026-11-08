"""Shared helpers and base types for the wire-primitive models.

Every timestamp in the shared contract is timezone-aware UTC (Coordinated
Universal Time). Models must use :func:`utc_now` as their
``default_factory`` — never ``datetime.utcnow``, which returns a naive
datetime and was the source of mixed naive/aware timestamps in the two
agent repos this library replaces.
"""

from datetime import UTC, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class WireModel(BaseModel):
    """Base class for every shared wire primitive.

    Forward-compatibility rule (flagged decision FD-13): implementations
    MUST ignore unknown fields — ``extra="ignore"`` is set deliberately, not
    inherited by accident — so a newer counterparty can add fields without
    breaking an older one. The ``x_`` field-name prefix is reserved for
    vendor extensions and will never be claimed by the spec.
    """

    model_config = ConfigDict(extra="ignore")


class Money(WireModel):
    """Exact money amount in integer micros (flagged decision FD-11).

    ``1_000_000`` micros = 1 currency unit — the ad-industry convention
    (Google Ad Manager, among others, prices in micros). Float is BANNED on
    the wire for money: IEEE 754 floating point is non-deterministic for
    money math (``0.1 + 0.2 != 0.3``, and repeated CPM — cost per mille —
    arithmetic accumulates error), and the two source repos used ``float``
    end-to-end; that defect must not be fossilized into the spec. Every
    price, rate, budget, and offer in the shared contract is a ``Money``.

    ``amount_micros`` is a strict integer: float inputs are rejected at
    validation time rather than silently truncated.
    """

    amount_micros: int = Field(
        strict=True,
        description="Amount in micros; 1,000,000 micros = 1 currency unit.",
    )
    currency: str = Field(
        default="USD",
        pattern=r"^[A-Z]{3}$",
        description="ISO 4217 alpha-3 currency code.",
    )

    @classmethod
    def from_decimal_str(cls, amount: str, currency: str = "USD") -> "Money":
        """Build a Money from a decimal string, e.g. ``Money.from_decimal_str("12.50")``.

        Uses :class:`decimal.Decimal` so ``"12.50"`` becomes exactly
        ``12_500_000`` micros with no float rounding on the way in.
        """
        micros = Decimal(amount) * 1_000_000
        if micros != micros.to_integral_value():
            raise ValueError(f"{amount!r} has more precision than micros can represent")
        return cls(amount_micros=int(micros), currency=currency)
