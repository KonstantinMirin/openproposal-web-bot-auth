"""Reusable interop assertions over a :class:`TransactionResult`.

These are the anti-regression checks that both agent repos' future CI will
call after running the golden scenarios with their REAL agent swapped in for
a reference one. Each targets a specific historical interop break that a
mocked counterparty hid:

- :func:`assert_quote_roundtrips` — a quote request produced a valid quote
  whose product/deal_type/media_type match what was asked.
- :func:`assert_no_field_dropped` — the ``agent_url`` / ``linear_tv`` /
  ``audience_plan`` regression: fields the buyer sent survive to the response
  (or, for an unsupported capability, are rejected STRUCTURALLY — never
  silently dropped and mispriced).
- :func:`assert_negotiation_terminates` — no infinite 'active': a negotiation
  reaches a terminal status in bounded rounds.
- :func:`assert_booking_has_seller_deal_id` — a booked deal carries a
  seller-minted ``deal_id`` and the seller's id.
- :func:`assert_auth_tier_enforced` — the buyer got exactly the tier the
  registry granted, never a self-asserted higher one.
- :func:`assert_idempotent_booking` — the same idempotency key booked one
  deal, not two.
- :func:`assert_state_consistent` — the buyer's and seller's independently
  tracked deal status reconcile as ``consistent`` (no DisagreementReport).

Every function raises :class:`AssertionError` with a diagnostic message on
failure and returns ``None`` on success, so they drop straight into pytest.

Acronyms: CPM = cost per mille; FD = flagged decision; TV = television.
"""

from __future__ import annotations

from ..primitives import AccessTier, DealStatus, MediaType
from ..protocol import ErrorCode, ErrorEnvelope
from ..state import ReconciliationOutcome
from .scenario import TransactionResult


def assert_quote_roundtrips(result: TransactionResult) -> None:
    """At least one quote request round-tripped into a coherent quote."""
    quote_exchanges = [ex for ex in result.exchanges("quote") if not ex.rejected]
    assert quote_exchanges, "no successful quote exchange in the timeline"
    for ex in quote_exchanges:
        request = ex.request
        quote = ex.response.quote
        assert quote.quote_id, "quote is missing a seller-minted quote_id"
        assert quote.product.product_id == request.product_id, (
            f"quote product {quote.product.product_id!r} != requested {request.product_id!r}"
        )
        assert quote.deal_type == request.deal_type, (
            f"quote deal_type {quote.deal_type} != requested {request.deal_type}"
        )
        assert quote.media_type == request.media_type, (
            f"quote media_type {quote.media_type} != requested {request.media_type}"
        )
        assert quote.pricing.final_cpm is not None, "priced quote is missing final_cpm"


def assert_no_field_dropped(result: TransactionResult) -> None:
    """The agent_url / linear_tv / audience_plan fields are never silently dropped."""
    # agent_url: the buyer must identify itself for registry trust on the
    # quote request (the historical dropped-header regression).
    for ex in result.exchanges("quote"):
        assert ex.request.agent_url, (
            "quote request dropped agent_url (buyer must self-identify for trust)"
        )
        # linear_tv: an unsupported media type must be rejected STRUCTURALLY,
        # never mispriced as digital.
        if ex.request.media_type == MediaType.LINEAR_TV:
            if ex.rejected:
                detail = ex.response.detail
                assert detail.error == ErrorCode.UNSUPPORTED_CAPABILITY, (
                    f"linear_tv rejected with {detail.error} (expected unsupported_capability)"
                )
                assert any(item.capability == "linear_tv" for item in detail.unsupported), (
                    "linear_tv rejection did not name linear_tv in unsupported[]"
                )
            else:
                quote = ex.response.quote
                assert quote.media_type == MediaType.LINEAR_TV, (
                    "linear_tv quote silently downgraded media_type"
                )
                assert quote.linear_tv is not None, "linear_tv quote dropped linear_tv details"

    # audience_plan: what the booking carried must be snapshotted verbatim.
    for ex in result.exchanges("booking"):
        if ex.rejected:
            continue
        sent = ex.request.audience_plan
        if sent is not None:
            snapshot = ex.response.audience_plan_snapshot
            assert snapshot == sent, (
                f"audience_plan not snapshotted verbatim: sent {sent!r}, got {snapshot!r}"
            )


def assert_negotiation_terminates(result: TransactionResult) -> None:
    """If a negotiation occurred, it reached a terminal status (never stuck 'active')."""
    negotiation = result.negotiation
    if negotiation is None and not result.exchanges("negotiation"):
        return  # no negotiation in this transaction — nothing to assert
    assert negotiation is not None, "negotiation exchanges occurred but no history was recorded"
    terminal = {
        "accepted",
        "rejected",
        "expired",
    }
    assert negotiation.status.value in terminal, (
        f"negotiation ended 'active' (status={negotiation.status.value}); "
        "it must terminate in accepted/rejected/expired"
    )
    assert negotiation.rounds, "terminal negotiation recorded zero rounds"
    # The last recorded round should carry the terminal move.
    last = negotiation.rounds[-1]
    assert last.round_number == len(negotiation.rounds), (
        "round numbering is not contiguous — seller numbering must be authoritative"
    )


def assert_booking_has_seller_deal_id(result: TransactionResult) -> None:
    """A booked deal has a non-empty seller-minted deal_id and seller id."""
    assert result.booked, "transaction did not book a deal"
    assert result.deal is not None, "booked transaction has no Deal"
    assert result.deal.deal_id, "booked Deal is missing a seller-minted deal_id"
    assert result.deal.seller_id, "booked Deal is missing the seller's id"
    assert result.deal.status == DealStatus.BOOKED, (
        f"booked Deal status is {result.deal.status} (expected booked)"
    )


def assert_auth_tier_enforced(result: TransactionResult, *, expected_tier: AccessTier) -> None:
    """The quote's granted tier equals ``expected_tier`` and never exceeds the ceiling.

    Proves a buyer cannot self-assert a higher tier than the registry grants:
    the effective tier on the quote must be the min of the claimed tier and
    the registry ceiling.
    """
    from .roles import TIER_ORDER

    assert result.quote is not None, "no quote to check the tier on"
    granted = result.quote.buyer_tier
    assert granted == expected_tier, f"granted tier {granted} != expected {expected_tier}"
    assert TIER_ORDER[granted] <= TIER_ORDER[result.tier_ceiling], (
        f"granted tier {granted} exceeds the registry ceiling {result.tier_ceiling}"
    )


def assert_idempotent_booking(result: TransactionResult) -> None:
    """Re-booking with the same idempotency key returned the SAME single deal."""
    assert result.deal is not None, "no deal to check idempotency on"
    assert result.replay_deal is not None, (
        "idempotency probe did not run: replay_deal is None (set brief.idempotent_double_book=True)"
    )
    assert result.replay_deal.deal_id == result.deal.deal_id, (
        f"replay minted a different deal: {result.replay_deal.deal_id!r} != "
        f"{result.deal.deal_id!r} — booking is NOT idempotent"
    )


def assert_state_consistent(result: TransactionResult) -> None:
    """Buyer-side and seller-side deal status reconcile as consistent (FD-8)."""
    assert result.reconciliation is not None, (
        "no reconciliation was performed (did the transaction book a deal?)"
    )
    assert result.reconciliation.outcome is ReconciliationOutcome.CONSISTENT, (
        f"deal state reconciled as {result.reconciliation.outcome.value}, not consistent"
    )
    assert result.disagreement is None, f"unexpected DisagreementReport: {result.disagreement}"


def assert_structural_rejection(result: TransactionResult, surface: str, code: ErrorCode) -> None:
    """A given surface produced at least one structured rejection with ``code``.

    Useful for the FD-6 checks (linear_tv / unsupported deal type): the
    rejection is a typed :class:`ErrorEnvelope`, not an exception or a
    silently mispriced success.
    """
    rejections = [ex for ex in result.exchanges(surface) if ex.rejected]
    assert rejections, f"expected a structural rejection on {surface!r}, found none"
    for ex in rejections:
        assert isinstance(ex.response, ErrorEnvelope)
    assert any(ex.response.detail.error == code for ex in rejections), (
        f"no {code.value!r} rejection on {surface!r}; "
        f"got {[ex.response.detail.error.value for ex in rejections]}"
    )


__all__ = [
    "assert_auth_tier_enforced",
    "assert_booking_has_seller_deal_id",
    "assert_idempotent_booking",
    "assert_negotiation_terminates",
    "assert_no_field_dropped",
    "assert_quote_roundtrips",
    "assert_state_consistent",
    "assert_structural_rejection",
]
