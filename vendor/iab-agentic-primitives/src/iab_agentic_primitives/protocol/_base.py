"""Shared base classes for the protocol messages.

Idempotency (flagged decision FD-12): every money-mutating request in the
contract — quote create, deal booking, negotiation counter, change request —
inherits :class:`IdempotentRequest` and therefore carries a REQUIRED
``idempotency_key``. Replay semantics: if a server receives a request whose
``idempotency_key`` it has already processed, it MUST return the same
response it returned the first time and MUST NOT repeat the side effect
(no duplicate quote, deal, negotiation round, or change request). A reused
key with a *different* request body is an error
(:class:`~iab_agentic_primitives.protocol.errors.ErrorCode.IDEMPOTENCY_CONFLICT`).
Keys are opaque strings minted by the requester (a UUID — universally
unique identifier — is recommended) and scoped per buyer/seller pair.
"""

from pydantic import Field

from ..primitives import WireModel


class IdempotentRequest(WireModel):
    """Base class for every money-mutating request envelope (FD-12).

    ``idempotency_key`` is deliberately required with no default: a
    retried request that cannot be deduplicated is how duplicate deals
    get booked, so the field cannot be omitted or auto-minted silently
    by the model layer.
    """

    idempotency_key: str = Field(
        min_length=1,
        description=(
            "Requester-minted opaque key (UUID recommended). Same key -> "
            "same response, no duplicate side effects (FD-12). Reusing a "
            "key with a different body is an idempotency_conflict error."
        ),
    )
