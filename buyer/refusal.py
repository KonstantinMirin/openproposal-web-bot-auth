"""The buyer's refusal: what it says when it won't act on a trigger or on a seller's answer.

The buyer mirrors the seller's identity boundary. Whatever it can't verify,
parse, or match, it refuses, and a refusal is a value the flow returns, never
an exception that escapes as a 500. A refusal keeps nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Reason(StrEnum):
    """Why the buyer refuses, when the library's own refusal codes don't say."""

    #: The trigger names a seller this buyer has no record of.
    UNKNOWN_SELLER = "unknown-seller"
    #: The trigger names a line item the buyer's plan has no writes for.
    UNKNOWN_LINE_ITEM = "unknown-line-item"
    #: A bearer call to a seller that issued this buyer no token.
    NOT_ISSUED = "credential-not-issued"
    #: The seller didn't answer.
    UNREACHABLE = "unreachable"
    #: A verified answer that isn't the document its status says it is.
    MALFORMED_ANSWER = "malformed-answer"
    #: A verified proposal that names another seller.
    WRONG_SELLER = "wrong-seller"
    #: The seller's identity boundary refused the buyer's credential.
    CREDENTIAL_REFUSED = "credential-refused"
    #: The seller answered the read of the proposal to commit to with an error.
    UNREADABLE_PROPOSAL = "unreadable-proposal"
    #: A verified `CommitResult` that doesn't answer the buyer's `commit` (§ 4.1.2, § 5.6.1).
    RESULT_MISMATCH = "result-mismatch"


@dataclass(frozen=True)
class Refusal:
    """The buyer won't go on: `reason` is a `Reason` or the library's refusal code."""

    reason: str
    detail: str
