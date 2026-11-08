"""The agents' control plane, as types: what each `/operator/` route takes and answers.

Both agents declare their routes with these models, and the live runner reads
every answer through the same ones, so a route and its reader can't drift
apart. The module imports pydantic, the SDK, the pure values, and the Web Bot
Auth library's refusal vocabulary, so the runner reads the answers without
loading an HTTP framework.

Every error body either agent sends outside § 2.4 is an `ErrorBody`: a closed
`error` code and a `detail`. The codes are the control plane's (`ControlCode`),
the seller's identity boundary's own (`BoundaryReason`), and the library's
refusal reasons.

The buyer's `Outcome` is a discriminated union on `state`. Each variant carries
only its own fields, and every one names the authentication method it used.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from iab_agentic_primitives.web_bot_auth import Refusal
from pydantic import Field, PlainSerializer, PlainValidator, TypeAdapter, WithJsonSchema

from persistence.values import AuthMethod, Origin
from protocol.values import JsonObject, JsonValue, Value

#: The header every control call carries the operator key in (transport/operator.py).
OPERATOR_HEADER = "X-Operator-Key"


# The error vocabulary

#: Why a control call fails, or a route the agent doesn't serve.
ControlCode = Literal[
    "operator-key",
    "validation",
    "not-found",
    "method-not-allowed",
    "bad-request",
    "unknown-principal",
    "rotation",
    "not-pending",
    "cfbot-unreachable",
    "cfbot-malformed",
    "internal",
]
#: The seller's identity boundary's own refusals, beside the library's for a signature.
BoundaryReason = Literal["invalid-authorization", "two-credentials", "invalid-token"]
#: The library's answer to a response it can't sign (its `ResponseSigningMiddleware`).
UnsignableCode = Literal["response-unsignable"]


def _refusal(value: object) -> Refusal:
    """A `Refusal` as given, or the one whose reason code `value` is; else `ValueError`."""
    return value if isinstance(value, Refusal) else Refusal.of(str(value))


#: A library refusal, read from its reason code and written as it.
RefusalCode = Annotated[
    Refusal,
    PlainValidator(_refusal),
    PlainSerializer(lambda refusal: refusal.code, return_type=str),
    WithJsonSchema({"type": "string", "enum": sorted(r.code for r in Refusal)}),
]


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


#: Why the buyer refused: its own reason, or the library's refusal of the seller's answer.
BuyerReason = Reason | RefusalCode


def code_of(reason: str | Refusal) -> str:
    """The code a reason goes on the wire as."""
    return reason.code if isinstance(reason, Refusal) else str(reason)


class ErrorBody(Value):
    """Every error body outside § 2.4: `{"error": <code>, "detail": <text>}`."""

    error: ControlCode | BoundaryReason | UnsignableCode | RefusalCode
    detail: str

    @property
    def code(self) -> str:
        return code_of(self.error)


class _Answer(Value):
    """A control-plane body: a `Value`, so a route and the runner read it strictly."""


class Health(_Answer):
    ok: bool


# The seller's controls


class IssueRequest(_Answer):
    """`POST /operator/issue`: issue a fresh proposal to this principal."""

    principal_id: str


class Issued(_Answer):
    proposal_id: str
    principal_id: str


# The buyer's controls


class KeyState(_Answer):
    """The buyer's keyring: the keys its directory publishes, and the one that signs."""

    published: list[str]
    active: str


class PublishedKey(KeyState):
    """Rotation, step 1: the key just published."""

    published_kid: str


class CloudflareCheck(_Answer):
    """cfbot's answer to a request the buyer signed: its status and its verdict."""

    status: int
    verdict: JsonValue


class ReadTrigger(_Answer):
    """`POST /operator/read`: read an issued proposal and verify the seller's answer."""

    #: The seller's origin; the buyer's `peer_seller_origin` when omitted.
    seller: Origin | None = None
    proposal_id: str
    credential: AuthMethod = "web_bot_auth"


class CommitTrigger(ReadTrigger):
    """`POST /operator/commit`: read, commit to these line items, and keep the agreement."""

    line_item_ids: Annotated[list[str], Field(min_length=1)]


class SellerView(_Answer):
    """The seller an outcome is about, as the buyer's own records hold it."""

    origin: Origin
    domain: str
    legal_name: str


class Read(_Answer):
    """The seller's signed answer verified, and it holds the proposal."""

    state: Literal["read"] = "read"
    seller: SellerView
    authentication_method: AuthMethod
    keyid: str | None
    #: The proposal as received, unknown members and all.
    proposal: JsonObject


class Agreed(_Answer):
    """The seller's signed `CommitResult` verified and matched; the buyer kept it."""

    state: Literal["agreed"] = "agreed"
    proposal_id: str
    seller: SellerView
    authentication_method: AuthMethod
    #: The key that signed the commit, or None for a bearer commit.
    keyid: str | None
    record_digest: str
    entries: list[JsonObject]
    attributed: bool
    commit_id: int
    #: The kept answer (persistence/evidence.py).
    evidence_id: int


class Rejected(_Answer):
    """The seller said no, in a verified § 2.4 `errors[]` answer."""

    state: Literal["rejected"] = "rejected"
    seller: SellerView
    authentication_method: AuthMethod
    errors: list[JsonObject]
    #: The commit the errors answer; None for a read.
    commit_id: int | None = None


class Refused(_Answer):
    """The buyer said no: to the trigger, or to what the seller sent. It kept nothing."""

    state: Literal["refused"] = "refused"
    #: None when the trigger names no seller this buyer deals with.
    seller: SellerView | None
    authentication_method: AuthMethod
    #: The buyer's own reason, or the library's refusal of the seller's answer.
    reason: BuyerReason
    detail: str


#: What `/operator/read` and `/operator/commit` answer.
Outcome = Annotated[Read | Agreed | Rejected | Refused, Field(discriminator="state")]
#: Reads an `Outcome` from JSON, as the runner does.
OUTCOME: TypeAdapter[Read | Agreed | Rejected | Refused] = TypeAdapter(Outcome)
