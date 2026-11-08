"""The agents' control plane, as values: each operation, what it takes, and what it answers.

Each control operation is a `ControlOp` declared once here: its method, its
path, its request model, and its answer model. Both agents register their
routes from these values (`control_route`, transport/operator.py), and the live
runner, the tests, and the e2e call them through `ControlClient`
(transport/client.py), which validates every answer with the operation's own
model, so a route and its reader can't drift apart. No control path is written
anywhere else. The module imports pydantic, the SDK, the pure values, and the
Web Bot Auth library's refusal vocabulary, so the runner reads the answers
without loading an HTTP framework.

Every error body either agent sends outside § 2.4 is an `ErrorBody`: a closed
`error` code and a `detail`. The codes are the control plane's (`ControlCode`),
the seller's identity boundary's own (`BoundaryReason`), and the library's
refusal reasons.

The buyer's `Outcome` is a discriminated union on `state`. Each variant carries
only its own fields, and every one names the authentication method it used.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from iab_agentic_primitives.web_bot_auth import Refusal
from openproposal import AssentEntry, ErrorObject, dump
from pydantic import (
    BaseModel,
    Field,
    PlainSerializer,
    PlainValidator,
    TypeAdapter,
    WithJsonSchema,
)

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
    #: A verified proposal that names no buyer, or another buyer than this one.
    WRONG_BUYER = "wrong-buyer"
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


#: An SDK value as the SDK writes it (`openproposal.dump`): a member it doesn't hold stays
#: absent, never null, which the SDK's own types refuse to read back.
WireEntry = Annotated[AssentEntry, PlainSerializer(dump, return_type=JsonObject)]
WireError = Annotated[ErrorObject, PlainSerializer(dump, return_type=JsonObject)]


class _Answer(Value):
    """A control-plane body: a `Value`, so a route and the runner read it strictly."""


class Health(_Answer):
    ok: bool


# The seller's controls


class IssueRequest(_Answer):
    """Issue a fresh proposal to this principal."""

    principal_id: str


class Issued(_Answer):
    proposal_id: str
    principal_id: str


#: TEST ONLY (seller/faults.py): how a fault breaks the signature of the seller's answers.
BreakingFault = Literal["strip", "unbound", "rebound", "wrong_digest"]
#: A fault, or `none`, which leaves the seller's answers as it signs them.
FaultName = Literal["none", BreakingFault]
#: Which answers a fault breaks: to a commit, or to a read of a proposal.
FaultTarget = Literal["commit", "read"]


class FaultMode(_Answer):
    """TEST ONLY: the fault the seller's answers carry, and which answers it breaks."""

    mode: FaultName
    on: FaultTarget = "commit"


# The buyer's controls


class KeyState(_Answer):
    """The buyer's keyring: the keys its directory publishes, and the one that signs."""

    published: list[str]
    active: str


class PublishedKey(KeyState):
    """Rotation, step 1: the key just published."""

    published_kid: str


class DirectorySignature(_Answer):
    """A signature of the buyer's directory that cfbot verified."""

    label: str
    keyid: str


class CfbotAccepted(_Answer):
    """cfbot verified the signature (cfbot/server.mjs `verifyRequest`)."""

    ok: Literal[True]
    verifier: str
    #: The origin the signature established.
    identity: str
    keyid: str
    nonce: str
    directory_signatures: list[DirectorySignature]
    content_digest_matches: bool


class CfbotRefused(_Answer):
    """cfbot refused the signature, and why."""

    ok: Literal[False]
    error: str


#: cfbot's verdict on a request the buyer signed, told apart by `ok`.
CfbotVerdict = Annotated[CfbotAccepted | CfbotRefused, Field(discriminator="ok")]
#: Reads a verdict from cfbot's answer.
CFBOT_VERDICT: TypeAdapter[CfbotAccepted | CfbotRefused] = TypeAdapter(CfbotVerdict)


class CloudflareCheck(_Answer):
    """cfbot's answer to a request the buyer signed: its status and its verdict."""

    status: int
    verdict: CfbotVerdict


class ReadTrigger(_Answer):
    """Read an issued proposal and verify the seller's answer."""

    #: The seller's origin; the buyer's `peer_seller_origin` when omitted.
    seller: Origin | None = None
    proposal_id: str
    credential: AuthMethod = "web_bot_auth"


class CommitTrigger(ReadTrigger):
    """Read, commit to these line items, and keep the agreement."""

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
    entries: tuple[WireEntry, ...]
    attributed: bool
    commit_id: int
    #: The kept answer (persistence/evidence.py).
    evidence_id: int


class Rejected(_Answer):
    """The seller said no, in a verified § 2.4 `errors[]` answer."""

    state: Literal["rejected"] = "rejected"
    seller: SellerView
    authentication_method: AuthMethod
    errors: tuple[WireError, ...]
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

    @property
    def code(self) -> str:
        """The reason's code, as the answer carries it."""
        return code_of(self.reason)


#: What the buyer's read and commit answer.
Outcome = Annotated[Read | Agreed | Rejected | Refused, Field(discriminator="state")]
#: Reads an `Outcome` from JSON.
OUTCOME: TypeAdapter[Read | Agreed | Rejected | Refused] = TypeAdapter(Outcome)


# cfbot's controls (cfbot/server.mjs): each has cfbot sign a request to the seller.


class CfbotTrigger(_Answer):
    """The proposal cfbot reads, or commits to."""

    proposal_id: str


class CfbotRun(_Answer):
    """The seller's answer to the request cfbot signed: its status and its JSON body."""

    status: int
    body: JsonValue


# The operations

Method = Literal["GET", "POST", "PUT", "DELETE"]


@dataclass(frozen=True)
class ControlOp[B: BaseModel | None, A]:
    """One control operation: how it is called, what it takes, and what it answers."""

    method: Method
    #: The path, with `{name}` for each path parameter.
    path: str
    #: The body it takes; None for an operation that takes none.
    request_model: type[B] | None
    answer_model: TypeAdapter[A]

    def url(self, **params: str) -> str:
        """The path with each parameter filled in."""
        return self.path.format(**params)


#: Whether the agent is up; every agent answers it, with no operator key.
HEALTH: ControlOp[None, Health] = ControlOp("GET", "/health", None, TypeAdapter(Health))
#: The seller issues a fresh copy of its seed proposal to a principal it knows (§ 4.3).
ISSUE: ControlOp[IssueRequest, Issued] = ControlOp(
    "POST", "/operator/issue", IssueRequest, TypeAdapter(Issued)
)
#: TEST ONLY: sets the seller's fault (seller/faults.py).
FAULT: ControlOp[FaultMode, FaultMode] = ControlOp(
    "PUT", "/test/fault", FaultMode, TypeAdapter(FaultMode)
)
#: The buyer reads an issued proposal and verifies the seller's signed answer.
READ: ControlOp[ReadTrigger, Read | Agreed | Rejected | Refused] = ControlOp(
    "POST", "/operator/read", ReadTrigger, OUTCOME
)
#: The buyer reads, commits, verifies the signed answer, and keeps the agreement.
COMMIT: ControlOp[CommitTrigger, Read | Agreed | Rejected | Refused] = ControlOp(
    "POST", "/operator/commit", CommitTrigger, OUTCOME
)
#: The buyer's keyring.
KEYS: ControlOp[None, KeyState] = ControlOp("GET", "/operator/keys", None, TypeAdapter(KeyState))
#: Rotation, step 1: publish a new key beside the one that signs.
PUBLISH: ControlOp[None, PublishedKey] = ControlOp(
    "POST", "/operator/keys", None, TypeAdapter(PublishedKey)
)
#: Rotation, step 2: sign with the key `kid`.
ACTIVATE: ControlOp[None, KeyState] = ControlOp(
    "POST", "/operator/keys/{kid}/activate", None, TypeAdapter(KeyState)
)
#: Rotation, step 3: take the key `kid` out of the directory.
RETIRE: ControlOp[None, KeyState] = ControlOp(
    "DELETE", "/operator/keys/{kid}", None, TypeAdapter(KeyState)
)
#: The buyer signs a request to cfbot and answers its verdict.
CLOUDFLARE_CHECK: ControlOp[None, CloudflareCheck] = ControlOp(
    "POST", "/operator/cloudflare-check", None, TypeAdapter(CloudflareCheck)
)
#: cfbot asks the seller who it is.
CFBOT_WHOAMI: ControlOp[None, CfbotRun] = ControlOp(
    "POST", "/run/whoami", None, TypeAdapter(CfbotRun)
)
#: cfbot reads a proposal.
CFBOT_READ: ControlOp[CfbotTrigger, CfbotRun] = ControlOp(
    "POST", "/run/read", CfbotTrigger, TypeAdapter(CfbotRun)
)
#: cfbot commits to a proposal.
CFBOT_COMMIT: ControlOp[CfbotTrigger, CfbotRun] = ControlOp(
    "POST", "/run/commit", CfbotTrigger, TypeAdapter(CfbotRun)
)
