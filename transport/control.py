"""The agents' control plane, as types: what each `/operator/` route takes and answers.

Both agents declare their routes with these models, and the live runner reads
every answer through the same ones, so a route and its reader can't drift
apart. The module imports pydantic and the pure values only, so the runner
reads the answers without loading an HTTP framework.

The buyer's `Outcome` is a discriminated union on `state`. Each variant carries
only its own fields, and every one names the authentication method it used.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter

from persistence.values import AuthMethod, Origin
from protocol.values import JsonObject, JsonValue, Value

#: The header every control call carries the operator key in (transport/operator.py).
OPERATOR_HEADER = "X-Operator-Key"


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
    #: The library's refusal code, or the buyer's own (buyer/refusal.py).
    reason: str
    detail: str


#: What `/operator/read` and `/operator/commit` answer.
Outcome = Annotated[Read | Agreed | Rejected | Refused, Field(discriminator="state")]
#: Reads an `Outcome` from JSON, as the runner does.
OUTCOME: TypeAdapter[Read | Agreed | Rejected | Refused] = TypeAdapter(Outcome)
