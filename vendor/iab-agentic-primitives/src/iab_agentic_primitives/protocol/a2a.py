"""A2A (Agent-to-Agent protocol) transport envelope: JSON-RPC 2.0,
standardized on the ``message/send`` method.

JSON-RPC = JSON (JavaScript Object Notation) Remote Procedure Call, the
request/response envelope the A2A specification builds on.

The two repos spoke two incompatible JSON-RPC dialects: the buyer's
``clients/a2a_client.py`` sent the A2A-spec method ``message/send`` with
``params.message`` (``messageId``/``role``/``parts``), while the seller's
``clients/a2a_client.py`` sent a homegrown method ``"call"`` with
``params.request``. Canonical decision: the A2A-spec-conformant dialect
wins — the ONE method is ``message/send`` and the message shape below
follows the A2A specification. The ``"call"`` dialect is retired and MUST
be answered with JSON-RPC error ``-32601`` (method not found).

Field naming: the A2A specification is an external standard that uses
camelCase on the wire (``messageId``, ``contextId``, ``taskId``), so —
as the one documented exception to the contract's snake_case rule (G1 in
RECONCILIATION.md) — these models declare camelCase serialization
aliases. Serialize with ``model_dump(by_alias=True)`` /
``model_dump_json(by_alias=True)``; validation accepts either spelling
(``populate_by_name=True``).

Discovery: the agent card for A2A discovery is served at
``GET /.well-known/agent.json`` — see
:mod:`iab_agentic_primitives.protocol.agent_card`.
"""

from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from ..primitives import WireModel

#: The ONE canonical JSON-RPC method for agent messaging.
A2A_METHOD_MESSAGE_SEND = "message/send"

#: JSON-RPC 2.0 reserved error code servers MUST answer for the retired
#: seller dialect (method "call") and any other unknown method.
JSONRPC_METHOD_NOT_FOUND = -32601


class A2AWireModel(WireModel):
    """Base for A2A envelope models: camelCase aliases, either spelling in."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class A2APart(A2AWireModel):
    """One part of an A2A message: text or structured data."""

    kind: Literal["text", "data"]
    text: str | None = Field(default=None, description="Set when kind == 'text'.")
    data: dict[str, Any] | None = Field(default=None, description="Set when kind == 'data'.")

    @model_validator(mode="after")
    def _kind_consistency(self) -> "A2APart":
        if self.kind == "text" and self.text is None:
            raise ValueError("part kind 'text' requires text")
        if self.kind == "data" and self.data is None:
            raise ValueError("part kind 'data' requires data")
        return self


class A2AMessage(A2AWireModel):
    """An A2A message (the A2A-spec shape the buyer already sent)."""

    message_id: str = Field(alias="messageId", description="Sender-minted unique message id.")
    role: Literal["user", "agent"] = "user"
    parts: list[A2APart] = Field(min_length=1)


class MessageSendParams(A2AWireModel):
    """``params`` object for the ``message/send`` method."""

    message: A2AMessage
    context_id: str | None = Field(
        default=None,
        alias="contextId",
        description="Continues a multi-turn conversation; None starts one.",
    )


class JsonRpcRequest(A2AWireModel):
    """JSON-RPC 2.0 request envelope, pinned to ``message/send``.

    ``method`` is a Literal: the seller's retired ``"call"`` dialect does
    not validate against this model by construction.
    """

    jsonrpc: Literal["2.0"] = "2.0"
    id: str = Field(description="Caller-minted request id, echoed in the response.")
    method: Literal["message/send"] = A2A_METHOD_MESSAGE_SEND
    params: MessageSendParams


class A2AResult(A2AWireModel):
    """``result`` object of a successful ``message/send`` response."""

    task_id: str = Field(default="", alias="taskId")
    context_id: str = Field(
        default="",
        alias="contextId",
        description="Echo/mint of the conversation context for multi-turn.",
    )
    role: Literal["user", "agent"] = "agent"
    parts: list[A2APart] = Field(default_factory=list)


class JsonRpcError(A2AWireModel):
    """JSON-RPC 2.0 error object (protocol-level errors only; domain
    errors ride inside ``result`` parts using the shared error envelope)."""

    code: int
    message: str
    data: Any = None


class JsonRpcResponse(A2AWireModel):
    """JSON-RPC 2.0 response envelope: exactly one of result/error."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: str
    result: A2AResult | None = None
    error: JsonRpcError | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> "JsonRpcResponse":
        if (self.result is None) == (self.error is None):
            raise ValueError("JsonRpcResponse requires exactly one of result/error")
        return self


__all__ = [
    "A2A_METHOD_MESSAGE_SEND",
    "JSONRPC_METHOD_NOT_FOUND",
    "A2AMessage",
    "A2APart",
    "A2AResult",
    "A2AWireModel",
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "MessageSendParams",
]
