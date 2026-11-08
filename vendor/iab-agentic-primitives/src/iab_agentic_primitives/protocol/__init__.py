"""Wire-protocol message definitions for the buyer <-> seller surfaces.

Defines the request/response messages and envelopes for the protocol
surfaces the two agents speak to each other: the catalog
(``GET /products``), the avails query (``POST /products/avails``), the
Deals API quote->book flow, negotiation
messages, the A2A (Agent-to-Agent protocol) JSON-RPC envelope, the Agent
Card discovery surface, and the ONE structured error envelope.
Request/response query messages that are capabilities rather than
persisted objects (for example an avails query) are classified here as
protocol messages, not primitives. Buyer and seller interoperate only
through these shared definitions, so the contract can no longer drift
silently between repos.

Every message envelope imports the shared primitives
(:mod:`iab_agentic_primitives.primitives`) — Quote, Deal, Negotiation,
Money, ... are never redefined here. Money-mutating requests inherit
:class:`~iab_agentic_primitives.protocol._base.IdempotentRequest` and
carry a required ``idempotency_key`` (flagged decision FD-12).

Surface-by-surface reconciliation decisions (which repo's shape won, what
broke, and why) are recorded in PROTOCOL_RECONCILIATION.md at the
repository root. The OpenAPI fragment for these endpoints is
``spec/openapi/iab-agentic-api.yaml``; the exported JSON Schemas live in
``spec/jsonschema/protocol/`` (regenerate with
``uv run python spec/jsonschema/protocol/generate.py``).
"""

from ._base import IdempotentRequest
from .a2a import (
    A2A_METHOD_MESSAGE_SEND,
    JSONRPC_METHOD_NOT_FOUND,
    A2AMessage,
    A2APart,
    A2AResult,
    A2AWireModel,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    MessageSendParams,
)
from .agent_card import AgentCard, AgentDiscoveryRequest, AgentTrustVerification
from .avails import (
    EXTENSION_DATASOURCE,
    TARGET_BUDGET,
    TARGET_IMPRESSIONS,
    TARGET_REQUESTED_IMPRESSIONS,
    Avails,
    AvailsCollection,
    AvailsRequest,
    AvailsResponse,
    AvailsStatus,
    AvailsStatusReason,
    AvailsStatusValue,
    AvailsWireModel,
    ProductAvailsSearch,
    ProductTargeting,
    TargetingDimension,
    TargetingUnit,
    avails_from_simplified,
    parse_avails_request,
    parse_avails_response,
)
from .catalog import ProductListRequest, ProductListResponse
from .deals import (
    ChangeRequestCreate,
    ChangeRequestResponse,
    DealBookingRequest,
    DealBookingResponse,
)
from .errors import ErrorCode, ErrorDetail, ErrorEnvelope, UnsupportedItem
from .negotiation import (
    PRICED_ACTIONS,
    TERMINAL_ACTIONS,
    NegotiationMessage,
    NegotiationRoundResponse,
)
from .quotes import QuoteRequest, QuoteResponse

# The protocol messages, in surface order. This mapping drives the
# JSON-Schema export (spec/jsonschema/protocol/generate.py) and the
# drift-guard test. The Agent Card itself is the Agent primitive and is
# exported with the primitives (spec/jsonschema/Agent.json), not here.
PROTOCOL_MESSAGES: dict[str, type] = {
    # catalog
    "ProductListRequest": ProductListRequest,
    "ProductListResponse": ProductListResponse,
    # avails — legacy simplified profile AND the published OpenDirect 2.1
    # shapes (request dialects discriminated by productids vs productid;
    # response dialect follows the request dialect)
    "AvailsRequest": AvailsRequest,
    "AvailsResponse": AvailsResponse,
    "ProductAvailsSearch": ProductAvailsSearch,
    "Avails": Avails,
    "AvailsCollection": AvailsCollection,
    # quotes
    "QuoteRequest": QuoteRequest,
    "QuoteResponse": QuoteResponse,
    # deals + change requests
    "DealBookingRequest": DealBookingRequest,
    "DealBookingResponse": DealBookingResponse,
    "ChangeRequestCreate": ChangeRequestCreate,
    "ChangeRequestResponse": ChangeRequestResponse,
    # negotiation
    "NegotiationMessage": NegotiationMessage,
    "NegotiationRoundResponse": NegotiationRoundResponse,
    # a2a
    "JsonRpcRequest": JsonRpcRequest,
    "JsonRpcResponse": JsonRpcResponse,
    # agent card / registry
    "AgentDiscoveryRequest": AgentDiscoveryRequest,
    "AgentTrustVerification": AgentTrustVerification,
    # errors
    "ErrorEnvelope": ErrorEnvelope,
}

__all__ = [
    "A2A_METHOD_MESSAGE_SEND",
    "EXTENSION_DATASOURCE",
    "JSONRPC_METHOD_NOT_FOUND",
    "PRICED_ACTIONS",
    "PROTOCOL_MESSAGES",
    "TARGET_BUDGET",
    "TARGET_IMPRESSIONS",
    "TARGET_REQUESTED_IMPRESSIONS",
    "TERMINAL_ACTIONS",
    "A2AMessage",
    "A2APart",
    "A2AResult",
    "A2AWireModel",
    "AgentCard",
    "AgentDiscoveryRequest",
    "AgentTrustVerification",
    "Avails",
    "AvailsCollection",
    "AvailsRequest",
    "AvailsResponse",
    "AvailsStatus",
    "AvailsStatusReason",
    "AvailsStatusValue",
    "AvailsWireModel",
    "ProductAvailsSearch",
    "ProductTargeting",
    "TargetingDimension",
    "TargetingUnit",
    "avails_from_simplified",
    "parse_avails_request",
    "parse_avails_response",
    "ChangeRequestCreate",
    "ChangeRequestResponse",
    "DealBookingRequest",
    "DealBookingResponse",
    "ErrorCode",
    "ErrorDetail",
    "ErrorEnvelope",
    "IdempotentRequest",
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "MessageSendParams",
    "NegotiationMessage",
    "NegotiationRoundResponse",
    "ProductListRequest",
    "ProductListResponse",
    "QuoteRequest",
    "QuoteResponse",
    "UnsupportedItem",
]
