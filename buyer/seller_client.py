"""The buyer's one client to a seller: transport in, typed answers out.

It is the buyer's mirror of the seller's identity boundary. Every answer is
verified first: the seller's signature, against the origin this buyer knows the
seller by, and, for a signed request, its binding to the request. Then the
answer is parsed as the document its status says it is: a `Proposal`, a
`CommitResult`, or a § 2.4 `errors[]`. Verification and parsing run inside one
refusal boundary, so whatever the seller sends comes back as a value
(`ReadProposal`, `Accepted`, `Rejection`) or as a `Refusal`, never as an
exception. No HTTP status leaves this module.

Every call goes through the client the buyer's lifespan owns (buyer/app.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
from iab_agentic_primitives.web_bot_auth import (
    HTTPRequest,
    HTTPResponse,
    KeyResolver,
    ResponseVerifier,
    VerifiedResponse,
    WebBotAuthError,
)
from iab_agentic_primitives.web_bot_auth.httpx import verified_response
from openproposal import CommitResult, ErrorObject, Proposal
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from persistence.evidence import StoredRequest, StoredResponse
from protocol.operations import RECEIVE, parse_errors, parse_result
from protocol.values import JsonObject

from .credentials import BuyerCredential
from .refusal import Reason, Refusal
from .repository import Counterparty

#: The client every call goes through. The rest of the buyer holds one and passes it
#: here; only this module, buyer/credentials.py, and buyer/cfbot.py touch httpx.
HTTPClient = httpx.AsyncClient

_JSON_OBJECT: TypeAdapter[JsonObject] = TypeAdapter(JsonObject)


class _BoundaryRefusal(BaseModel):
    """The seller's identity-boundary refusal body (`{"error", "detail"}`)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    error: str
    detail: str


class _Unsigned(Exception):
    """The auth let an answer through without a verified signature."""

    def __init__(self) -> None:
        super().__init__("the answer carries no verified signature")


@dataclass(frozen=True)
class Exchange:
    """One request and the verified answer to it, as sent and as received."""

    #: The request as sent, which the answer is bound to. A bearer token is left out.
    request: HTTPRequest
    #: The answer as received: its status, its header lines in order and case, its body.
    response: HTTPResponse
    verified: VerifiedResponse
    #: The key that signed the request, or None for a bearer request.
    keyid: str | None

    def evidence(self, buyer_origin: str) -> StoredResponse:
        """The answer as the buyer keeps it (§ 4.1.2), with the request it is bound to."""
        directory = self.verified.directory
        return StoredResponse(
            response=self.response,
            request=StoredRequest(self.request, buyer_origin, self.keyid),
            origin=str(self.verified.origin),
            keyid=self.verified.keyid,
            directory=None if directory is None else directory.evidence,
        )


@dataclass(frozen=True)
class ReadProposal:
    """The proposal the seller answered with: typed to decide on, raw to digest."""

    proposal: Proposal
    #: The proposal as received, unknown members and all: the digest input (§ 4.1.1).
    raw: JsonObject
    exchange: Exchange


@dataclass(frozen=True)
class Accepted:
    """A verified answer to a commit that parses as a `CommitResult`. The buyer still
    checks that it answers its own commit (`protocol.operations.check_result`)."""

    result: CommitResult
    exchange: Exchange


@dataclass(frozen=True)
class Rejection:
    """A verified § 2.4 `errors[]` answer: the seller said no."""

    errors: list[ErrorObject]
    exchange: Exchange


def _lines(headers: httpx.Headers) -> list[tuple[str, str]]:
    """Header lines exactly as sent or received: `raw` keeps each name's case."""
    return [(k.decode("latin-1"), v.decode("latin-1")) for k, v in headers.raw]


def _refusal(error: Exception) -> Refusal:
    """What the buyer says about an answer it can't take."""
    if isinstance(error, WebBotAuthError):
        return Refusal(error.reason, f"the seller's answer is refused: {error.reason}: {error}")
    if isinstance(error, httpx.HTTPError):
        return Refusal(Reason.UNREACHABLE, f"the seller didn't answer: {error}")
    return Refusal(Reason.MALFORMED_ANSWER, f"the seller's answer doesn't parse: {error}")


#: What verifying and parsing an answer can raise. Each one becomes a `Refusal`:
#: ValueError covers pydantic's ValidationError, ProtocolViolation, a JSON or UTF-8
#: decoding error, and `_Unsigned` is the auth's own guarantee failing.
_REFUSED = (WebBotAuthError, httpx.HTTPError, ValueError, _Unsigned)


def _rejection(exchange: Exchange) -> Rejection | Refusal:
    """A non-200 answer: the seller's § 2.4 errors, or its boundary refusing the credential."""
    body = exchange.response.body
    try:
        return Rejection(parse_errors(body), exchange)
    except ValidationError:
        refused = _BoundaryRefusal.model_validate_json(body)  # neither form: malformed
    return Refusal(
        Reason.CREDENTIAL_REFUSED,
        f"the seller refused the credential: {exchange.response.status} {refused.error}: "
        f"{refused.detail}",
    )


def _proposal(seller: Counterparty, exchange: Exchange) -> ReadProposal | Refusal:
    body = exchange.response.body
    # The typed value decides; the raw JSON, unknown members and all, is the digest input.
    proposal = Proposal.model_validate_json(body, context=RECEIVE)
    raw = _JSON_OBJECT.validate_python(json.loads(body))
    if proposal.seller.domain != seller.domain:
        return Refusal(
            Reason.WRONG_SELLER,
            f"the proposal names seller {proposal.seller.domain}, not {seller.domain}",
        )
    return ReadProposal(proposal, raw, exchange)


class SellerClient:
    """Sends the buyer's requests to a seller, and verifies and parses each answer."""

    def __init__(self, http: HTTPClient, resolver: KeyResolver) -> None:
        self._http = http
        self._verifier = ResponseVerifier(resolver)

    async def read(
        self, seller: Counterparty, credential: BuyerCredential, proposal_id: str
    ) -> ReadProposal | Rejection | Refusal:
        """`GET /proposals/{id}`: the issued proposal, or the seller's errors."""
        try:
            exchange = await self._send(seller, credential, "GET", f"/proposals/{proposal_id}")
            if exchange.response.status != httpx.codes.OK:
                return _rejection(exchange)
            return _proposal(seller, exchange)
        except _REFUSED as e:
            return _refusal(e)

    async def commit(
        self, seller: Counterparty, credential: BuyerCredential, proposal_id: str, body: bytes
    ) -> Accepted | Rejection | Refusal:
        """`POST /proposals/{id}/commit` with the `Commit` body, sent as stored."""
        try:
            exchange = await self._send(
                seller, credential, "POST", f"/proposals/{proposal_id}/commit", body
            )
            if exchange.response.status != httpx.codes.OK:
                return _rejection(exchange)
            return Accepted(parse_result(exchange.response.body), exchange)
        except _REFUSED as e:
            return _refusal(e)

    async def _send(
        self,
        seller: Counterparty,
        credential: BuyerCredential,
        method: str,
        path: str,
        body: bytes = b"",
    ) -> Exchange:
        """The one send path: the request with its credential, and the verified answer."""
        url = f"{seller.origin}{path}"
        headers = {"Content-Type": "application/json"} if body else {}
        response = await self._http.request(
            method,
            url,
            content=body,
            headers=headers | credential.headers(),
            auth=credential.auth(self._verifier, seller.origin),
        )
        verified = verified_response(response)
        if verified is None:  # the auth refuses an unsigned answer, so this can't happen
            raise _Unsigned
        sent = [(k, v) for k, v in _lines(response.request.headers) if k.lower() != "authorization"]
        request = HTTPRequest(method, url, sent, body)
        return Exchange(
            request=request,
            response=HTTPResponse(
                response.status_code, _lines(response.headers), response.content, request
            ),
            verified=verified,
            keyid=credential.keyid,
        )
