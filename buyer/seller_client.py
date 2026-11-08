"""The buyer's one client to a seller: transport in, typed answers out.

It is the buyer's mirror of the seller's identity boundary. Every answer is
verified first: the seller's signature, against the origin this buyer knows the
seller by, and, for a signed request, its binding to the request. An answer
of any status that doesn't verify is refused: a failing signature with the
library's reason, never taken as no signature, and an unsigned answer as
`signature-missing`. Each verified answer keeps the instant it verified at, so
the evidence verifies again at that instant. Then the
answer is parsed as the document its status says it is: a `Proposal`, a
`CommitResult`, or a § 2.4 `errors[]`. Verification and parsing run inside one
refusal boundary, so whatever the seller sends comes back as a value
(`ReadProposal`, `Accepted`, `Rejection`) or as a `Refusal`, never as an
exception. No HTTP status leaves this module.

Every call goes through the client the buyer's lifespan owns (buyer/app.py),
with the auth `seller_call` builds (buyer/credentials.py), which always
verifies the answer against the seller's origin. It is the only way the buyer
sends to a seller.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from iab_agentic_primitives.web_bot_auth import (
    KeyResolver,
    ResponseVerifier,
    UnixSeconds,
    VerifiedResponse,
    system_clock,
)
from iab_agentic_primitives.web_bot_auth import Refusal as LibraryRefusal
from iab_agentic_primitives.web_bot_auth.httpx import (
    ResponseNotVerified,
    Unsigned,
    VerificationFailed,
    verification,
)
from openproposal import CommitResult, ErrorObject, Proposal
from pydantic import ValidationError

from persistence.values import KeptResponse, Origin, SignedResponse, Signer
from protocol.operations import RECEIVE, parse_errors, parse_result
from protocol.values import JsonObject, read_json
from transport.control import ErrorBody
from transport.wba import fetch_of, lines_of, origin_of, sent_request

from .credentials import BuyerCredential, seller_call
from .refusal import Reason, Refusal
from .settings import Counterparty

#: The client every call goes through. The rest of the buyer holds one and passes it
#: here; only this module, buyer/credentials.py, and buyer/cfbot.py touch httpx.
HTTPClient = httpx.AsyncClient


class _NotVerified(Exception):
    """An answer whose signature didn't verify, whatever its status: unsigned, or failing.

    The auth returns every answer, and says what it found out about it. A
    signature that fails is refused with the library's reason, never taken as
    no signature; an unsigned answer is refused `signature-missing`. Either
    way, the buyer acts on no answer the seller didn't sign.
    """

    def __init__(self, status: int, found: Unsigned | VerificationFailed | None) -> None:
        if isinstance(found, VerificationFailed):
            self.reason = found.reason
            why = f"{found.reason.code}: {found.detail}"
        else:
            self.reason = LibraryRefusal.SIGNATURE_MISSING
            why = "it carries no signature"
        super().__init__(f"the seller's {status} answer is refused: {why}")


class _Instant:
    """The clock of one answer's verifier: it reads the system clock, and keeps the instant
    it last read, which the buyer keeps with the answer as when it verified it."""

    def __init__(self) -> None:
        self.at = system_clock()

    def __call__(self) -> UnixSeconds:
        self.at = system_clock()
        return self.at


@dataclass(frozen=True)
class Exchange:
    """One request and the verified answer to it, as sent and as received."""

    #: The answer as received: its status, its header lines in order and case, its body,
    #: and the request as sent, which it is bound to. A bearer token is left out.
    response: KeptResponse
    verified: VerifiedResponse
    #: The key that signed the request, or None for a bearer request.
    keyid: str | None
    #: The instant the answer verified at, in Unix seconds.
    verified_at: int

    def evidence(self, buyer_origin: Origin) -> SignedResponse:
        """The answer as the buyer keeps it (§ 4.1.2), with the request it is bound to."""
        directory = self.verified.directory
        signer = Signer(
            origin=origin_of(self.verified.origin),
            keyid=self.verified.keyid,
            directory=None if directory is None else fetch_of(directory.evidence),
        )
        sender = Signer(origin=buyer_origin, keyid=self.keyid)
        return SignedResponse(
            response=self.response,
            signer=signer,
            request_signer=sender,
            verified_at=self.verified_at,
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


def _refusal(error: Exception) -> Refusal:
    """What the buyer says about an answer it can't take."""
    if isinstance(error, _NotVerified):
        return Refusal(error.reason, str(error))
    if isinstance(error, httpx.HTTPError):
        return Refusal(Reason.UNREACHABLE, f"the seller didn't answer: {error}")
    return Refusal(Reason.MALFORMED_ANSWER, f"the seller's answer doesn't parse: {error}")


#: What verifying and parsing an answer can raise. Each one becomes a `Refusal`:
#: `_NotVerified` is an answer whose signature didn't verify, and ValueError covers
#: pydantic's ValidationError, ProtocolViolation, and MalformedJsonError (a body that
#: isn't JSON, or holds a number outside the RFC 8785 domain).
_REFUSED = (_NotVerified, httpx.HTTPError, ValueError)


def _rejection(exchange: Exchange) -> Rejection | Refusal:
    """A non-200 answer: the seller's § 2.4 errors, or its boundary refusing the credential."""
    body = exchange.response.body
    try:
        return Rejection(parse_errors(body), exchange)
    except ValidationError:
        refused = ErrorBody.model_validate_json(body)  # neither form: malformed
    return Refusal(
        Reason.CREDENTIAL_REFUSED,
        f"the seller refused the credential: {exchange.response.status} {refused.code}: "
        f"{refused.detail}",
    )


def _proposal(seller: Counterparty, exchange: Exchange) -> ReadProposal | Refusal:
    body = exchange.response.body
    # The raw JSON, unknown members and all, is the digest input, so its numbers must
    # canonicalize; the typed value, read from the same bytes, decides.
    raw = read_json(body)
    proposal = Proposal.model_validate_json(body, context=RECEIVE)
    if proposal.seller.domain != seller.domain:
        return Refusal(
            Reason.WRONG_SELLER,
            f"the proposal names seller {proposal.seller.domain}, not {seller.domain}",
        )
    return ReadProposal(proposal, raw, exchange)


class SellerClient:
    """Sends the buyer's requests to a seller, and verifies and parses each answer."""

    def __init__(self, http: HTTPClient, resolver: KeyResolver) -> None:
        self._http, self._resolver = http, resolver

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
        """The one send path: the request with its credential, and the verified answer.

        The auth returns every answer with what it found out about it, and raises
        `ResponseNotVerified` for a `2xx` it couldn't verify. Both come down to one
        check: an answer whose signature didn't verify is refused, whatever its status.
        """
        instant = _Instant()
        verifier = ResponseVerifier(self._resolver, clock=instant)
        call = seller_call(credential, verifier, seller.origin)
        headers = {"Content-Type": "application/json"} if body else {}
        try:
            response = await self._http.request(
                method,
                f"{seller.origin}{path}",
                content=body,
                headers=headers | dict(call.headers),
                auth=call.auth,
            )
        except ResponseNotVerified as e:
            raise _NotVerified(e.response.status_code, e.verification) from e
        found = verification(response)
        if not isinstance(found, VerifiedResponse):
            raise _NotVerified(response.status_code, found)
        return Exchange(
            response=KeptResponse(
                status=response.status_code,
                lines=lines_of(response.headers.raw),
                body=response.content,
                request=sent_request(response.request),
            ),
            verified=found,
            keyid=credential.keyid,
            verified_at=instant.at,
        )
