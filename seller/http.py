"""The seller's HTTP seam: what a route asks for, and how every answer and error is rendered.

A route takes `caller: CallerDep`, or, when it calls the offer logic,
`principal: PrincipalDep` or `writer: EntryWriterDep`, and, when it reads one,
`body: RawBodyDep`, never a `Request`, which would hand it the credential
headers. `CallerDep` runs the identity boundary that `create_app` built, over
the same body bytes the route then parses, so nothing parses the body before
the credential is confirmed.

The offer logic receives of the caller only its principal id: as
`PrincipalDep`, or as the `principal_id` of the `EntryWriter` that
`EntryWriterDep` binds here to the caller's provenance. The writer is the one
place a caller's entry meets its provenance. It computes, inside the offer
logic's transaction, whether a signature attributes the entry (§ 4.1.2):
against the `buyer.domain` of the record the entry is about, never against
the caller's principal, as the buyer does for the seller's answer.

The offer logic returns its answers as values; this module renders them. A
seller error body has one of two forms:

- `{"errors": [ErrorObject, ...]}` (§ 2.4), for the offer logic's `Rejected`,
  with the status `status_for` gives;
- an `ErrorBody` (`{"error": ..., "detail": ...}`, transport/control.py) for
  the control plane's errors, which `install_control_handlers` renders for
  both agents;
- a `RefusalBody` (`{"error": ..., "status": ...}`, the library's form) for
  the identity boundary's `Refused`, which this module adds.

A refusal answers the body the boundary built: for a signature, the library's
`refusal_response` body, whose `error` is the library's reason; for the
boundary's own reasons (`BoundaryReason`), the same form. The refusal's detail
goes to the seller's log, never into the body.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from openproposal import AssentEntry, CommitResult, ErrorObject, ErrorObjectCode, dump

from persistence.values import Provenance
from protocol.attribution import attributes
from protocol.operations import is_stored_result
from protocol.values import JsonObject
from transport.handlers import on_error
from transport.operator import install_control_handlers

from .boundary import Refused
from .caller import Caller, ResolvedCaller
from .errors import Rejected
from .ports import EntryWriter, KeptEvidence
from .resources import BoundaryDep, KeptEvidenceDep

_log = logging.getLogger(__name__)


async def raw_body(request: Request) -> bytes:
    """The request body, as received. Read once per request and shared."""
    return await request.body()


RawBodyDep = Annotated[bytes, Depends(raw_body)]


async def resolve_caller(request: Request, body: RawBodyDep, boundary: BoundaryDep) -> Caller:
    """The caller the identity boundary confirmed; a failing credential raises `Refused`."""
    return await boundary.resolve(request, body)


#: How a route asks for its caller: `caller: CallerDep`.
CallerDep = Annotated[Caller, Depends(resolve_caller)]


async def principal_of(caller: CallerDep) -> str | None:
    """What a read takes of the caller: its principal id, or None with no principal."""
    return caller.principal.id if isinstance(caller, ResolvedCaller) else None


#: How a route that reads through the offer logic asks for its caller.
PrincipalDep = Annotated[str | None, Depends(principal_of)]


class CallerEntries:
    """An `EntryWriter` bound to one caller's confirmed provenance, which only it holds."""

    def __init__(self, evidence: KeptEvidence, provenance: Provenance) -> None:
        self._evidence, self._provenance = evidence, provenance

    @property
    def principal_id(self) -> str:
        return self._provenance.principal_id

    def append(self, proposal_id: str, entry: AssentEntry, *, record_buyer: str | None) -> None:
        """Keeps `entry` with the provenance. A signature attributes it when it covers the
        body and its host is `record_buyer` or a subdomain of it (§ 4.1.2)."""
        p, host = self._provenance, self._provenance.signing_host
        attributed = (
            host is not None
            and record_buyer is not None
            and attributes(host, record_buyer, body_covered=p.body_covered)
        )
        self._evidence.append_caller_entry(proposal_id, entry, p, attributed=attributed)


async def entry_writer(caller: CallerDep, evidence: KeptEvidenceDep) -> EntryWriter | None:
    """What a commit takes of the caller: the writer of its entries, or None with no
    principal."""
    if not isinstance(caller, ResolvedCaller):
        return None
    return CallerEntries(evidence, caller.provenance)


#: How a route that writes through the offer logic asks for its caller.
EntryWriterDep = Annotated[EntryWriter | None, Depends(entry_writer)]


# § 2.4 errors

#: The informative status of each core code (§ 2.4).
CORE_STATUS: Mapping[ErrorObjectCode, int] = {
    "validation": 400,
    "not_offered": 400,
    "unresolved_reference": 400,
    "not_eligible": 403,
    "not_found": 404,
    "not_committable": 409,
    "stale_version": 409,
    "record_mismatch": 409,
    "expired": 410,
    "idempotency_conflict": 422,
}


def status_for(error: ErrorObject) -> int:
    """The HTTP status of an error. Total: a receiver acts on `retry` (§ 2.4), so an error
    with `retry: same` fits 503 whatever its code, and an extension code fits 400."""
    if not is_stored_result([error]):
        return 503
    return CORE_STATUS.get(error.code, 400)


def rejection(rejected: Rejected) -> JSONResponse:
    return JSONResponse({"errors": [dump(rejected.error)]}, status_code=status_for(rejected.error))


def answer(outcome: CommitResult | JsonObject | Rejected) -> JSONResponse:
    """A route's answer: the value, or its rejection."""
    if isinstance(outcome, Rejected):
        return rejection(outcome)
    return JSONResponse(outcome if isinstance(outcome, dict) else dump(outcome))


# The boundary's refusal, rendered once.


def refused(error: Refused) -> Response:
    """The identity boundary's refusal: the body it built, with its status and hint. Its
    detail goes to the log."""
    _log.info("refused %s %s: %s", error.status, error.reason, error.detail)
    return Response(
        error.body,
        status_code=error.status,
        headers=dict(error.headers),
        media_type="application/json",
    )


def install_handlers(app: FastAPI) -> None:
    """Registers the control plane's renderers, and the boundary's refusal, once each."""
    install_control_handlers(app)
    on_error(app, Refused, refused)
