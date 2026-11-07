"""The seller's HTTP seam: what a route asks for, and how every answer and error is rendered.

A route takes `caller: CallerDep` and, when it reads one, `body: RawBodyDep`,
never a `Request`, which would hand it the credential headers. `CallerDep` runs
the identity boundary that `create_app` built, over the same body bytes the
route then parses, so nothing parses the body before the credential is
confirmed.

The offer logic returns its answers as values; this module renders them. A
seller error body has one of two forms:

- `{"errors": [ErrorObject, ...]}` (§ 2.4), for the offer logic's `Rejected`,
  with the status `status_for` gives;
- `{"error": ..., "detail": ...}`, for the identity boundary (`Refused`) and
  the control plane (`ControlError`, a validation error on a control route, or
  a route FastAPI doesn't have).

The identity boundary's refusal has the second form too: the library's
`refusal_response` body, `error` being the library's reason or the boundary's
own (`BoundaryReason`).
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from openproposal import CommitResult, ErrorObject, dump
from starlette.exceptions import HTTPException

from protocol.values import JsonObject
from shared.handlers import on_error
from shared.operator import ControlError, render_control

from .boundary import Refused
from .caller import Caller
from .errors import Rejected, validation_detail
from .resources import BoundaryDep


async def raw_body(request: Request) -> bytes:
    """The request body, as received. Read once per request and shared."""
    return await request.body()


RawBodyDep = Annotated[bytes, Depends(raw_body)]


async def resolve_caller(request: Request, body: RawBodyDep, boundary: BoundaryDep) -> Caller:
    """The caller the identity boundary confirmed; a failing credential raises `Refused`."""
    return await boundary.resolve(request, body)


#: How a route asks for its caller: `caller: CallerDep`.
CallerDep = Annotated[Caller, Depends(resolve_caller)]


# § 2.4 errors

#: The informative status of each core code (§ 2.4).
CORE_STATUS: Mapping[str, int] = {
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
    if error.retry == "same":
        return 503
    return CORE_STATUS.get(error.code, 400)


def rejection(rejected: Rejected) -> JSONResponse:
    return JSONResponse({"errors": [dump(rejected.error)]}, status_code=status_for(rejected.error))


def answer(outcome: CommitResult | JsonObject | Rejected) -> JSONResponse:
    """A route's answer: the value, or its rejection."""
    if isinstance(outcome, Rejected):
        return rejection(outcome)
    return JSONResponse(outcome if isinstance(outcome, dict) else dump(outcome))


# The other errors, each rendered once.


def refused(error: Refused) -> JSONResponse:
    """The identity boundary's refusal."""
    body = {"error": error.reason, "detail": error.detail}
    return JSONResponse(body, status_code=error.status, headers=dict(error.headers))


def invalid_control_call(error: RequestValidationError) -> JSONResponse:
    """A body or parameter a control route refuses. No agent-facing route parses with
    FastAPI (they take the raw body), so this is never a § 2.4 `validation` error."""
    return render_control(ControlError(422, "validation", validation_detail(error.errors())))


def no_route(error: HTTPException) -> JSONResponse:
    """A path or method this seller doesn't serve."""
    phrase = HTTPStatus(error.status_code).phrase.lower().replace(" ", "-")
    return render_control(ControlError(error.status_code, phrase, str(error.detail)))


def install_handlers(app: FastAPI) -> None:
    """Registers each error's renderer, once."""
    on_error(app, Refused, refused)
    on_error(app, ControlError, render_control)
    on_error(app, RequestValidationError, invalid_control_call)
    on_error(app, HTTPException, no_route)
