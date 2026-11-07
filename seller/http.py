"""The seller's HTTP seam: what a route asks for, and how a refusal is rendered.

A route takes `caller: CallerDep` and, when it reads one, `body: RawBodyDep`,
never a `Request`, which would hand it the credential headers. `CallerDep` runs
the identity boundary that `create_app` built, over the same body bytes the
route then parses, so nothing parses the body before the credential is
confirmed.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from fastapi.responses import JSONResponse

from .boundary import Refused
from .caller import Caller
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


async def refused(_request: Request, error: Exception) -> JSONResponse:
    """The boundary's refusal. Async, so it runs on the event loop's thread."""
    if not isinstance(error, Refused):
        raise error
    body = {"refused_at": "identity-boundary", "reason": error.reason, "detail": error.detail}
    return JSONResponse(body, status_code=error.status, headers=dict(error.headers))
