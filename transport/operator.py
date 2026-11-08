"""The operator key and the control plane's error seam, which both agents install.

The operator key is what an agent's own controls (`/operator/` routes) require.
The controls are the party's own, never another agent's, so they sit outside
the identity boundary. No front routes them (the Caddy snippet in deploy/, which
the e2e front serves too), and each call also carries `X-Operator-Key`, which must equal the
`OPERATOR_KEY` the agent's settings hold. Each party has a key of its own, so one
party's key opens no other party's controls. An agent without `OPERATOR_KEY`
refuses every operator call.

`install_control_handlers` makes an agent's HTTP seam total: a control route
that fails raises `ControlError`; a body or parameter FastAPI refuses, a path
or method the agent doesn't serve, and any exception nothing else handles are
rendered too. Each answers an `ErrorBody` (transport/control.py), and a 500
carries no traceback: the exception goes to the server's log.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from http import HTTPStatus
from typing import Annotated

from fastapi import FastAPI, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import SecretStr
from starlette.exceptions import HTTPException

from protocol.values import validation_detail

from .control import OPERATOR_HEADER, ControlCode, ErrorBody
from .handlers import on_error

__all__ = [
    "ControlError",
    "OperatorKey",
    "error_response",
    "install_control_handlers",
]


class ControlError(Exception):
    """A control-plane call that fails: its status, a code from the closed set, and `detail`."""

    def __init__(self, status: HTTPStatus, error: ControlCode, detail: str) -> None:
        super().__init__(detail)
        self.status, self.body = status, ErrorBody(error=error, detail=detail)


def error_response(
    status: int, body: ErrorBody, headers: Mapping[str, str] | None = None
) -> JSONResponse:
    """An `ErrorBody`, with its status."""
    return JSONResponse(body.model_dump(mode="json"), status_code=status, headers=headers)


def _control(error: ControlError) -> JSONResponse:
    return error_response(error.status, error.body)


def _invalid(error: RequestValidationError) -> JSONResponse:
    """A body or parameter a control route refuses. No agent-facing route parses with
    FastAPI (the seller's take the raw body), so this is never a § 2.4 `validation` error."""
    body = ErrorBody(error="validation", detail=validation_detail(error.errors()))
    return error_response(HTTPStatus.UNPROCESSABLE_ENTITY, body)


#: The codes of the routing errors Starlette raises; any other status is a bad request.
_ROUTING: Mapping[int, ControlCode] = {
    HTTPStatus.NOT_FOUND: "not-found",
    HTTPStatus.METHOD_NOT_ALLOWED: "method-not-allowed",
}


def _no_route(error: HTTPException) -> JSONResponse:
    """A path or method this agent doesn't serve."""
    code = _ROUTING.get(error.status_code, "bad-request")
    return error_response(error.status_code, ErrorBody(error=code, detail=str(error.detail)))


def _internal(_error: Exception) -> JSONResponse:
    """An exception nothing else handled. Starlette re-raises it after this answer, so the
    server logs it with its traceback; the body says only that the agent failed."""
    body = ErrorBody(error="internal", detail="the agent failed to answer; its log holds why")
    return error_response(HTTPStatus.INTERNAL_SERVER_ERROR, body)


def install_control_handlers(app: FastAPI) -> None:
    """Registers the control plane's renderers on `app`, once each."""
    on_error(app, ControlError, _control)
    on_error(app, RequestValidationError, _invalid)
    on_error(app, HTTPException, _no_route)
    on_error(app, Exception, _internal)


class OperatorKey:
    """A FastAPI dependency: `403` unless the call carries this agent's operator key.

    An agent builds one from its settings and puts it on its operator router:
    `include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])`.
    """

    def __init__(self, expected: SecretStr | None) -> None:
        self._expected = b"" if expected is None else expected.get_secret_value().encode()

    async def __call__(
        self, sent: Annotated[str | None, Header(alias=OPERATOR_HEADER)] = None
    ) -> None:
        if (
            not self._expected
            or sent is None
            or not hmac.compare_digest(sent.encode(), self._expected)
        ):
            raise ControlError(HTTPStatus.FORBIDDEN, "operator-key", "operator key required")
