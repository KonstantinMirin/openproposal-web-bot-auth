"""Registering an error's renderer on an agent's app, once per error type."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def on_error[E: Exception](
    app: FastAPI, kind: type[E], render: Callable[[E], JSONResponse]
) -> None:
    """Renders every `kind` the app raises with `render`, in an async handler, so it runs on
    the event loop's thread."""

    async def handler(_request: Request, error: Exception) -> JSONResponse:
        if not isinstance(error, kind):  # Starlette dispatches by type; this never happens
            raise error
        return render(error)

    app.add_exception_handler(kind, handler)
