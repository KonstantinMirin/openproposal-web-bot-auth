"""The buyer's HTTP seam: the control plane's renderers, and the one error the buyer adds.

Every failing call answers an `ErrorBody` (transport/control.py). The control
plane's renderers are both agents' (`install_control_handlers`); the buyer adds
only `RotationError`, a rotation step taken out of order or too early.
"""

from __future__ import annotations

from http import HTTPStatus

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from shared.keyring import RotationError
from transport.control import ErrorBody
from transport.handlers import on_error
from transport.operator import error_response, install_control_handlers


def rotation_refused(error: RotationError) -> JSONResponse:
    """A rotation step taken out of order, or too early: 409 (shared/keyring.py)."""
    return error_response(HTTPStatus.CONFLICT, ErrorBody(error="rotation", detail=str(error)))


def install_handlers(app: FastAPI) -> None:
    """Registers the control plane's renderers, and the rotation's, once each."""
    install_control_handlers(app)
    on_error(app, RotationError, rotation_refused)
