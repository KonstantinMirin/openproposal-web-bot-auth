"""How the buyer renders a failing control call: `{"error": ..., "detail": ...}`, each once."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from shared.keyring import RotationError
from transport.handlers import on_error
from transport.operator import ControlError, render_control


def rotation_refused(error: RotationError) -> JSONResponse:
    """A rotation step taken out of order, or too early: 409 (shared/keyring.py)."""
    return render_control(ControlError(409, "rotation", str(error)))


def install_handlers(app: FastAPI) -> None:
    """Registers each control error's renderer, once."""
    on_error(app, ControlError, render_control)
    on_error(app, RotationError, rotation_refused)
