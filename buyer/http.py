"""How the buyer renders a failing control call: `{"error": ..., "detail": ...}`, each once."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from shared.keyring import RotationError
from transport.handlers import on_error
from transport.operator import ControlError, render_control

from .repository import NotPendingError


def rotation_refused(error: RotationError) -> JSONResponse:
    """A rotation step taken out of order, or too early: 409 (shared/keyring.py)."""
    return render_control(ControlError(409, "rotation", str(error)))


def not_pending(error: NotPendingError) -> JSONResponse:
    """The commit was settled while this trigger waited for the seller: 409. Nothing of
    this trigger's answer is kept."""
    return render_control(
        ControlError(
            409, "not-pending", f"commit {error} is no longer pending, so it stays settled"
        )
    )


def install_handlers(app: FastAPI) -> None:
    """Registers each control error's renderer, once."""
    on_error(app, ControlError, render_control)
    on_error(app, RotationError, rotation_refused)
    on_error(app, NotPendingError, not_pending)
