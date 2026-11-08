"""How a request reads what its agent's lifespan opened.

Each agent's lifespan yields `{"resources": <its resources>}`, which Starlette
hands every request as `request.state`. `state_of` is the one reader of it,
and it returns a typed value.
"""

from __future__ import annotations

from fastapi import Request


class LifespanNotRunError(RuntimeError):
    """A request arrived without the lifespan's resources: the app was served without its
    lifespan, or the lifespan yielded something else."""


def state_of[T](request: Request, kind: type[T]) -> T:
    """The `kind` value the lifespan yielded as `resources`."""
    value = getattr(request.state, "resources", None)
    if not isinstance(value, kind):
        raise LifespanNotRunError(kind.__name__)
    return value
