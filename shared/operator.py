"""The operator key: what an agent's own controls (`/operator/` routes) require.

The controls are the party's own, never another agent's, so they sit outside
the identity boundary. No front routes them (e2e/nginx.conf, the Caddy snippet
in deploy/), and each call also carries `X-Operator-Key`, which must equal the
`OPERATOR_KEY` the agent started with. An agent without `OPERATOR_KEY` refuses
every operator call.
"""

from __future__ import annotations

import hmac
import os
from typing import Annotated

from fastapi import Header, HTTPException

HEADER = "X-Operator-Key"


def require_operator(x_operator_key: Annotated[str | None, Header()] = None) -> None:
    """A FastAPI dependency: `403` unless the call carries this agent's operator key."""
    expected = os.environ.get("OPERATOR_KEY", "")
    if (
        not expected
        or x_operator_key is None
        or not hmac.compare_digest(x_operator_key.encode(), expected.encode())
    ):
        raise HTTPException(403, "operator key required")
