"""The operator key: what an agent's own controls (`/operator/` routes) require.

The controls are the party's own, never another agent's, so they sit outside
the identity boundary. No front routes them (e2e/nginx.conf, the Caddy snippet
in deploy/), and each call also carries `X-Operator-Key`, which must equal the
`OPERATOR_KEY` the agent's settings hold. An agent without `OPERATOR_KEY`
refuses every operator call.
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Header, HTTPException
from pydantic import SecretStr

HEADER = "X-Operator-Key"


class OperatorKey:
    """A FastAPI dependency: `403` unless the call carries this agent's operator key.

    An agent builds one from its settings and puts it on its operator router:
    `include_router(operator, dependencies=[Depends(OperatorKey(settings.operator_key))])`.
    """

    def __init__(self, expected: SecretStr | None) -> None:
        self._expected = b"" if expected is None else expected.get_secret_value().encode()

    def __call__(self, x_operator_key: Annotated[str | None, Header()] = None) -> None:
        if (
            not self._expected
            or x_operator_key is None
            or not hmac.compare_digest(x_operator_key.encode(), self._expected)
        ):
            raise HTTPException(403, "operator key required")
