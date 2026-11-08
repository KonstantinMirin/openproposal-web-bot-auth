"""The one way to call an agent's controls: `ControlClient`, or `AsyncControlClient`.

`call(op, body)` sends the operation's method to its path under the agent's
base URL, with the agent's operator key in `X-Operator-Key`, and returns the
answer validated by the operation's own answer model (transport/control.py). A
failing answer raises `ControlFailed`, which carries its status and its
`ErrorBody`. The live runner calls asynchronously; the tests and the e2e call
synchronously. The module imports httpx and the control plane's values only,
so the runner calls without loading an HTTP framework.
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel, SecretStr, ValidationError

from protocol.values import JsonValue

from .control import OPERATOR_HEADER, ControlOp, ErrorBody


class ControlFailed(Exception):
    """A control call that answered an error: its status, and its body, an `ErrorBody` when
    the agent answered one."""

    def __init__(self, method: str, path: str, status: int, body: bytes) -> None:
        text = body.decode("utf-8", "replace")
        super().__init__(f"{method} {path} answered {status}: {text}")
        self.status = status
        try:
            self.error: ErrorBody | None = ErrorBody.model_validate_json(body)
        except ValidationError:
            self.error = None


def _json(body: BaseModel | None) -> JsonValue:
    return None if body is None else body.model_dump(mode="json")


def _answer[B: BaseModel | None, A](op: ControlOp[B, A], response: httpx.Response) -> A:
    if not response.is_success:
        raise ControlFailed(op.method, op.path, response.status_code, response.content)
    return op.answer_model.validate_json(response.content)


class _Base:
    def __init__(self, base: httpx.URL | str, operator_key: SecretStr | None) -> None:
        #: The agent's control URL, which an operation's path goes under; "" for a client
        #: whose own base URL is the agent's.
        self._base = str(base).rstrip("/")
        self._headers = (
            {} if operator_key is None else {OPERATOR_HEADER: operator_key.get_secret_value()}
        )

    def _url[B: BaseModel | None, A](self, op: ControlOp[B, A], params: dict[str, str]) -> str:
        return self._base + op.url(**params)


class ControlClient(_Base):
    """Calls one agent's controls with that agent's operator key, synchronously."""

    def __init__(
        self, http: httpx.Client, base: httpx.URL | str = "", operator_key: SecretStr | None = None
    ) -> None:
        super().__init__(base, operator_key)
        self._http = http

    def call[B: BaseModel | None, A](self, op: ControlOp[B, A], body: B, **params: str) -> A:
        """The answer to `op` with `body`, its path parameters filled in from `params`."""
        response = self._http.request(
            op.method, self._url(op, params), json=_json(body), headers=self._headers
        )
        return _answer(op, response)


class AsyncControlClient(_Base):
    """Calls one agent's controls with that agent's operator key."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        base: httpx.URL | str = "",
        operator_key: SecretStr | None = None,
    ) -> None:
        super().__init__(base, operator_key)
        self._http = http

    async def call[B: BaseModel | None, A](self, op: ControlOp[B, A], body: B, **params: str) -> A:
        """The answer to `op` with `body`, its path parameters filled in from `params`."""
        response = await self._http.request(
            op.method, self._url(op, params), json=_json(body), headers=self._headers
        )
        return _answer(op, response)
