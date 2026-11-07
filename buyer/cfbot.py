"""cfbot: the one peer the buyer signs for without verifying an answer.

cfbot verifies the buyer's signature with Cloudflare's library and answers
unsigned, so its answer is a verdict to report, not a counterparty's word.
Its origin is bound when the buyer builds it, from the buyer's settings.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
from iab_agentic_primitives.web_bot_auth import Origin, RequestSigner
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth
from pydantic import TypeAdapter, ValidationError

from protocol.values import JsonValue
from transport.control import CloudflareCheck

_VERDICT: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class Cfbot:
    def __init__(
        self, http: httpx.AsyncClient, origin: Origin, signer: Callable[[], RequestSigner]
    ) -> None:
        #: `signer` gives the signer of the moment, so a rotation reaches cfbot's checks too.
        self._http, self._url, self._signer = http, f"{origin}/verify", signer

    async def verify(self, body: bytes) -> CloudflareCheck:
        """Signs `body` to cfbot's `/verify` and returns its status and verdict."""
        response = await self._http.post(
            self._url,
            content=body,
            headers={"Content-Type": "application/json"},
            auth=WebBotAuth(self._signer()),
        )
        try:
            verdict = _VERDICT.validate_json(response.content)
        except ValidationError:
            verdict = response.content.decode("utf-8", "replace")
        return CloudflareCheck(status=response.status_code, verdict=verdict)
