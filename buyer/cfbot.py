"""cfbot: the one peer the buyer signs for without verifying an answer.

cfbot verifies the buyer's signature with Cloudflare's library and answers
unsigned, so its answer is a verdict to report, not a counterparty's word.
Its origin is bound when the buyer builds it, from the buyer's settings, and it
signs with the buyer's signing identity, so a rotation reaches cfbot's checks too.
"""

from __future__ import annotations

from http import HTTPStatus

import httpx
from iab_agentic_primitives.web_bot_auth.httpx import WebBotAuth
from pydantic import ValidationError

from persistence.values import Origin
from shared.keyring import SigningIdentity
from transport.control import CFBOT_VERDICT, CloudflareCheck
from transport.operator import ControlError
from transport.wba import Network


class Cfbot:
    def __init__(self, network: Network, origin: Origin, signing: SigningIdentity) -> None:
        self._network, self._url, self._signing = network, f"{origin}/verify", signing

    async def verify(self, body: bytes) -> CloudflareCheck:
        """Signs `body` to cfbot's `/verify` and returns its status and verdict. A cfbot that
        doesn't answer is a 502 `cfbot-unreachable`; an answer that is no verdict, a 502
        `cfbot-malformed`."""
        auth = WebBotAuth(self._signing.signer())
        try:
            async with self._network.signed(auth) as http:
                response = await http.post(
                    self._url, content=body, headers={"Content-Type": "application/json"}
                )
        except httpx.HTTPError as e:
            detail = f"cfbot didn't answer: {e}"
            raise ControlError(HTTPStatus.BAD_GATEWAY, "cfbot-unreachable", detail) from e
        try:
            verdict = CFBOT_VERDICT.validate_json(response.content)
        except ValidationError as e:
            detail = f"cfbot answered {response.status_code} with no verdict: {e}"
            raise ControlError(HTTPStatus.BAD_GATEWAY, "cfbot-malformed", detail) from e
        return CloudflareCheck(status=response.status_code, verdict=verdict)
