"""TEST ONLY. Breaks the signatures of the seller's answers to `commit` on purpose.

The e2e uses it to prove that the buyer refuses them.

The app installs this middleware only when `DEMO_FAULT_INJECTION=1`, and the
TLS front never routes `/test/` to the seller. A real seller has neither.

Each instance holds its own mode, so two apps never share one. Modes, set with
`PUT /test/fault {"mode": ...}` (the instance's `control()` router):

- `strip`: send the response with no signature.
- `unbound`: sign the response as if the request had been unsigned, so the
  signature doesn't cover the request's signature.
- `rebound`: sign the response bound to a different request signature.
"""

from __future__ import annotations

import base64
from typing import Literal

from fastapi import APIRouter
from iab_agentic_primitives.web_bot_auth import (
    HTTPRequest,
    HTTPResponse,
    ResponseSigner,
    ServerIdentity,
)
from iab_agentic_primitives.web_bot_auth.asgi import request_url
from pydantic import BaseModel
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SIGNATURE_FIELDS = (b"signature", b"signature-input", b"signature-agent")
Mode = Literal["none", "strip", "unbound", "rebound"]
_OTHER_SIGNATURE = "sig1=:" + base64.b64encode(bytes(64)).decode() + ":"


class FaultMode(BaseModel):
    mode: Mode


class FaultInjection:
    def __init__(self, app: ASGIApp, signer: ResponseSigner, identity: ServerIdentity) -> None:
        self.app, self.signer, self.identity = app, signer, identity
        self.mode: Mode = "none"

    def control(self) -> APIRouter:
        """`PUT /test/fault`, which sets this instance's mode. FastAPI validates the mode."""
        router = APIRouter()

        @router.put("/test/fault")
        async def set_fault(body: FaultMode) -> FaultMode:
            """TEST ONLY: see seller/faults.py."""
            self.mode = body.mode
            return body

        return router

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.mode == "none" or not scope["path"].endswith("/commit"):
            await self.app(scope, receive, send)
            return
        mode = self.mode
        start: Message = {}
        body = bytearray()

        async def capture(message: Message) -> None:
            if message["type"] == "http.response.start":
                start.update(message)
            elif message["type"] == "http.response.body":
                body.extend(message.get("body", b""))
                if not message.get("more_body"):
                    await self._send(mode, scope, start, bytes(body), send)

        await self.app(scope, receive, capture)

    async def _send(
        self, mode: Mode, scope: Scope, start: Message, body: bytes, send: Send
    ) -> None:
        headers = [(k, v) for k, v in start["headers"] if k.lower() not in SIGNATURE_FIELDS]
        if mode in ("unbound", "rebound"):
            # Sign again, against a request other than the one received.
            fields = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
            if mode == "unbound":
                fields = [(k, v) for k, v in fields if k.lower().encode() not in SIGNATURE_FIELDS]
            else:
                fields = [(k, v) for k, v in fields if k.lower() != "signature"]
                fields.append(("signature", _OTHER_SIGNATURE))
            request = HTTPRequest(scope["method"], request_url(scope, self.identity), fields)
            text = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in headers]
            signed = self.signer.sign(HTTPResponse(start["status"], text, body, request))
            # The lines signing added follow the response's own.
            added = signed.headers.items()[len(text) :]
            headers += [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in added]
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})
