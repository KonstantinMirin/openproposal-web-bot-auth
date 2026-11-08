"""TEST ONLY. Breaks the signatures of the seller's answers on purpose.

The e2e uses it to prove that the buyer refuses them.

The app installs this middleware only when `DEMO_FAULT_INJECTION=1`, and the
TLS front never routes `/test/` to the seller. A real seller has neither.

Each instance holds its own fault, so two apps never share one. A fault is set
with the `FAULT` control (transport/control.py), which the instance's
`control()` router serves. `on` names the answers it breaks: `commit` (the default), the answers
to `POST /proposals/{id}/commit`, or `read`, the answers to
`GET /proposals/{id}`. The modes:

- `strip`: send the response with no signature.
- `unbound`: sign the response as if the request had been unsigned, so the
  signature doesn't cover the request's signature.
- `rebound`: sign the response bound to a different request signature.
- `wrong_digest`: sign the response over a body with one byte changed, and send
  the body unchanged, so its `Content-Digest` doesn't match what arrives.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter
from iab_agentic_primitives.web_bot_auth import ResponseSigner, ServerIdentity
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from persistence.values import KeptRequest, KeptResponse
from transport.control import FAULT, FaultMode, FaultName, FaultTarget
from transport.operator import control_route
from transport.wba import asgi_lines, lines_of, request_of, response_to_library

SIGNATURE_FIELDS = (b"signature", b"signature-input", b"signature-agent")
_OTHER_SIGNATURE = "sig1=:" + base64.b64encode(bytes(64)).decode() + ":"


def _targets(scope: Scope, on: FaultTarget) -> bool:
    """Whether the request in `scope` asks for an answer the fault breaks."""
    path: str = scope["path"]
    if not path.startswith("/proposals/"):
        return False
    method: str = scope["method"]
    if on == "commit":
        return method == "POST" and path.endswith("/commit")
    return method == "GET"


class FaultInjection:
    def __init__(self, app: ASGIApp, signer: ResponseSigner, identity: ServerIdentity) -> None:
        self.app, self.signer, self.identity = app, signer, identity
        self.fault = FaultMode(mode="none")

    def control(self) -> APIRouter:
        """The `FAULT` control, which sets this instance's fault. FastAPI validates it."""
        router = APIRouter()

        @control_route(router, FAULT)
        async def set_fault(body: FaultMode) -> FaultMode:
            """TEST ONLY: see seller/faults.py."""
            self.fault = body
            return body

        return router

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        fault = self.fault
        if scope["type"] != "http" or fault.mode == "none" or not _targets(scope, fault.on):
            await self.app(scope, receive, send)
            return
        start: Message = {}
        body = bytearray()

        async def capture(message: Message) -> None:
            if message["type"] == "http.response.start":
                start.update(message)
            elif message["type"] == "http.response.body":
                body.extend(message.get("body", b""))
                if not message.get("more_body"):
                    await self._send(fault.mode, scope, start, bytes(body), send)

        await self.app(scope, receive, capture)

    def _request(self, mode: FaultName, scope: Scope) -> KeptRequest:
        """The request the broken signature is bound to."""
        received = request_of(scope, self.identity, b"")
        fields = list(received.lines)
        if mode == "unbound":
            fields = [(k, v) for k, v in fields if k.lower().encode() not in SIGNATURE_FIELDS]
        elif mode == "rebound":
            fields = [(k, v) for k, v in fields if k.lower() != "signature"]
            fields.append(("signature", _OTHER_SIGNATURE))
        return KeptRequest(method=received.method, url=received.url, lines=tuple(fields), body=b"")

    async def _send(
        self, mode: FaultName, scope: Scope, start: Message, body: bytes, send: Send
    ) -> None:
        # wrong_digest also drops Content-Digest, so that signing computes it over the changed body.
        dropped = (
            (*SIGNATURE_FIELDS, b"content-digest") if mode == "wrong_digest" else SIGNATURE_FIELDS
        )
        headers = [(k, v) for k, v in start["headers"] if k.lower() not in dropped]
        if mode != "strip":
            # Sign again: against another request, or over another body.
            signed_body = body[:-1] + bytes([body[-1] ^ 1]) if mode == "wrong_digest" else body
            text = lines_of(headers)
            response = KeptResponse(
                status=start["status"],
                lines=text,
                body=signed_body,
                request=self._request(mode, scope),
            )
            signed = self.signer.sign(response_to_library(response))
            # The lines signing added follow the response's own.
            headers += asgi_lines(signed.headers.items()[len(text) :])
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})
