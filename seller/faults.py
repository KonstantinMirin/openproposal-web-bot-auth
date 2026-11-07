"""TEST ONLY. Breaks the signatures of the seller's answers to `commit` on purpose, so the e2e can prove the buyer refuses them.

The app installs this middleware only when `DEMO_FAULT_INJECTION=1`, and the
TLS front never routes `/test/` to the seller. A real seller has neither.

Modes, set with `PUT /test/fault {"mode": ...}`:

- `strip`: send the response with no signature.
- `unbound`: sign the response as if the request had been unsigned, so the
  signature doesn't cover the request's signature.
- `rebound`: sign the response bound to a different request signature.
"""

from __future__ import annotations

import base64

from iab_agentic_primitives.web_bot_auth import HTTPRequest, ResponseSigner
from iab_agentic_primitives.web_bot_auth.asgi import request_url

SIGNATURE_FIELDS = (b"signature", b"signature-input", b"signature-agent")
MODES = ("none", "strip", "unbound", "rebound")
_OTHER_SIGNATURE = "sig1=:" + base64.b64encode(bytes(64)).decode() + ":"


class FaultInjection:
    mode = "none"

    def __init__(self, app, signer: ResponseSigner, base_url: str) -> None:
        self.app, self.signer, self.base_url = app, signer, base_url

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.mode == "none" or not scope["path"].endswith("/commit"):
            await self.app(scope, receive, send)
            return
        mode, parts = self.mode, {}

        async def capture(message):
            if message["type"] == "http.response.start":
                parts["start"] = message
            elif message["type"] == "http.response.body":
                parts["body"] = parts.get("body", b"") + message.get("body", b"")
                if not message.get("more_body"):
                    await self._send(mode, scope, parts["start"], parts["body"], send)

        await self.app(scope, receive, capture)

    async def _send(self, mode, scope, start, body, send) -> None:
        headers = [(k, v) for k, v in start["headers"] if k.lower() not in SIGNATURE_FIELDS]
        if mode in ("unbound", "rebound"):
            # Sign again, against a request other than the one received.
            fields = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
            if mode == "unbound":
                fields = [(k, v) for k, v in fields if k.lower().encode() not in SIGNATURE_FIELDS]
            else:
                fields = [(k, v) for k, v in fields if k.lower() != "signature"]
                fields.append(("signature", _OTHER_SIGNATURE))
            request = HTTPRequest(scope["method"], request_url(scope, self.base_url), fields)
            text = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in headers]
            added = self.signer.sign(start["status"], text, body, request)
            headers += [
                (k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in added.items()
            ]
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})
