"""Both agents in process: the seller and the buyer apps, each over its own SQLite file.

Each app is built by its own `create_app`, with the library's real signer and
verifiers. The buyer's one client reaches the seller app through `Stack.route`,
an in-process transport, so a test drives the buyer's operator routes and
reads what each party kept. A test can stand in for the seller (`answer`), for
example to send a correctly signed answer that is malformed, and the transport
records every request the buyer sent.

Each party finds the other's keys as in production: the library's
`DirectoryResolver` fetches the counterparty's signed directory, which the
counterparty app serves, and each party keeps the directory it verified
against. Calls between the apps are forwarded on a worker thread, so an app
that waits on the other never blocks the other's event loop.

`runner_transport` is the network as the live runner sees it: the agents'
controls at `http://seller:8000` and `http://buyer:8000`, their directories, and
cfbot's directory.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType

import anyio.to_thread
import httpx
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    Ed25519Key,
    HTTPRequest,
    HTTPResponse,
    MemoryNonceStore,
    Origin,
    ResponseSigner,
    keyfile,
)
from iab_agentic_primitives.web_bot_auth.asgi import directory_response
from pydantic import SecretStr

from buyer.app import create_app as create_buyer
from buyer.settings import BuyerSettings
from seller.app import create_app as create_seller
from seller.settings import SellerSettings
from shared.keyring import Keyring
from shared.wba import directory_resolver, http_client, tls_context

SELLER = "https://seller.wba-demo.noetis.dev"
BUYER = "https://buyer.wba-demo.noetis.dev"
CFBOT = "https://cfbot.wba-demo.noetis.dev"
OPERATOR = {"X-Operator-Key": "operator-key-for-tests"}
TOKEN = "bearer-token-for-tests"  # noqa: S105 -- a test value, not a deployed secret

#: Stands in for the seller: an answer to the buyer's request, or None to let the seller answer.
Answer = Callable[[httpx.Request], httpx.Response | None]


def seller_settings(data_dir: Path, *, faults: bool = False) -> SellerSettings:
    return SellerSettings(
        self_origin=Origin.parse(SELLER),
        peer_buyer_origin=Origin.parse(BUYER),
        data_dir=data_dir,
        operator_key=SecretStr(OPERATOR["X-Operator-Key"]),
        bearer_token=SecretStr(TOKEN),
        faults=faults,
    )


def buyer_settings(data_dir: Path, *, token: bool = True) -> BuyerSettings:
    return BuyerSettings(
        self_origin=Origin.parse(BUYER),
        peer_seller_origin=Origin.parse(SELLER),
        peer_cfbot_origin=Origin.parse(CFBOT),
        data_dir=data_dir,
        operator_key=SecretStr(OPERATOR["X-Operator-Key"]),
        bearer_token=SecretStr(TOKEN) if token else None,
    )


def read_only(path: Path) -> sqlite3.Connection:
    """A party's database, opened read-only from the test's own thread."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


class Stack:
    def __init__(self, root: Path, *, faults: bool = False, token: bool = True) -> None:
        self.seller_dir, self.buyer_dir = root / "seller", root / "buyer"
        self.seller_dir.mkdir(parents=True)
        # The seller loads this key at create_app; `signed` signs as the seller with it.
        self.seller_key = keyfile.load_or_create(self.seller_dir / "wba-key.jwk")
        #: cfbot's key, which its directory publishes.
        self.cfbot_key = Ed25519Key.generate()
        #: Every request the buyer sent, directory fetches left out.
        self.requests: list[httpx.Request] = []
        #: Stands in for the seller when set; see `Answer`.
        self.answer: Answer | None = None
        #: What cfbot answers the buyer's signed check.
        self.cfbot: Callable[[httpx.Request], httpx.Response] = lambda _: httpx.Response(
            200, json={"ok": True, "identity": BUYER, "verifier": "web-bot-auth (test)"}
        )
        buyer = create_buyer(
            buyer_settings(self.buyer_dir, token=token), transport=httpx.MockTransport(self.route)
        )
        # The buyer mints its first key in create_app.
        self.buyer_keys = Keyring(self.buyer_dir / "keys", rotation_wait=0, signature_lifetime=0)
        to_buyer = http_client(tls_context(None), transport=httpx.MockTransport(self._to_buyer))
        seller = create_seller(
            seller_settings(self.seller_dir, faults=faults),
            nonces=MemoryNonceStore(),
            resolver=directory_resolver(to_buyer, max_cache_age=None),
        )
        self.seller = TestClient(seller, base_url=SELLER)
        self.buyer = TestClient(buyer, base_url=BUYER)

    def __enter__(self) -> Stack:
        self.seller.__enter__()
        self.buyer.__enter__()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.buyer.__exit__(kind, error, trace)
        self.seller.__exit__(kind, error, trace)

    async def route(self, request: httpx.Request) -> httpx.Response:
        """The network, as the buyer's client sees it."""
        if request.url.path == DIRECTORY_PATH:
            return await self._call(self.seller, request)
        self.requests.append(request)
        if request.url.host == Origin.parse(CFBOT).host:
            return self.cfbot(request)
        await request.aread()
        # Off the loop too: a stand-in may ask the seller, which fetches the buyer's directory.
        answer = self.answer
        replaced = None if answer is None else await anyio.to_thread.run_sync(answer, request)
        if replaced is not None:
            return replaced
        return await self._call(self.seller, request)

    async def _to_buyer(self, request: httpx.Request) -> httpx.Response:
        """The network, as the seller's directory resolver sees it."""
        return await self._call(self.buyer, request)

    async def runner_route(self, request: httpx.Request) -> httpx.Response:
        """The network, as the live runner sees it."""
        host = request.url.host
        if host == Origin.parse(CFBOT).host:
            status, headers, body = directory_response(
                [self.cfbot_key], authority=host, now=int(time.time())
            )
            return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))
        app = self.seller if host in ("seller", Origin.parse(SELLER).host) else self.buyer
        return await self._call(app, request)

    @staticmethod
    async def _call(app: TestClient, request: httpx.Request) -> httpx.Response:
        """`app`'s answer to `request`, from a worker thread, so this loop stays free."""
        await request.aread()
        return await anyio.to_thread.run_sync(Stack._forward, app, request)

    @staticmethod
    def _forward(app: TestClient, request: httpx.Request) -> httpx.Response:
        answer = app.request(
            request.method,
            str(request.url),
            content=request.content,
            headers=request.headers,
        )
        # A stream, as the network gives one: the library's directory fetcher streams the body.
        return httpx.Response(
            answer.status_code,
            headers=answer.headers.multi_items(),
            stream=httpx.ByteStream(answer.content),
        )

    def forward(self, request: httpx.Request) -> httpx.Response:
        """The seller app's own answer to `request`, read."""
        answer = self._forward(self.seller, request)
        answer.read()
        return answer

    def signed(self, request: httpx.Request, status: int, body: bytes) -> httpx.Response:
        """An answer signed with the seller's key and bound to `request`, as the seller signs."""
        sent = HTTPRequest(
            request.method, str(request.url), request.headers.multi_items(), request.content
        )
        answer = HTTPResponse(status, [("content-type", "application/json")], body, sent)
        signed = ResponseSigner(self.seller_key, SELLER).sign(answer)
        return httpx.Response(status, headers=signed.headers.items(), content=body)

    # The buyer's controls

    def commit(
        self, proposal_id: str, line_item_ids: list[str], credential: str = "web_bot_auth"
    ) -> httpx.Response:
        trigger = {
            "proposal_id": proposal_id,
            "line_item_ids": line_item_ids,
            "credential": credential,
        }
        return self.buyer.post("/operator/commit", json=trigger, headers=OPERATOR)

    def read(self, proposal_id: str, credential: str = "web_bot_auth") -> httpx.Response:
        trigger = {"proposal_id": proposal_id, "credential": credential}
        return self.buyer.post("/operator/read", json=trigger, headers=OPERATOR)

    # What each party kept

    @contextmanager
    def seller_db(self) -> Iterator[sqlite3.Connection]:
        db = read_only(self.seller_dir / "seller.db")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def buyer_db(self) -> Iterator[sqlite3.Connection]:
        db = read_only(self.buyer_dir / "buyer.db")
        try:
            yield db
        finally:
            db.close()
