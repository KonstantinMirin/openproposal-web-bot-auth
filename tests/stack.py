"""Both agents in process: the seller and the buyer apps, each over its own SQLite file.

Each app is built by its own `create_app`, with the library's real signer and
verifiers. The buyer's one client reaches the seller app through `Stack.route`,
an in-process transport, so a test drives the buyer's operator routes and
reads what each party kept through its read model (`seller_records`,
`buyer_records`), as an observer outside the party reads it. A test can stand
in for the seller (`answer`), for example to send a correctly signed answer
that is malformed, or one signed by the reseller, a third party with its own
key and origin.

The transport records the exact header lines on both sides: every request the
buyer sent and every answer it got (`requests`, `responses`), and each
request's lines as the seller app received them (`received`).

Each party finds the other's keys as in production: the library's
`DirectoryResolver` fetches the signed directory of the origin a signature
names, and the stack routes each directory fetch by its host, to the app that
serves it or to the stand-in that owns it (cfbot, the reseller). Each party
keeps the directory it verified against. Calls between the apps are forwarded
on a worker thread, so an app that waits on the other never blocks the other's
event loop.

`runner_transport` is the network as the live runner sees it: the agents'
controls at `http://seller:8000` and `http://buyer:8000`, their directories, and
cfbot's directory.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import anyio
import anyio.to_thread
import httpx
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    DIRECTORY_PATH,
    Ed25519Key,
    HTTPRequest,
    HTTPResponse,
    MemoryNonceStore,
    ResponseSigner,
    keyfile,
)
from iab_agentic_primitives.web_bot_auth.asgi import directory_response
from pydantic import SecretStr
from starlette.types import ASGIApp, Receive, Scope, Send

from buyer.app import create_app as create_buyer
from buyer.settings import BuyerSettings
from persistence.observe import BuyerRecords, SellerRecords
from persistence.values import Origin
from seller.app import create_app as create_seller
from seller.settings import SellerSettings
from shared.keyring import KeyStore
from shared.settings import DEFAULT_ORIGINS
from transport.control import OPERATOR_HEADER
from transport.wba import directory_resolver, http_client, tls_context

SELLER = str(DEFAULT_ORIGINS["seller"])
BUYER = str(DEFAULT_ORIGINS["buyer"])
CFBOT = str(DEFAULT_ORIGINS["cfbot"])
#: A third party with its own key and directory, and no seller of the buyer's.
RESELLER = "https://reseller.wba-demo.noetis.dev"
#: Each agent's own operator key, distinct per party, as the header its controls require.
SELLER_OPERATOR = {OPERATOR_HEADER: "seller-operator-key-for-tests"}
BUYER_OPERATOR = {OPERATOR_HEADER: "buyer-operator-key-for-tests"}
TOKEN = "bearer-token-for-tests"  # noqa: S105 -- a test value, not a deployed secret


@dataclass(frozen=True)
class Origins:
    """The origins the two agents run under: the demo's own by default."""

    seller: Origin = DEFAULT_ORIGINS["seller"]
    buyer: Origin = DEFAULT_ORIGINS["buyer"]


#: The demo's own origins, which a stack runs under unless a test names others.
DEMO = Origins()


#: Stands in for the seller: an answer to the buyer's request, or None to let the seller answer.
Answer = Callable[[httpx.Request], httpx.Response | None]


def seller_settings(
    data_dir: Path, *, origins: Origins = DEMO, faults: bool = False
) -> SellerSettings:
    """The seller over one directory, its database and its key both."""
    return SellerSettings(
        self_origin=origins.seller,
        peer_buyer_origin=origins.buyer,
        data_dir=data_dir,
        keys_dir=data_dir,
        operator_key=SecretStr(SELLER_OPERATOR[OPERATOR_HEADER]),
        bearer_token=SecretStr(TOKEN),
        faults=faults,
    )


def buyer_settings(data_dir: Path, *, origins: Origins = DEMO, token: bool = True) -> BuyerSettings:
    """The buyer over one directory: its database, and its keyring in `keys/`."""
    return BuyerSettings(
        self_origin=origins.buyer,
        peer_seller_origin=origins.seller,
        data_dir=data_dir,
        keys_dir=data_dir / "keys",
        operator_key=SecretStr(BUYER_OPERATOR[OPERATOR_HEADER]),
        bearer_token=SecretStr(TOKEN) if token else None,
    )


Lines = list[tuple[str, str]]


def lines(raw: list[tuple[bytes, bytes]]) -> Lines:
    """Header lines as text, in their order and case."""
    return [(k.decode("latin-1"), v.decode("latin-1")) for k, v in raw]


@dataclass(frozen=True)
class Received:
    """A request as an app received it: the header lines are the ASGI scope's own."""

    method: str
    path: str
    headers: Lines


class Recorder:
    """An ASGI app in front of `app` that records each HTTP request as `app` receives it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.received: list[Received] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            self.received.append(Received(scope["method"], scope["path"], lines(scope["headers"])))
        await self.app(scope, receive, send)


def _directory_of(key: Ed25519Key, host: str) -> httpx.Response:
    """The signed directory that publishes `key`, served as `host` serves it."""
    status, headers, body = directory_response([key], authority=host, now=int(time.time()))
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


class Stack:
    def __init__(
        self,
        root: Path,
        *,
        origins: Origins = DEMO,
        faults: bool = False,
        token: bool = True,
    ) -> None:
        self.origins = origins
        self.seller_dir, self.buyer_dir = root / "seller", root / "buyer"
        self.seller_dir.mkdir(parents=True)
        # The seller loads this key at create_app; `signed` signs as the seller with it.
        self.seller_key = keyfile.load_or_create(self.seller_dir / "wba-key.jwk")
        #: cfbot's key, which its directory publishes.
        self.cfbot_key = Ed25519Key.generate()
        #: The reseller's key, which its directory publishes; `signed` can sign as it.
        self.reseller_key = Ed25519Key.generate()
        #: The parties whose directories the stack serves itself, by host.
        self._published = {
            Origin.parse(CFBOT).host: self.cfbot_key,
            Origin.parse(RESELLER).host: self.reseller_key,
        }
        #: Every request the buyer sent, directory fetches left out, as its client sent it.
        self.requests: list[httpx.Request] = []
        #: The answer to each of `requests`, as the transport delivered it.
        self.responses: list[httpx.Response] = []
        #: Stands in for the seller when set; see `Answer`.
        self.answer: Answer | None = None
        #: What cfbot answers the buyer's signed check.
        self.cfbot: Callable[[httpx.Request], httpx.Response] = lambda _: httpx.Response(
            200,
            json={"ok": True, "identity": str(origins.buyer), "verifier": "web-bot-auth (test)"},
        )
        buyer = create_buyer(
            buyer_settings(self.buyer_dir, origins=origins, token=token),
            transport=httpx.MockTransport(self.route),
        )
        #: The seller's directory client, which the stack builds, owns, and closes.
        self._to_buyer = http_client(
            tls_context(None), transport=httpx.MockTransport(self._seller_network)
        )
        seller = create_seller(
            seller_settings(self.seller_dir, origins=origins, faults=faults),
            nonces=MemoryNonceStore(),
            resolver=directory_resolver(self._to_buyer, max_cache_age=None),
        )
        self._seller = Recorder(seller)
        # A server error is an answer the test reads, as a client would, never an exception.
        self.seller = TestClient(
            self._seller, base_url=str(origins.seller), raise_server_exceptions=False
        )
        self.buyer = TestClient(buyer, base_url=str(origins.buyer), raise_server_exceptions=False)

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
        anyio.run(self._to_buyer.aclose)

    @property
    def buyer_keys(self) -> KeyStore:
        """The buyer's keys as its key directory holds them now, read-only, as the e2e reads
        them. The buyer mints its first key in create_app."""
        return KeyStore.open(self.buyer_dir / "keys")

    @property
    def received(self) -> list[Received]:
        """Every request the seller app received, as it received it."""
        return self._seller.received

    async def route(self, request: httpx.Request) -> httpx.Response:
        """The network, as the buyer's client sees it."""
        if request.url.path == DIRECTORY_PATH:
            return await self._directory(request)
        self.requests.append(request)
        response = await self._answer(request)
        self.responses.append(response)
        return response

    async def _answer(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == Origin.parse(CFBOT).host:
            return self.cfbot(request)
        await request.aread()
        # Off the loop too: a stand-in may ask the seller, which fetches the buyer's directory.
        answer = self.answer
        replaced = None if answer is None else await anyio.to_thread.run_sync(answer, request)
        if replaced is not None:
            return replaced
        return await self._call(self.seller, request)

    async def _directory(self, request: httpx.Request) -> httpx.Response:
        """A directory fetch, routed by its host to the party that publishes it."""
        host = request.url.host
        key = self._published.get(host)
        if key is not None:
            return _directory_of(key, host)
        apps = {self.origins.seller.host: self.seller, self.origins.buyer.host: self.buyer}
        app = apps.get(host)
        if app is None:
            return httpx.Response(404)
        return await self._call(app, request)

    async def _seller_network(self, request: httpx.Request) -> httpx.Response:
        """The network, as the seller's directory resolver sees it."""
        return await self._directory(request)

    async def runner_route(self, request: httpx.Request) -> httpx.Response:
        """The network, as the live runner sees it: the agents' controls, and every directory."""
        if request.url.path == DIRECTORY_PATH:
            return await self._directory(request)
        app = self.seller if request.url.host == "seller" else self.buyer
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
        # The app's own header lines, in order and case, and a stream, as the network gives
        # one: the library's directory fetcher streams the body.
        return httpx.Response(
            answer.status_code,
            headers=answer.headers.raw,
            stream=httpx.ByteStream(answer.content),
        )

    def forward(self, request: httpx.Request) -> httpx.Response:
        """The seller app's own answer to `request`, read."""
        answer = self._forward(self.seller, request)
        answer.read()
        return answer

    def signed(
        self, request: httpx.Request, status: int, body: bytes, *, by: str | None = None
    ) -> httpx.Response:
        """An answer bound to `request`, signed as the seller signs, by the seller or by the
        reseller (`by`) with its own key under its own origin."""
        seller = str(self.origins.seller)
        by = seller if by is None else by
        key = {seller: self.seller_key, RESELLER: self.reseller_key}[by]
        sent = HTTPRequest(
            request.method, str(request.url), lines(request.headers.raw), request.content
        )
        answer = HTTPResponse(status, [("content-type", "application/json")], body, sent)
        signed = ResponseSigner(key, by).sign(answer)
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
        response: httpx.Response = self.buyer.post(
            "/operator/commit", json=trigger, headers=BUYER_OPERATOR
        )
        return response

    def read(self, proposal_id: str, credential: str = "web_bot_auth") -> httpx.Response:
        trigger = {"proposal_id": proposal_id, "credential": credential}
        response: httpx.Response = self.buyer.post(
            "/operator/read", json=trigger, headers=BUYER_OPERATOR
        )
        return response

    # What each party kept

    def seller_records(self) -> AbstractContextManager[SellerRecords]:
        """The seller's records, read-only, as an observer outside the seller reads them."""
        return SellerRecords.open(self.seller_dir / "seller.db")

    def buyer_records(self) -> AbstractContextManager[BuyerRecords]:
        """The buyer's records, read-only, as an observer outside the buyer reads them."""
        return BuyerRecords.open(self.buyer_dir / "buyer.db")

    def commit_states(self, proposal_id: str, line_item_ids: list[str]) -> list[str]:
        """Where each of the buyer's commits on these line items of `proposal_id` stands,
        oldest first."""
        with self.buyer_records() as records:
            return [c.state for c in records.commits(proposal_id, line_item_ids)]
