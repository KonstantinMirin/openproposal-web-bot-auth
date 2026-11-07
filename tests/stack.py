"""Both agents in process: the seller and the buyer apps, each over its own SQLite file.

Each app is built by its own `create_app`, with the library's real signer and
verifiers. The buyer's one client reaches the seller app through `Stack.route`,
an in-process transport, so a test drives the buyer's operator routes and
reads what each party kept. A test can stand in for the seller (`answer`), for
example to send a correctly signed answer that is malformed, and the transport
records every request the buyer sent.

The seller verifies the buyer's signatures with the buyer's first key, and the
buyer verifies the seller's with the seller's key, each through the library's
`StaticKeyResolver`: no directory fetch is involved.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType

import httpx
from fastapi.testclient import TestClient
from iab_agentic_primitives.web_bot_auth import (
    HTTPRequest,
    HTTPResponse,
    MemoryNonceStore,
    Origin,
    ResponseSigner,
    StaticKeyResolver,
    keyfile,
)
from pydantic import SecretStr

from buyer.app import create_app as create_buyer
from buyer.settings import BuyerSettings
from seller.app import create_app as create_seller
from seller.settings import SellerSettings
from shared.keyring import Keyring

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
        # The seller loads this key at create_app; the buyer verifies the seller's answers with it.
        self.seller_key = keyfile.load_or_create(self.seller_dir / "wba-key.jwk")
        self.requests: list[httpx.Request] = []
        #: Stands in for the seller when set; see `Answer`.
        self.answer: Answer | None = None
        #: What cfbot answers the buyer's signed check.
        self.cfbot: Callable[[httpx.Request], httpx.Response] = lambda _: httpx.Response(
            200, json={"ok": True, "identity": BUYER}
        )
        buyer = create_buyer(
            buyer_settings(self.buyer_dir, token=token),
            resolver=StaticKeyResolver({SELLER: [self.seller_key]}),
            transport=httpx.MockTransport(self.route),
        )
        # The buyer mints its first key in create_app; the seller verifies with it.
        self.buyer_keys = Keyring(self.buyer_dir / "keys", rotation_wait=0, signature_lifetime=0)
        seller = create_seller(
            seller_settings(self.seller_dir, faults=faults),
            nonces=MemoryNonceStore(),
            resolver=StaticKeyResolver({BUYER: [self.buyer_keys.active()]}),
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

    def route(self, request: httpx.Request) -> httpx.Response:
        """The network, as the buyer's client sees it."""
        self.requests.append(request)
        if request.url.host == Origin.parse(CFBOT).host:
            return self.cfbot(request)
        replaced = None if self.answer is None else self.answer(request)
        if replaced is not None:
            return replaced
        return self.forward(request)

    def forward(self, request: httpx.Request) -> httpx.Response:
        """The seller app's own answer to `request`."""
        answer = self.seller.request(
            request.method, str(request.url), content=request.content, headers=request.headers
        )
        return httpx.Response(
            answer.status_code, headers=answer.headers.multi_items(), content=answer.content
        )

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
