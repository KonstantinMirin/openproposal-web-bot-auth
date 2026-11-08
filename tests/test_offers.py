"""The seller's answer to `commit` (§ 5.6.1), through the app: every code, the ledger, acceptance.

Each test seeds a seller's database from the template, changed where a row
needs it (an ended window, a sold-out line item, an earlier live commitment),
starts the app with `create_app`, and commits over its ASGI interface as the
seller's buyer, with the bearer token the seller issued it. The commit is
composed with the protocol operations from the document the seller serves, so
it is correct unless the row breaks it on purpose. What comes out is the answer and the records the
seller kept, read through its read model.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import httpx
import pytest
from fastapi.testclient import TestClient
from openproposal import AssentEntry, Proposal
from pydantic import SecretStr

from persistence.observe import KeptEntry, SellerRecords
from persistence.values import Origin
from protocol.operations import parse_errors, parse_result
from protocol.record import items_by_id
from protocol.values import JsonObject, JsonValue, read_json
from seller.offers.issuance import issue
from seller.ports import Principal
from seller.seed import onboard
from seller.sqlite_store import SqliteSellerStore
from tests._tools import commit_body, seed_issuer, seed_template
from tests.stack import ELSEWHERE, seller_app, seller_settings
from tests.stack import TOKEN as BUYER_TOKEN

#: The seller alone, under origins other than the demo's.
SELLER = str(ELSEWHERE.seller)
#: The token the seller's settings issue its buyer, which each boot applies.
TOKEN = {"Authorization": f"Bearer {BUYER_TOKEN}"}
ITEM = "business-daily-display"
PATH = "/proposals/demo-wba-1/commit"

#: A commitment someone made earlier on ITEM, which nothing accepted or ended.
EARLIER = {
    "version": 1,
    "record_digest": "sha256:" + "1" * 64,
    "line_item_ids": [ITEM],
    "at": "2026-11-01T00:00:00Z",
}


def _entry(role: str, **fields: object) -> AssentEntry:
    return AssentEntry.model_validate({"role": role, **EARLIER, **fields})


#: Another buyer of the seller's, with a proposal of its own.
OTHER = Principal(
    id="other-buyer", kind="buyer", legal_name="Other Agency LLC", domain="other.example.com"
)


def _seed(data_dir: Path, edit: Edit, prior: list[AssentEntry]) -> None:
    """The first-boot records from an edited template, with `prior` in demo-wba-1's log,
    and another buyer issued `other-1`."""
    data_dir.mkdir()
    template = seed_template()
    edit(template)
    issuer = seed_issuer(template)
    store = SqliteSellerStore(data_dir / "seller.db")
    try:
        onboard(
            store,
            issuer,
            buyer_origin=ELSEWHERE.buyer,
            buyer_legal_name="Demo Buyer Agency LLC",
            bearer_token=SecretStr(BUYER_TOKEN),
        )
        with store.transaction():
            for entry in prior:
                store.append_own_entry("demo-wba-1", entry)
            store.add_principal(OTHER)
            store.set_origin_credential(OTHER.id, Origin.parse(f"https://{OTHER.domain}"))
            issue(store, issuer, OTHER, "other-1")
    finally:
        store.close()


@dataclass
class Seller:
    client: TestClient
    data_dir: Path

    def commit(
        self, body: JsonObject, *, path: str = PATH, headers: dict[str, str] = TOKEN
    ) -> httpx.Response:
        response: httpx.Response = self.client.post(
            path, content=json.dumps(body).encode(), headers=headers
        )
        return response

    def composed(self, key: str = "k-1") -> JsonObject:
        """The buyer's correct commit to ITEM, composed on the document the seller serves."""
        document = read_json(self.client.get("/proposals/demo-wba-1", headers=TOKEN).content)
        body: JsonObject = json.loads(commit_body(document, ITEM, key=key))
        return body

    def records(self) -> AbstractContextManager[SellerRecords]:
        return SellerRecords.open(self.data_dir / "seller.db")

    def entries(self) -> list[KeptEntry]:
        """The assent log of demo-wba-1."""
        with self.records() as records:
            return records.entries("demo-wba-1")

    def ledger(self, proposal_id: str = "demo-wba-1") -> list[str]:
        """The idempotency keys of the commits the seller processed on `proposal_id`."""
        with self.records() as records:
            return records.processed(proposal_id)


def _codes(answer: httpx.Response) -> list[str]:
    """The codes of a § 2.4 `errors[]` answer."""
    return [e.code for e in parse_errors(answer.content)]


#: A change to the template before it is issued, or to a commit before it is sent.
Edit = Callable[[JsonObject], None]


def _keep(_document: JsonObject) -> None:
    pass


class StartSeller(Protocol):
    def __call__(self, edit: Edit = ..., prior: list[AssentEntry] | None = None) -> Seller: ...


@pytest.fixture
def seller_with(tmp_path: Path) -> Iterator[StartSeller]:
    clients: list[TestClient] = []

    def start(edit: Edit = _keep, prior: list[AssentEntry] | None = None) -> Seller:
        data_dir = tmp_path / f"seller-{len(clients)}"
        _seed(data_dir, edit, prior or [])
        app = seller_app(seller_settings(data_dir, origins=ELSEWHERE))
        client = TestClient(app, base_url=SELLER).__enter__()
        clients.append(client)
        return Seller(client, data_dir)

    yield start
    for client in clients:
        client.__exit__(None, None, None)


# ── Every code ─────────────────────────────────────────────────────────────


def _at(document: JsonObject, *path: str) -> JsonObject:
    """The object at `path` in `document`."""
    node = document
    for key in path:
        child = node[key]
        assert isinstance(child, dict), path
        node = child
    return node


def _item(template: JsonObject) -> JsonObject:
    return items_by_id(template)[ITEM]


def _window(start: str, end: str) -> Edit:
    def edit(template: JsonObject) -> None:
        template["offer_window"] = {"start": start, "end": end}

    return edit


def _item_status(status: str) -> Edit:
    def edit(template: JsonObject) -> None:
        _item(template)["status"] = status

    return edit


def _price_until(instant: str) -> Edit:
    def edit(template: JsonObject) -> None:
        pricing = _item(template)["pricing"]
        assert isinstance(pricing, list) and isinstance(pricing[0], dict)
        pricing[0]["price_valid_until"] = instant

    return edit


def _set(path: tuple[str, ...], name: str, value: JsonValue) -> Edit:
    """Sets `name` on the object at `path` of the commit."""

    def change(commit: JsonObject) -> None:
        _at(commit, *path)[name] = value

    return change


def _rename_item(commit: JsonObject) -> None:
    writes = _at(commit, "writes")
    writes["no-such-line-item"] = writes.pop(ITEM)
    _at(commit, "entry")["line_item_ids"] = ["no-such-line-item"]


@dataclass(frozen=True)
class Row:
    name: str
    code: str
    status: int
    stored: bool
    #: What the error tells the buyer to do next: retry the same commit, refetch, or stop.
    retry: str
    edit: Edit = _keep
    change: Edit = _keep
    prior: list[AssentEntry] = field(default_factory=list)


ROWS = [
    Row(
        "offer_window.end has passed",
        "expired",
        410,
        stored=True,
        retry="none",
        edit=_window("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"),
    ),
    Row(
        "price_valid_until has passed",
        "expired",
        410,
        stored=True,
        retry="none",
        edit=_price_until("2026-02-01T00:00:00Z"),
    ),
    Row(
        "another version",
        "stale_version",
        409,
        stored=True,
        retry="refetch",
        change=_set(("entry",), "version", 2),
    ),
    Row("no such line item", "not_found", 404, stored=True, retry="none", change=_rename_item),
    Row(
        "a write § 3.4 doesn't list",
        "validation",
        400,
        stored=True,
        retry="none",
        change=_set(
            ("writes", ITEM),
            "daypart",
            {"value": {"include": [{"days": ["monday"], "start": "06:00", "before": "22:00"}]}},
        ),
    ),
    Row(
        "a commitment under no pricing entry",
        "validation",
        400,
        stored=True,
        retry="none",
        change=_set(("writes", ITEM, "commitment"), "pricing_id", "no-such-entry"),
    ),
    Row(
        "a line item that isn't committable",
        "not_committable",
        409,
        stored=True,
        retry="none",
        edit=_item_status("sold_out"),
    ),
    Row(
        "before offer_window.start",
        "not_committable",
        503,
        stored=False,
        retry="same",
        edit=_window("2029-01-01T00:00:00Z", "2029-12-31T23:59:59Z"),
    ),
    Row(
        "a live commitment names the line item",
        "not_committable",
        503,
        stored=False,
        retry="same",
        prior=[_entry("commitment", idempotency_key="earlier")],
    ),
    Row(
        "a record_digest that isn't the seller's",
        "record_mismatch",
        409,
        stored=True,
        retry="refetch",
        change=_set(("entry",), "record_digest", "sha256:" + "0" * 64),
    ),
]


def _both(*changes: Edit) -> Edit:
    def change(commit: JsonObject) -> None:
        for one in changes:
            one(commit)

    return change


#: § 5.6.1's order: two grounds at once, and the earlier code wins.
ROWS += [
    Row(
        "expired before stale_version",
        "expired",
        410,
        stored=True,
        retry="none",
        edit=_window("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"),
        change=_set(("entry",), "version", 2),
    ),
    Row(
        "stale_version before an unknown line item",
        "stale_version",
        409,
        stored=True,
        retry="refetch",
        change=_both(_rename_item, _set(("entry",), "version", 2)),
    ),
    Row(
        "not_committable before record_mismatch",
        "not_committable",
        409,
        stored=True,
        retry="none",
        edit=_item_status("sold_out"),
        change=_set(("entry",), "record_digest", "sha256:" + "0" * 64),
    ),
]


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.name)
def test_each_check_rejects_with_its_code(seller_with: StartSeller, row: Row) -> None:
    seller = seller_with(row.edit, row.prior)
    commit = seller.composed()
    row.change(commit)
    answer = seller.commit(commit)
    assert answer.status_code == row.status, answer.text
    (error,) = parse_errors(answer.content)
    assert (error.code, error.version, error.retry) == (row.code, 1, row.retry)
    assert seller.ledger() == (["k-1"] if row.stored else [])
    # Nothing was written to the record.
    assert [e.role for e in seller.entries() if e.idempotency_key == "k-1"] == []


def test_a_caller_with_no_principal_is_not_eligible(seller_with: StartSeller) -> None:
    seller = seller_with()
    answer = seller.commit(seller.composed(), headers={})
    assert answer.status_code == 403
    assert _codes(answer) == ["not_eligible"]
    assert seller.ledger() == []


@pytest.mark.parametrize(
    "body",
    [b"{not json", b'{"entry": {}}'],
    ids=["not JSON", "not a Commit"],
)
def test_an_unparsable_body_is_a_validation_error(seller_with: StartSeller, body: bytes) -> None:
    seller = seller_with()
    answer = seller.client.post(PATH, content=body, headers=TOKEN)
    assert answer.status_code == 400
    assert _codes(answer) == ["validation"]


def test_a_commit_that_names_a_member_twice_is_a_validation_error(
    seller_with: StartSeller,
) -> None:
    """§ 4.1.1: a document that names a member twice is invalid. Readers disagree on which of
    the two counts, so a verifier reading the first would read another record_digest than a
    seller reading the last: the seller refuses the commit and keeps nothing of it."""
    seller = seller_with()
    commit = seller.composed()
    entry, writes = json.dumps(commit["entry"]), json.dumps(commit["writes"])
    wrong = json.dumps("sha256:" + "0" * 64)
    body = f'{{"entry": {{"record_digest": {wrong}, {entry[1:]}, "writes": {writes}}}'.encode()
    answer = seller.client.post(PATH, content=body, headers=TOKEN)
    assert answer.status_code == 400
    (error,) = parse_errors(answer.content)
    assert (error.code, "'record_digest' twice" in error.detail) == ("validation", True)
    assert seller.entries() == [] and seller.ledger() == []


def test_writes_for_a_line_item_the_entry_doesnt_name_are_a_validation_error(
    seller_with: StartSeller,
) -> None:
    seller = seller_with()
    commit = seller.composed()
    writes = _at(commit, "writes")
    writes["weather-app-ctv"] = writes[ITEM]  # § 5.6.1: keyed by exactly the named items
    answer = seller.commit(commit)
    assert answer.status_code == 400
    (error,) = parse_errors(answer.content)
    assert error.code == "validation" and "writes are keyed" in error.detail


def test_a_proposal_issued_to_another_buyer_is_not_found(seller_with: StartSeller) -> None:
    seller = seller_with()
    answer = seller.commit(seller.composed(), path="/proposals/other-1/commit")
    assert answer.status_code == 404
    assert _codes(answer) == ["not_found"]
    assert seller.ledger("other-1") == seller.ledger() == []


# ── Acceptance ────────────────────────────────────────────────────────────


def test_an_accepted_commit_writes_the_pair_and_the_agreed_record(
    seller_with: StartSeller,
) -> None:
    seller = seller_with()
    commit = seller.composed()
    answer = seller.commit(commit)
    assert answer.status_code == 200, answer.text
    commitment, acceptance = parse_result(answer.content).entries
    assert commitment == AssentEntry.model_validate(commit["entry"])
    assert acceptance.role == "acceptance"
    assert acceptance.record_digest == commitment.record_digest

    assert [e.role for e in seller.entries()] == ["commitment", "acceptance"]
    with seller.records() as records:
        (agreed,) = records.agreed("demo-wba-1")
    assert agreed.record_digest == commitment.record_digest
    assert seller.ledger() == ["k-1"]
    proposal = seller.client.get("/proposals/demo-wba-1", headers=TOKEN).content
    assert items_by_id(read_json(proposal))[ITEM].get("status") == "agreed"
    assent = Proposal.model_validate_json(proposal).assent or []
    assert [e.role for e in assent] == ["commitment", "acceptance"]

    # The same commit again is a replay: the same result, and nothing written.
    again = seller.commit(commit)
    assert again.content == answer.content
    assert len(seller.entries()) == 2


# ── The ledger ────────────────────────────────────────────────────────────


def test_a_stored_rejection_is_replayed_as_stored(seller_with: StartSeller) -> None:
    seller = seller_with()
    commit = seller.composed()
    _set(("entry",), "record_digest", "sha256:" + "0" * 64)(commit)
    first = seller.commit(commit)
    assert first.status_code == 409
    again = seller.commit(commit)
    assert (again.status_code, again.content) == (409, first.content)
    assert seller.ledger() == ["k-1"]


def test_a_key_reused_with_another_commit_is_an_idempotency_conflict(
    seller_with: StartSeller,
) -> None:
    seller = seller_with()
    commit = seller.composed()
    wrong = json.loads(json.dumps(commit))
    _set(("entry",), "record_digest", "sha256:" + "0" * 64)(wrong)
    assert seller.commit(wrong).status_code == 409  # stored under k-1
    answer = seller.commit(commit)  # the same key, another commit
    assert answer.status_code == 422
    assert _codes(answer) == ["idempotency_conflict"]


def test_a_key_reused_on_another_proposal_is_an_idempotency_conflict(
    seller_with: StartSeller,
) -> None:
    seller = seller_with()
    commit = seller.composed()
    assert seller.commit(commit).status_code == 200
    answer = seller.commit(commit, path="/proposals/demo-wba-2/commit")
    assert answer.status_code == 422
    assert _codes(answer) == ["idempotency_conflict"]


def test_a_retry_same_rejection_is_not_stored_and_the_same_key_then_succeeds(
    seller_with: StartSeller,
) -> None:
    earlier = _entry("commitment", idempotency_key="earlier")
    seller = seller_with(prior=[earlier])
    commit = seller.composed()
    refused = seller.commit(commit)
    assert refused.status_code == 503
    assert [e.retry for e in parse_errors(refused.content)] == ["same"]
    assert seller.ledger() == []

    # The earlier commitment is withdrawn, so the same request can now succeed.
    store = SqliteSellerStore(seller.data_dir / "seller.db")
    try:
        with store.transaction():
            store.append_own_entry("demo-wba-1", _entry("withdrawal"))
    finally:
        store.close()
    accepted = seller.commit(commit)
    assert accepted.status_code == 200, accepted.text
    assert seller.ledger() == ["k-1"]
