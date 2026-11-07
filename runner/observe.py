"""The runner's steps: what it asks the agents, and what it reads of what each party kept.

The runner reaches the agents' own controls through their typed control-plane
models (transport/control.py), and reads both parties' databases read-only through
their read models (persistence/observe.py), never with its own SQL. It holds no
agent's key: what it verifies, it verifies against the directory bytes a party
kept, or against a directory it fetches itself.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import httpx
from iab_agentic_primitives.web_bot_auth import (
    DirectoryResponse,
    Origin,
    ServerIdentity,
    parse_directory_response,
)

from persistence.evidence import KeptFetch, KeptRequest, KeptResponse
from persistence.observe import BuyerRecords, SellerRecords
from protocol.record import digest_of, sha256_hex
from protocol.values import instant
from transport.auth import AuthMethod
from transport.control import OUTCOME, Agreed, CloudflareCheck, CommitTrigger, Issued, IssueRequest

from . import checks
from .checks import Done, expect
from .report import (
    Answer,
    BuyerSide,
    Digest,
    Directory,
    Message,
    Reverified,
    SellerSide,
    body_of,
    public_headers,
    public_key,
)
from .settings import RunnerSettings

LINE_ITEM = "business-daily-display"


def instant_of(seconds: float) -> str:
    return instant(datetime.fromtimestamp(seconds, UTC))


def _kept_directory(kept: KeptFetch) -> Directory:
    body = body_of(kept.body)
    keys = body.get("keys", []) if isinstance(body, dict) else []
    return Directory(
        url=kept.url,
        status=kept.status,
        fetched_at=None if kept.fetched_at is None else instant_of(kept.fetched_at),
        headers=public_headers(kept.headers),
        keys=[public_key(k) for k in keys] if isinstance(keys, list) else [],
        sha256=sha256_hex(kept.body),
    )


def _message(kept: KeptRequest) -> Message:
    request = kept.request
    return Message(
        method=request.method,
        url=request.url,
        keyid=kept.keyid,
        headers=public_headers(request.headers.items()),
        body=body_of(request.body),
    )


def _answer(kept: KeptResponse) -> Answer:
    response = kept.response
    return Answer(
        status=response.status,
        keyid=kept.keyid,
        headers=public_headers(response.headers.items()),
        body=body_of(response.body),
    )


class Observer:
    """The steps of one run, against one deployment."""

    def __init__(
        self, settings: RunnerSettings, control: httpx.AsyncClient, web: httpx.AsyncClient
    ) -> None:
        #: `control` reaches the agents' own controls; `web` fetches over public HTTPS.
        self.settings, self.control, self.web = settings, control, web

    async def directory(self, origin: Origin) -> Done[Directory]:
        """Fetches the origin's directory as a verifier does, and verifies it with the library."""
        url = origin.directory_url
        response = await self.web.get(url, headers={"Accept-Encoding": "identity"})
        lines = response.headers.multi_items()
        now = int(time.time())
        fetched = DirectoryResponse(url, response.status_code, lines, response.content, now)
        verified = parse_directory_response(fetched, origin.authority, now)
        body = body_of(response.content)
        keys = body.get("keys", []) if isinstance(body, dict) else []
        directory = Directory(
            url=url,
            status=response.status_code,
            expires=instant_of(verified.expires),
            headers=public_headers(lines),
            keys=[public_key(k) for k in keys] if isinstance(keys, list) else [],
        )
        kids = list(verified.keys)
        return Done(directory, f"{len(kids)} key(s), signed by each: {', '.join(kids)}")

    async def issue(self, principal_id: str) -> Done[Issued]:
        response = await self.control.post(
            f"{self.settings.seller_control}/operator/issue",
            json=IssueRequest(principal_id=principal_id).model_dump(),
        )
        expect(
            response.status_code == httpx.codes.OK,
            f"issue returned {response.status_code}: {response.text}",
        )
        issued = Issued.model_validate_json(response.content)
        return Done(issued, issued.proposal_id)

    async def commit(self, issued: Issued | None, method: AuthMethod) -> Done[Agreed]:
        trigger = CommitTrigger(
            seller=str(self.settings.seller),
            proposal_id=checks.given(issued, "issued proposal").proposal_id,
            line_item_ids=[LINE_ITEM],
            credential=method,
        )
        response = await self.control.post(
            f"{self.settings.buyer_control}/operator/commit", json=trigger.model_dump()
        )
        expect(
            response.status_code == httpx.codes.OK,
            f"commit returned {response.status_code}: {response.text}",
        )
        outcome = checks.agreed(OUTCOME.validate_json(response.content), method)
        return Done(outcome, f"agreed, record_digest {outcome.record_digest}")

    def seller_side(
        self, outcome: Agreed | None, method: AuthMethod, principal_id: str
    ) -> Done[SellerSide]:
        """What the seller's boundary resolved, and the signed request it kept."""
        proposal_id = checks.given(outcome, "agreement").proposal_id
        with SellerRecords.open(self.settings.seller_db) as seller:
            entry = checks.commitment(seller.entries(proposal_id), principal_id, method)
            side = SellerSide(
                principal_id=principal_id,
                authentication_method=method,
                attributed=entry.attributed,
                evidence_id=entry.evidence_id,
            )
            if entry.evidence_id is None:
                return Done(side, f"resolved {principal_id} by token hash; no signature evidence")
            kept = seller.request(entry.evidence_id)
            expect(kept.origin == str(self.settings.buyer), f"evidence from {kept.origin}")
            directory = (
                None if kept.directory_digest is None else seller.directory(kept.directory_digest)
            )
        side = side.model_copy(
            update={
                "request": _message(kept),
                "directory": None if directory is None else _kept_directory(directory),
            }
        )
        return Done(side, f"resolved {principal_id} from origin {kept.origin}, keyid {kept.keyid}")

    def buyer_side(self, agreed: Agreed | None) -> Done[BuyerSide]:
        """The request as the buyer sent it, and the seller's signed answer as it arrived."""
        outcome = checks.given(agreed, "agreement")
        with BuyerRecords.open(self.settings.buyer_db) as buyer:
            kept = buyer.response(outcome.evidence_id)
            expect(kept.origin == str(self.settings.seller), f"answer from {kept.origin}")
            directory = (
                None if kept.directory_digest is None else buyer.directory(kept.directory_digest)
            )
        request = _message(kept.request)
        if outcome.authentication_method == "bearer":
            # The request carried the token; the buyer's evidence never stores it.
            withheld = sorted({*request.headers.withheld, "authorization"})
            headers = request.headers.model_copy(update={"withheld": withheld})
            request = request.model_copy(update={"headers": headers})
        side = BuyerSide(
            evidence_id=kept.id,
            request=request.model_copy(update={"keyid": outcome.keyid}),
            response=_answer(kept),
            directory=None if directory is None else _kept_directory(directory),
        )
        return Done(side, f"kept the seller's signed answer, keyid {kept.keyid}")

    def same_digest(self, agreed: Agreed | None) -> Done[Digest]:
        """Both parties hold the same digest input, and it hashes to the agreed record_digest."""
        outcome = checks.given(agreed, "agreement")
        proposal_id = outcome.proposal_id
        with SellerRecords.open(self.settings.seller_db) as seller:
            agreements = seller.agreed(proposal_id)
        with BuyerRecords.open(self.settings.buyer_db) as buyer:
            commit = buyer.commit(outcome.commit_id)
        recomputed = digest_of(commit.digest_input) if commit is not None else ""
        agreement = checks.same_digest(agreements, commit, recomputed, outcome)
        digest = Digest(record_digest=recomputed, digest_input_bytes=len(agreement.digest_input))
        return Done(digest, f"both sides: {recomputed}")

    async def reverify(
        self, seller: SellerSide | None, buyer: BuyerSide | None
    ) -> Done[Reverified]:
        """Verifies both kept messages again, offline, against the directory bytes each kept."""
        request_id = checks.given(
            checks.given(seller, "seller side").evidence_id, "seller evidence"
        )
        response_id = checks.given(buyer, "buyer side").evidence_id
        with SellerRecords.open(self.settings.seller_db) as records:
            again = await records.reverify_request(
                records.request(request_id),
                ServerIdentity.from_config(str(self.settings.seller)),
            )
        expect(
            again.origin == self.settings.buyer and again.body_covered,
            "the seller's evidence doesn't verify again",
        )
        with BuyerRecords.open(self.settings.buyer_db) as records:
            answered = await records.reverify_response(records.response(response_id))
        expect(
            answered.bound and answered.body_covered, "the buyer's evidence doesn't verify again"
        )
        reverified = Reverified(
            request_components=list(again.components),
            response_components=list(answered.components),
            response_bound=answered.bound,
        )
        return Done(
            reverified, "the signed request and the bound answer both verify from stored bytes"
        )

    async def cloudflare(self) -> Done[CloudflareCheck]:
        response = await self.control.post(
            f"{self.settings.buyer_control}/operator/cloudflare-check"
        )
        expect(
            response.status_code == httpx.codes.OK,
            f"cloudflare-check returned {response.status_code}",
        )
        check = CloudflareCheck.model_validate_json(response.content)
        verdict = checks.cfbot_accepted(check, str(self.settings.buyer))
        return Done(check, f"{verdict.get('verifier')} accepted {verdict.get('identity')}")
