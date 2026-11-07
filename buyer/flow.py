"""The buyer's side of offer acceptance: read the issued proposal, commit, and check the answer."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from iab_agentic_primitives.web_bot_auth import DirectoryResolver, RequestSigner, WebBotAuthError
from openproposal import dump_json
from pydantic import BaseModel

from demo_types.stack import AssentEntry, Commit, CommitResult
from shared.attribution import attributes
from shared.record import compose, digest_input, digest_of

from .client import Credential, Exchange, call_seller
from .keyring import Keyring
from .store import Store


class Outcome(BaseModel):
    """What the operator trigger reports."""

    state: str  # read | agreed | rejected (the seller said no) | refused (the buyer said no)
    detail: str | None = None
    seller: dict[str, Any] | None = None
    authentication_method: Credential | None = None
    keyid: str | None = None
    record_digest: str | None = None
    entries: list[dict[str, Any]] | None = None
    errors: list[dict[str, Any]] | None = None
    attributed: bool | None = None
    evidence_id: int | None = None
    commit_id: int | None = None


class Refusal(Exception):
    """The buyer refuses what the seller sent, so it writes nothing."""


class Buyer:
    def __init__(self, store: Store, resolver: DirectoryResolver, keyring: Keyring, origin: str,
                 plan: dict[str, dict[str, Any]], *, signature_lifetime: int = 300) -> None:
        self.store, self.resolver, self.keyring, self.origin = store, resolver, keyring, origin
        self.plan, self.signature_lifetime = plan, signature_lifetime

    @property
    def signer(self) -> RequestSigner:
        """Signs as this buyer's origin with its active key."""
        return RequestSigner(self.keyring.active(), self.origin, lifetime=self.signature_lifetime)

    async def _call(self, seller: dict, credential: Credential, method: str, path: str,
                    body: bytes = b"") -> Exchange:
        try:
            exchange = await call_seller(
                method, seller["origin"] + path, seller_origin=seller["origin"],
                resolver=self.resolver,
                signer=self.signer if credential == "web_bot_auth" else None,
                token=seller["bearer_token"], body=body,
            )
        except WebBotAuthError as e:
            raise Refusal(f"the seller's response is refused: {e.reason}: {e}") from e
        # The seller is whoever the verified origin is in this buyer's own records.
        if self.store.seller(exchange.verified.origin) is None:
            raise Refusal(f"{exchange.verified.origin} is not a seller this buyer deals with")
        return exchange

    def _seller(self, origin: str) -> dict:
        seller = self.store.seller(origin)
        if seller is None:
            raise Refusal(f"{origin} is not a seller this buyer deals with")
        return seller

    async def read(self, seller_origin: str, proposal_id: str, credential: Credential) -> Outcome:
        try:
            seller = self._seller(seller_origin)
            exchange = await self._call(seller, credential, "GET", f"/proposals/{proposal_id}")
        except Refusal as e:
            return Outcome(state="refused", detail=str(e))
        # A signed refusal verifies as well as an answer does, so the status decides.
        state = "read" if exchange.status == 200 else "rejected"
        return Outcome(state=state, detail=f"status {exchange.status}: {exchange.body.decode()}",
                       seller=_party(seller), authentication_method=credential,
                       keyid=exchange.keyid)

    async def commit(self, seller_origin: str, proposal_id: str, line_item_ids: list[str],
                     credential: Credential) -> Outcome:
        try:
            return await self._commit(seller_origin, proposal_id, line_item_ids, credential)
        except Refusal as e:
            return Outcome(state="refused", detail=str(e), authentication_method=credential)

    async def _commit(self, seller_origin: str, proposal_id: str, line_item_ids: list[str],
                      credential: Credential) -> Outcome:
        seller = self._seller(seller_origin)

        # 1. Read the issued proposal.
        read = await self._call(seller, credential, "GET", f"/proposals/{proposal_id}")
        if read.status != 200:
            raise Refusal(f"reading {proposal_id} returned {read.status}: {read.body.decode()}")
        proposal = json.loads(read.body)
        if proposal["seller"]["domain"] != seller["domain"]:
            raise Refusal(f"{proposal_id} names seller {proposal['seller']['domain']}")

        # 2. Compose the Commit, or re-send the pending one whole (§ 4.1.2, § 5.6.1).
        row = self.store.pending_commit(seller_origin, proposal_id, line_item_ids)
        if row is None:
            writes = {name: self.plan[name] for name in line_item_ids}
            data = digest_input(compose(proposal, writes), line_item_ids)
            entry = AssentEntry(
                role="commitment", version=proposal["version"], record_digest=digest_of(data),
                line_item_ids=line_item_ids, at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                idempotency_key=str(uuid.uuid4()),
            )
            body = dump_json(Commit(entry=entry, writes=writes)).encode()
            row = self.store.add_commit(seller_origin, proposal_id, line_item_ids,
                                        entry.idempotency_key, body, data)
        commit = Commit.model_validate_json(row["body"])

        # 3. Send it, signed or with the bearer token.
        answer = await self._call(seller, credential, "POST", f"/proposals/{proposal_id}/commit",
                                  row["body"])
        if answer.status != 200:
            errors = json.loads(answer.body).get("errors")
            if errors and all(e.get("retry") != "same" for e in errors):
                self.store.settle_commit(row["id"], "rejected", errors=errors)
            return Outcome(state="rejected", errors=errors, detail=answer.body.decode(),
                           seller=_party(seller), authentication_method=credential,
                           commit_id=row["id"])

        # 4. Check the matching pair from the agreed record (§ 4.1.2).
        result = CommitResult.model_validate_json(answer.body)
        if result.entries[0].wire() != commit.entry.wire():
            raise Refusal("the CommitResult doesn't start with this buyer's entry")
        acceptance = next((e for e in result.entries[1:]
                           if e.role == "acceptance" and e.matches(commit.entry)), None)
        if acceptance is None:
            raise Refusal(f"no matching acceptance: {[e.role for e in result.entries]}")
        if digest_of(row["digest_input"]) != acceptance.record_digest:
            raise Refusal("record_digest doesn't recompute from the agreed record")

        # 5. Keep the agreed record and the signed answer as evidence.
        verified = answer.verified
        attributed = attributes(verified.host, proposal["seller"]["domain"],
                                body_covered=verified.body_covered)
        entries = [e.wire() for e in result.entries]
        evidence_id = self.store.record_evidence(
            commit_id=row["id"], origin=verified.origin, keyid=verified.keyid,
            attributed=attributed, request=answer.request_record(), status=answer.status,
            headers=answer.headers, body=answer.body,
            directory=verified.directory,
        )
        self.store.settle_commit(row["id"], "agreed", entries=entries)
        return Outcome(
            state="agreed", seller=_party(seller), authentication_method=credential,
            keyid=answer.keyid,
            record_digest=acceptance.record_digest, entries=entries, attributed=attributed,
            evidence_id=evidence_id, commit_id=row["id"],
        )


def _party(seller: dict) -> dict:
    return {"origin": seller["origin"], "domain": seller["domain"], "legal_name": seller["legal_name"]}
