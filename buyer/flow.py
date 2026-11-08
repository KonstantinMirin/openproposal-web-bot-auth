"""The buyer's side of offer acceptance: read the issued proposal, commit, check the answer.

`Buyer.commit` is a sequence of protocol operations: resolve the seller among
the sellers the buyer deals with, read the proposal (`SellerClient.read`), compose the
`commit` (`protocol.compose_commit`), send it (`SellerClient.commit`), check
the answer (`protocol.check_result`), and keep the agreement
(`BuyerRepository.keep_agreement`). Each step returns a value; the first
refusal ends the flow, and the outcome says which state it reached.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from openproposal import Commit, LineItemWrites

from persistence.values import AuthMethod, Origin
from protocol.attribution import attributes
from protocol.operations import (
    ProtocolViolation,
    check_result,
    compose_commit,
    is_stored_result,
    parse_commit,
)
from shared.keyring import SigningIdentity
from transport.control import Agreed, Outcome, Read, Refused, Rejected, SellerView

from .credentials import Bearer, BuyerCredential, SignWith
from .plan import Plan
from .refusal import Reason, Refusal
from .repository import BuyerRepository, CommitKey, PendingCommit
from .seller_client import Accepted, ReadProposal, Rejection, SellerClient
from .settings import Counterparty


@dataclass(frozen=True)
class _Call:
    """Who the buyer calls, and with which credential."""

    seller: Counterparty
    credential: BuyerCredential

    @property
    def view(self) -> SellerView:
        return _view(self.seller)

    def refused(self, refusal: Refusal) -> Refused:
        return _refused(self.view, self.credential.method, refusal)

    def rejected(self, rejection: Rejection, commit_id: int | None) -> Rejected:
        return Rejected(
            seller=self.view,
            authentication_method=self.credential.method,
            errors=tuple(rejection.errors),
            commit_id=commit_id,
        )


def _view(seller: Counterparty) -> SellerView:
    return SellerView(origin=seller.origin, domain=seller.domain, legal_name=seller.legal_name)


def _refused(seller: SellerView | None, method: AuthMethod, refusal: Refusal) -> Refused:
    return Refused(
        seller=seller, authentication_method=method, reason=refusal.reason, detail=refusal.detail
    )


class Buyer:
    """The offer flow, over the buyer's records, its sellers, its seller client, its signing
    identity, whose origin it keeps with each signed answer as the receiver, and its plan."""

    def __init__(
        self,
        repo: BuyerRepository,
        sellers: Sequence[Counterparty],
        client: SellerClient,
        signing: SigningIdentity,
        plan: Plan,
    ) -> None:
        self.repo, self.client, self.signing, self.plan = repo, client, signing, plan
        self.sellers = {seller.origin: seller for seller in sellers}

    def _call(self, seller_origin: Origin, method: AuthMethod) -> _Call | Refused:
        """The seller, resolved once from the sellers the buyer deals with, and the credential."""
        seller = self.sellers.get(seller_origin)
        if seller is None:
            detail = f"{seller_origin} is not a seller this buyer deals with"
            return _refused(None, method, Refusal(Reason.UNKNOWN_SELLER, detail))
        credential = self._credential(seller, method)
        if isinstance(credential, Refusal):
            return _refused(_view(seller), method, credential)
        return _Call(seller, credential)

    def _credential(self, seller: Counterparty, method: AuthMethod) -> BuyerCredential | Refusal:
        if method == "web_bot_auth":
            return SignWith(self.signing.signer())
        if seller.bearer_token is None:
            return Refusal(Reason.NOT_ISSUED, f"{seller.origin} issued this buyer no token")
        return Bearer(seller.bearer_token)

    async def read(self, seller_origin: Origin, proposal_id: str, method: AuthMethod) -> Outcome:
        """Reads the proposal and verifies the seller's signed answer."""
        call = self._call(seller_origin, method)
        if isinstance(call, Refused):
            return call
        answer = await self.client.read(call.seller, call.credential, proposal_id)
        if isinstance(answer, Refusal):
            return call.refused(answer)
        if isinstance(answer, Rejection):
            return call.rejected(answer, None)
        return Read(
            seller=call.view,
            authentication_method=method,
            keyid=call.credential.keyid,
            proposal=answer.raw,
        )

    async def commit(
        self,
        seller_origin: Origin,
        proposal_id: str,
        line_item_ids: Sequence[str],
        method: AuthMethod,
    ) -> Outcome:
        """Reads, commits to `line_item_ids`, verifies the signed answer, keeps the agreement."""
        call = self._call(seller_origin, method)
        if isinstance(call, Refused):
            return call
        writes = self.plan.writes_for(line_item_ids)
        if isinstance(writes, Refusal):
            return call.refused(writes)
        read = await self.client.read(call.seller, call.credential, proposal_id)
        if not isinstance(read, ReadProposal):
            return call.refused(_unreadable(proposal_id, read))
        key = CommitKey(
            seller_origin=call.seller.origin, proposal_id=proposal_id, line_item_ids=tuple(writes)
        )
        pending = self._pending(key, read, writes)
        answer = await self.client.commit(call.seller, call.credential, proposal_id, pending.body)
        if isinstance(answer, Refusal):
            return call.refused(answer)
        if isinstance(answer, Rejection):
            return self._rejected(call, answer, pending)
        return self._agree(call, read, pending, answer)

    def _pending(
        self, key: CommitKey, read: ReadProposal, writes: dict[str, LineItemWrites]
    ) -> PendingCommit:
        """The pending `commit` for `key`, re-sent whole, or a newly composed one (§ 5.6.1)."""
        pending = self.repo.pending(key)
        if pending is not None:
            return pending
        composed = compose_commit(
            read.proposal, read.raw, writes, at=datetime.now(UTC), key=str(uuid.uuid4())
        )
        return self.repo.add_pending(key, composed.commit, composed.digest_input)

    def _rejected(self, call: _Call, rejection: Rejection, pending: PendingCommit) -> Rejected:
        """The seller said no. A stored rejection settles the commit; `retry: same` doesn't."""
        if is_stored_result(rejection.errors):
            self.repo.settle_rejected(pending.id, rejection.errors)
        return call.rejected(rejection, pending.id)

    def _agree(
        self, call: _Call, read: ReadProposal, pending: PendingCommit, answer: Accepted
    ) -> Outcome:
        """Checks the pair from the agreed record (§ 4.1.2), then keeps the signed answer and
        settles the commit, in one transaction."""
        commit: Commit = parse_commit(pending.body)
        try:
            acceptance = check_result(commit, answer.result, pending.digest_input)
        except ProtocolViolation as e:
            return call.refused(
                Refusal(Reason.RESULT_MISMATCH, f"the seller's CommitResult is refused: {e}")
            )
        verified = answer.exchange.verified
        attributed = attributes(
            verified.origin.host, read.proposal.seller.domain, body_covered=verified.body_covered
        )
        evidence_id = self.repo.keep_agreement(
            pending.id,
            answer.exchange.evidence(self.signing.origin),
            answer.result.entries,
            attributed=attributed,
        )
        return Agreed(
            proposal_id=pending.key.proposal_id,
            seller=call.view,
            authentication_method=call.credential.method,
            keyid=call.credential.keyid,
            record_digest=acceptance.record_digest,
            entries=tuple(answer.result.entries),
            attributed=attributed,
            commit_id=pending.id,
            evidence_id=evidence_id,
        )


def _unreadable(proposal_id: str, answer: Rejection | Refusal) -> Refusal:
    """The read before a commit failed, so there is nothing to commit to."""
    if isinstance(answer, Refusal):
        return answer
    codes = ", ".join(e.code for e in answer.errors)
    return Refusal(Reason.UNREADABLE_PROPOSAL, f"reading {proposal_id} was refused: {codes}")
