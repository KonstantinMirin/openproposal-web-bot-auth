"""9. The buyer refuses a seller answer it can't verify, then retries the same commit.

The seller's test-only fault toggle (seller/faults.py) strips the answer's
signature, signs it unbound or bound to another request, or signs it over a
body with one byte changed. It breaks the answers to reads or to commits. For
each credential, each fault the buyer must refuse is refused, on a read and on
a commit. A bearer request is unsigned, so it has no signature for an answer to
be bound to: an unbound or rebound answer is what it should get.

On a commit, the seller has accepted, but the buyer refuses the answer and
records no agreement. It then re-sends the same Commit, with the same
idempotency_key. The seller returns the stored result and writes no second
entry (§ 5.6.1). Once the answer verifies, the buyer records the agreement.
"""

from collections.abc import Callable, Iterator

import pytest
from openproposal import AssentEntryRole

from persistence.observe import BuyerRecords, SellerRecords
from persistence.values import AuthMethod
from transport.client import ControlClient
from transport.control import (
    COMMIT,
    FAULT,
    READ,
    Agreed,
    CommitTrigger,
    FaultMode,
    FaultName,
    FaultTarget,
    Read,
    ReadTrigger,
    Refused,
)

#: Sets the seller's fault, and which answers it breaks.
SetFault = Callable[[FaultName, FaultTarget], None]
#: Each credential's own proposal and line item, which no earlier scenario commits to.
TRIGGER: dict[AuthMethod, CommitTrigger] = {
    "web_bot_auth": CommitTrigger(proposal_id="demo-wba-2", line_item_ids=["weather-app-ctv"]),
    "bearer": CommitTrigger(
        proposal_id="demo-bearer-1", line_item_ids=["weather-app-ctv"], credential="bearer"
    ),
}
#: The faults each credential must refuse, with the library's reason for each.
FAULTS: dict[AuthMethod, list[tuple[FaultName, str]]] = {
    "web_bot_auth": [
        ("strip", "signature-missing"),
        ("unbound", "response-not-bound"),
        ("rebound", "signature-invalid"),
        ("wrong_digest", "content-digest"),
    ],
    "bearer": [("strip", "signature-missing"), ("wrong_digest", "content-digest")],
}
CREDENTIALS = list(TRIGGER)


@pytest.fixture
def fault(seller_control: ControlClient) -> Iterator[SetFault]:
    def set_fault(mode: FaultName, on: FaultTarget) -> None:
        seller_control.call(FAULT, FaultMode(mode=mode, on=on))

    yield set_fault
    set_fault("none", "commit")


def _refused(outcome: object) -> Refused:
    assert isinstance(outcome, Refused), outcome
    return outcome


def _seller_state(
    seller_records: SellerRecords, proposal_id: str
) -> tuple[list[tuple[AssentEntryRole, str | None]], list[str]]:
    entries = [(e.role, e.idempotency_key) for e in seller_records.entries(proposal_id)]
    return entries, seller_records.processed(proposal_id)


@pytest.mark.parametrize("credential", CREDENTIALS)
def test_buyer_refuses_unverifiable_reads(
    buyer_control: ControlClient, fault: SetFault, credential: AuthMethod
) -> None:
    trigger = TRIGGER[credential]
    read = ReadTrigger(proposal_id=trigger.proposal_id, credential=trigger.credential)
    for mode, reason in FAULTS[credential]:
        fault(mode, "read")
        outcome = _refused(buyer_control.call(READ, read))
        assert outcome.code == reason, (mode, outcome)
        assert outcome.authentication_method == credential

    fault("none", "commit")
    assert isinstance(buyer_control.call(READ, read), Read)


@pytest.mark.parametrize("credential", CREDENTIALS)
def test_buyer_refuses_unverifiable_commit_answers(
    buyer_control: ControlClient,
    fault: SetFault,
    seller_records: SellerRecords,
    buyer_records: BuyerRecords,
    credential: AuthMethod,
) -> None:
    trigger = TRIGGER[credential]
    proposal_id, items = trigger.proposal_id, trigger.line_item_ids
    before_entries, before_processed = _seller_state(seller_records, proposal_id)
    accepted = None
    for mode, reason in FAULTS[credential]:
        fault(mode, "commit")
        outcome = _refused(buyer_control.call(COMMIT, trigger))
        assert outcome.code == reason, (mode, outcome)

        pending = buyer_records.commits(proposal_id, items)
        assert [p.state for p in pending] == ["pending"]  # one Commit, still unconfirmed
        key = pending[0].idempotency_key
        state = _seller_state(seller_records, proposal_id)
        if accepted is None:
            # The first faulted attempt reached the offer logic: the seller accepted it.
            assert state == (
                [*before_entries, ("commitment", key), ("acceptance", None)],
                sorted([*before_processed, key]),
            )
            accepted = state
        else:
            # Each retry is a replay of that commit: the stored result, and no new entry.
            assert state == accepted

    fault("none", "commit")
    agreed = buyer_control.call(COMMIT, trigger)
    assert isinstance(agreed, Agreed), agreed
    assert agreed.authentication_method == credential
    assert _seller_state(seller_records, proposal_id) == accepted
