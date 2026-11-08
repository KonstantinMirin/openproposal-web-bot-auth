"""What a runner step returns, and the checks it makes over typed values.

A step returns `Done(value, detail)`: the value goes into the report, and the
detail line into the step's row. A check that fails raises `CheckFailed`,
which the schedule records as the step's failure (runner/main.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import NoReturn

from openproposal import AssentEntryRoles

from persistence.observe import KeptAgreement, KeptCommit, KeptEntry
from persistence.values import AuthMethod
from transport.control import Agreed, CfbotAccepted, CfbotRefused, CloudflareCheck, Outcome


@dataclass(frozen=True)
class Done[V]:
    """A step's value, and the one line its row in the report shows."""

    value: V
    detail: str


class CheckFailed(Exception):
    """A step's expectation didn't hold."""


def fail(message: str) -> NoReturn:
    raise CheckFailed(message)


def given[T](value: T | None, what: str) -> T:
    """A value an earlier step produced. The schedule skips a step whose inputs failed,
    so a missing one means the schedule is wrong."""
    if value is None:
        fail(f"no {what}: the step it needs produced none")
    return value


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def agreed(outcome: Outcome, method: AuthMethod) -> Agreed:
    """The buyer reached agreement, with the credential the step asked for."""
    if not isinstance(outcome, Agreed):
        fail(f"{outcome.state}: {outcome.model_dump_json()}")
    expect(outcome.authentication_method == method, "the buyer used another credential")
    return outcome


def commitment(entries: list[KeptEntry], principal_id: str, method: AuthMethod) -> KeptEntry:
    """The seller resolved the stored principal, by the credential the buyer used."""
    entry = next((e for e in entries if e.role == AssentEntryRoles.COMMITMENT), None)
    if entry is None:
        fail("the seller holds no commitment entry")
    expect(
        entry.principal_id == principal_id,
        f"the seller resolved {entry.principal_id}, not {principal_id}",
    )
    expect(
        entry.authentication_method == method, f"the seller recorded {entry.authentication_method}"
    )
    if method == "bearer":
        expect(entry.evidence_id is None, "a bearer commit has no signature evidence")
    else:
        expect(entry.evidence_id is not None, "a signed commit keeps its request")
    return entry


def same_digest(
    agreements: list[KeptAgreement], commit: KeptCommit | None, digest: str, outcome: Agreed
) -> KeptAgreement:
    """Both parties hold the same digest input, and it hashes to the agreed record_digest."""
    expect(len(agreements) == 1, f"the seller holds {len(agreements)} agreed records")
    if commit is None:
        fail("the buyer holds no such commit")
    (agreement,) = agreements
    expect(agreement.digest_input == commit.digest_input, "the parties' digest inputs differ")
    expect(
        digest == agreement.record_digest == outcome.record_digest,
        "record_digest doesn't recompute from the digest input",
    )
    return agreement


def cfbot_accepted(check: CloudflareCheck, buyer: str) -> CfbotAccepted:
    """cfbot verified the buyer's signature as the buyer's origin."""
    verdict = check.verdict
    if isinstance(verdict, CfbotRefused):
        fail(f"cfbot refused: {check.status} {verdict.error}")
    expect(check.status == HTTPStatus.OK, f"cfbot accepted with status {check.status}")
    expect(verdict.identity == buyer, f"cfbot saw {verdict.identity}")
    return verdict
