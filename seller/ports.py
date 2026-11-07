"""What the seller's logic needs from storage, as role ports and the values that cross them.

Only domain values cross a port, never rows. seller/sqlite_store.py implements
every port; the boundary, the offer logic, and the first-boot records each
depend on the ports they use.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from openproposal import AssentEntry, ErrorObject

from persistence.evidence import StoredRequest
from protocol.values import JsonObject
from shared.wba import AuthMethod


@dataclass(frozen=True)
class PrincipalRecord:
    """A party this seller knows, as its records hold it. The boundary makes it a `Principal`."""

    id: str
    legal_name: str
    domain: str


@dataclass(frozen=True)
class StoredProposal:
    """An issued proposal (§ 4.3): its Full Representation without `assent[]`."""

    buyer_principal_id: str
    document: JsonObject

    @property
    def proposal_id(self) -> str:
        return str(self.document["proposal_id"])


@dataclass(frozen=True)
class ProcessedCommit:
    """A commit this seller processed (§ 5.6.1), and the rejection it stored, if any."""

    canonical: bytes
    proposal_id: str
    error: ErrorObject | None


@dataclass(frozen=True)
class Provenance:
    """How the entry's principal authenticated, and the signed request that carried it."""

    principal_id: str
    method: AuthMethod
    evidence_id: int | None
    attributed: bool


class PrincipalDirectory(Protocol):
    """The boundary's lookups: a principal by its verified origin, or by its token."""

    def for_origin(self, origin: str) -> PrincipalRecord | None: ...
    def for_token(self, token: str) -> PrincipalRecord | None: ...


class EvidenceLog(Protocol):
    """Where the boundary keeps a request it verified. Step 4 moves this into the entry write."""

    def keep_request(self, stored: StoredRequest) -> int: ...


class BoundaryRecords(PrincipalDirectory, EvidenceLog, Protocol):
    """What the identity boundary needs."""


class OfferRepository(Protocol):
    """Issued proposals, their assent log, and their agreed records."""

    def transaction(self) -> AbstractContextManager[None]: ...
    def issued(self, proposal_id: str) -> StoredProposal | None: ...
    def save_proposal(self, proposal: StoredProposal) -> None: ...
    def assent(self, proposal_id: str) -> list[AssentEntry]: ...
    def append_assent(
        self, proposal_id: str, entry: AssentEntry, provenance: Provenance | None
    ) -> None: ...
    def save_agreed(
        self, proposal_id: str, digest: str, digest_input: bytes, entries: Sequence[AssentEntry]
    ) -> None: ...


class CommitLedger(Protocol):
    """Each commit processed, by buyer and idempotency_key (§ 5.6.1)."""

    def processed(self, principal_id: str, key: str) -> ProcessedCommit | None: ...
    def record(
        self,
        principal_id: str,
        key: str,
        proposal_id: str,
        canonical: bytes,
        error: ErrorObject | None,
    ) -> None: ...


class OfferStore(OfferRepository, CommitLedger, Protocol):
    """What `commit` needs: the repository and the ledger, in one transaction."""


class Onboarding(OfferRepository, Protocol):
    """What the first-boot records and the operator's `issue` need."""

    def is_empty(self) -> bool: ...
    def principal(self, principal_id: str) -> PrincipalRecord | None: ...
    def add_principal(self, principal: PrincipalRecord) -> None: ...
    def add_origin_credential(self, principal_id: str, origin: str) -> None: ...
    def add_token_credential(self, principal_id: str, token: str) -> None: ...
