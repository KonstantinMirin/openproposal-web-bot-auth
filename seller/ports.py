"""What the seller's logic needs from storage, as role ports and the values that cross them.

Only domain values cross a port, never rows. seller/sqlite_store.py implements
every port; the boundary (its `PrincipalDirectory`, in seller/boundary.py), the
offer logic, and onboarding each depend on the ports they use.

The offer logic never holds a caller's provenance. It writes the caller's own
entry through an `EntryWriter`, which the HTTP seam (seller/http.py) binds to
the provenance the boundary confirmed, so the offer logic can't read how the
caller authenticated, nor write an entry in another caller's name. Only the
writer reaches `KeptEvidence`, the port that keeps an entry with its
provenance.

A `Principal` is the one value of a party this seller knows. The store builds it
from its row, and the boundary hands it on, unchanged, in the `ResolvedCaller` it
returns (seller/caller.py).
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from openproposal import AssentEntry, ErrorObject

from persistence.values import Origin, PrincipalKind, Provenance
from protocol.values import JsonObject, Value


class Principal(Value):
    """A party this seller knows, as its own database records it.

    The party owns its identity, its domain and legal name; a credential only
    points at it, so one principal can hold a signature credential and a
    bearer credential at once. Its domain and legal name are written once,
    when onboarding first records it, and never rewritten: the proposals
    issued to it name them. The store reads a principal row straight into it,
    by its fields' names.
    """

    id: str
    kind: PrincipalKind
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


@dataclass(frozen=True, kw_only=True)
class ProcessedCommit:
    """A commit this seller processed (§ 5.6.1), and the rejection it stored, if any."""

    canonical: bytes
    proposal_id: str
    error: ErrorObject | None


class OfferRepository(Protocol):
    """Issued proposals, their assent log, and their agreed records."""

    def transaction(self) -> AbstractContextManager[None]: ...
    def issued(self, proposal_id: str) -> StoredProposal | None: ...
    def save_proposal(self, proposal: StoredProposal) -> None: ...
    def assent(self, proposal_id: str) -> list[AssentEntry]: ...
    def append_own_entry(self, proposal_id: str, entry: AssentEntry) -> None:
        """Appends the seller's own entry, which no caller wrote."""

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


class EntryWriter(Protocol):
    """Writes one caller's own assent entries: the offer logic's only view of the caller.

    The HTTP seam builds it from the provenance the boundary confirmed, so the
    offer logic sees the principal id and nothing of the credential.
    """

    @property
    def principal_id(self) -> str:
        """The principal the caller's credential resolved to."""

    def append(self, proposal_id: str, entry: AssentEntry, *, record_buyer: str | None) -> None:
        """Appends `entry`, which the caller wrote, to the log of `proposal_id`, inside the
        offer logic's transaction. `record_buyer` is the `buyer.domain` of the record the
        entry is about: the party a signature attributes it to, or not (§ 4.1.2). None
        names no party, which nothing is attributed to."""


class KeptEvidence(Protocol):
    """Keeps a caller's entry with the provenance the boundary confirmed. Only the entry
    writer the HTTP seam binds reaches it."""

    def append_caller_entry(
        self, proposal_id: str, entry: AssentEntry, provenance: Provenance, *, attributed: bool
    ) -> None:
        """Appends `entry` with who wrote it, how they authenticated, whether a signature
        attributes it (§ 4.1.2) and, for a signature, the signed request, in the caller's
        transaction."""


class Onboarding(OfferRepository, Protocol):
    """What onboarding the settings' buyer and the operator's `issue` need."""

    def principal(self, principal_id: str) -> Principal | None: ...
    def add_principal(self, principal: Principal) -> None:
        """Records a new principal. A principal already recorded is never rewritten."""

    def set_origin_credential(self, principal_id: str, origin: Origin) -> None:
        """Makes `origin` the principal's one signature credential."""

    def set_token_credential(self, principal_id: str, token: str | None) -> None:
        """Makes `token` the principal's one bearer credential; None leaves it none."""
