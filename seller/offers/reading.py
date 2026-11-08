"""Reading an issued proposal, and reading a request body as a `Commit`."""

from __future__ import annotations

from openproposal import Commit, dump
from pydantic import ValidationError

from protocol.operations import ProtocolViolation
from protocol.operations import parse_commit as parse_commit_body
from protocol.values import JsonObject, JsonValue, MalformedJsonError
from seller.caller import Caller, ResolvedCaller
from seller.errors import Rejected, validation_detail
from seller.ports import OfferRepository, StoredProposal


def parse_commit(body: bytes) -> Commit | Rejected:
    """The request body as a `Commit` (§ 5.6.1), or a `validation` rejection (§ 2.4).

    A body that isn't a JSON object in the RFC 8785 number domain is refused
    here too, before anything digests it.
    """
    try:
        return parse_commit_body(body)
    except MalformedJsonError as e:
        return Rejected.of("validation", str(e))
    except ValidationError as e:
        detail = validation_detail(e.errors()) or "the body is not a Commit"
        return Rejected.of("validation", detail)
    except ProtocolViolation as e:
        return Rejected.of("validation", str(e))


def issued_to(store: OfferRepository, caller: Caller, proposal_id: str) -> StoredProposal | None:
    """The stored proposal, when it is issued to the caller's principal (§ 4.3)."""
    found = store.issued(proposal_id)
    if (
        found is None
        or not isinstance(caller, ResolvedCaller)
        or found.buyer_principal_id != caller.principal.id
    ):
        return None
    return found


def not_found(proposal_id: str) -> Rejected:
    """An issued proposal exists only for its buyer (§ 2.4 `not_found`)."""
    return Rejected.of("not_found", f"no proposal {proposal_id} for this caller")


def full_representation(
    store: OfferRepository, caller: Caller, proposal_id: str
) -> JsonObject | Rejected:
    """The Full Representation (§ 2.1) of an issued proposal, for its buyer only."""
    issued = issued_to(store, caller, proposal_id)
    if issued is None:
        return not_found(proposal_id)
    assent: list[JsonValue] = [dump(e) for e in store.assent(proposal_id)]
    return {**issued.document, "assent": assent} if assent else issued.document
