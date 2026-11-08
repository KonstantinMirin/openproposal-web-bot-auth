"""Verifying a kept message again, offline, against the directory bytes kept with it.

§ 4.1.2 asks a party to keep the counterparty's signed message and the key
directory it verified against, so that the message can be shown to verify
later. These functions take what a party's records hold (persistence/evidence.py)
and verify it with the library, with no network: the keys come from the kept
directory fetch, after the library verifies that fetch's own signatures again.
"""

from __future__ import annotations

from iab_agentic_primitives.web_bot_auth import (
    MemoryNonceStore,
    RequestVerifier,
    ResponseVerifier,
    ServerIdentity,
    StaticKeyResolver,
    UnixSeconds,
    VerifiedRequest,
    VerifiedResponse,
    verify_directory,
)

from persistence.evidence import NoEvidenceError
from persistence.values import DirectoryFetch, SignedRequest, SignedResponse, Signer

from .wba import directory_response_of, library_origin, response_to_library, to_library


def directory_keys(signer: Signer) -> StaticKeyResolver:
    """The keys of the directory a signer's key came from, after the library verifies the
    kept fetch again; raises `NoEvidenceError` when no directory was kept."""
    fetch: DirectoryFetch | None = signer.directory
    if fetch is None:
        raise NoEvidenceError(str(signer.origin))
    origin = library_origin(signer.origin)
    directory = verify_directory(
        directory_response_of(fetch), origin, UnixSeconds(fetch.fetched_at)
    )
    return StaticKeyResolver({origin: directory.keys})


async def reverify_request(kept: SignedRequest, identity: ServerIdentity) -> VerifiedRequest:
    """Verifies a kept request again, as the party `identity` received it."""
    verifier = RequestVerifier(
        directory_keys(kept.signer), identity=identity, nonces=MemoryNonceStore()
    )
    return await verifier.verify(to_library(kept.request))


async def reverify_response(kept: SignedResponse) -> VerifiedResponse:
    """Verifies a kept response again, with its binding to the kept request."""
    verifier = ResponseVerifier(directory_keys(kept.signer))
    return await verifier.verify(
        response_to_library(kept.response), expected_origin=library_origin(kept.signer.origin)
    )
