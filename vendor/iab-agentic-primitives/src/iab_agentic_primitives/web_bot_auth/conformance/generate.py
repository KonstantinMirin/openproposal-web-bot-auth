"""Generates the conformance vectors deterministically, with the real signers.

Every key comes from a published seed, every nonce from a seeded byte stream,
and every timestamp from a fixed clock, so running the generator again writes
the same bytes. Ed25519 is deterministic. Every signature is made by
:class:`RequestSigner`, :class:`ResponseSigner`, or
:func:`publish_directory`; a vector that departs from the profile asks
for it with a :class:`~.signing.MessageDeparture` and is signed raw. Don't
edit the vector files by hand:
change this module and regenerate them::

    python -m iab_agentic_primitives.web_bot_auth.conformance --regenerate  # write
    python -m iab_agentic_primitives.web_bot_auth.conformance --check       # 1 on a difference

:data:`VECTORS_REGISTRY` names each vector's path and tier once, with its builder.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from functools import cache
from pathlib import Path
from typing import Literal, TypedDict, Unpack

from .._unchecked import signature_base
from ..directory import publish_directory
from ..errors import Refusal
from ..keys import Ed25519Key
from ..message import HTTPRequest, HTTPResponse
from ..rules import REQUEST, RESPONSE, SIGNATURE_TAG, signature_agent_component
from ..signer import RequestSigner, ResponseSigner, SignerConfig
from ..values import DIRECTORY_MEDIA_TYPE, OMIT, Origin, UnixSeconds, parse_authority
from . import VECTORS
from .fixtures import (
    BUYER,
    BUYER_KEYS,
    COMMIT_BODY,
    COMMIT_RESULT_BODY,
    COMMIT_URL,
    DOC_URL,
    JSON,
    KEY_SPECS,
    OTHER,
    OTHER_KEYS,
    SEED_PREFIX,
    SELLER,
    SELLER_AUTHORITY,
    SPEC,
    T0,
    at,
    key,
    nonce,
)
from .models import (
    AcceptSignature,
    DirectoryDoc,
    KeyEntry,
    KeysDocument,
    Passes,
    RefusalEntry,
    RefusalsDocument,
    Refuses,
    ReplayEntry,
    RequestDoc,
    ResponseDoc,
    SignatureParameters,
    Tier,
    Vector,
    VectorOperation,
    VerifyDirectory,
    VerifyRequest,
    VerifyResponse,
    dump,
    passing,
    refusing,
)
from .scenarios import build_scenarios
from .signing import MessageDeparture, RawSigner, sign_directory

#: Where regeneration writes by default: the package's own vector directory.
SOURCE = Path(str(VECTORS))


# ── keys.json and refusals.json ────────────────────────────────────────────


def keys_document() -> KeysDocument:
    entries = []
    for name, identity in KEY_SPECS:
        k = key(name)
        jwk = k.public_jwk()
        entry = KeyEntry(
            identity=Origin.parse(identity),
            seed_name=name,
            kty="OKP",
            crv="Ed25519",
            kid=k.thumbprint,
            x=str(jwk["x"]),
            use="sig",
            private_d=str(k.private_jwk()["d"]),
        )
        entries.append(entry)
    return KeysDocument(
        comment=(
            "Public test keys for the Web Bot Auth profile conformance vectors. The private "
            "seeds are published so that implementations can reproduce every signature. Each "
            f"seed is SHA-256 of the ASCII string '{SEED_PREFIX}<seed_name>'. Web Bot Auth "
            "section 6.8: test keys MUST NOT be used in production, and verifiers SHOULD reject "
            "them when detected. Each kid is the RFC 7638 JWK thumbprint (RFC 8037 Appendix A.3 "
            "for Ed25519). Each entry's identity is the origin whose key directory publishes "
            "the key."
        ),
        keys=tuple(entries),
    )


def refusals_document() -> RefusalsDocument:
    return RefusalsDocument(
        comment=(
            "The refusal vocabulary: every rule a verifier refuses with, and its status. "
            "Generated from the Refusal enum; a harness grades a refusal by its rule and status."
        ),
        refusals=tuple(RefusalEntry(rule=r.code, status=r.status) for r in Refusal),
    )


# ── signed messages ────────────────────────────────────────────────────────


def _buyer() -> Ed25519Key:
    return key("buyer-request")


def _commit_request() -> HTTPRequest:
    return HTTPRequest("POST", COMMIT_URL, JSON, COMMIT_BODY)


def _signed(
    origin: str,
    stream: str,
    departure: MessageDeparture | None = None,
    config: SignerConfig | None = None,
) -> HTTPRequest:
    """The buyer's commit, signed as ``origin`` with the nonce of ``stream``.

    With no ``departure``, :class:`RequestSigner` signs it. A departure signs
    it raw; the nonce of ``stream`` stands unless the departure sets one.
    """
    config = config or SignerConfig(_buyer(), Origin.parse(origin))
    if departure is None:
        return RequestSigner(config).sign(_commit_request(), now=T0, nonce=nonce(stream))
    parameters = SignatureParameters(nonce=nonce(stream)).merged(departure.parameters)
    raw = RawSigner(config, replace(departure, parameters=parameters))
    return raw.request(_commit_request(), T0)


def _bases(message: HTTPRequest | HTTPResponse, *signers: tuple[str, Ed25519Key]) -> dict[str, str]:
    return {label: signature_base(message, label, k).decode() for label, k in signers}


@cache
def _commit_001() -> HTTPRequest:
    """The buyer's signed commit, positive/001: also replayed and verified before others."""
    return _signed(BUYER, "001")


def _seller_response(departure: MessageDeparture | None = None) -> HTTPResponse:
    response = HTTPResponse(200, JSON, COMMIT_RESULT_BODY, _commit_001())
    config = SignerConfig(key("seller-response"), Origin.parse(SELLER))
    if departure is None:
        return ResponseSigner(config).sign(response, now=at(1))
    return RawSigner(config, departure).response(response, at(1))


def _directories(*pairs: tuple[str, str]) -> dict[str, Ed25519Key]:
    """Each origin's directory, published with its one key."""
    return {origin: key(name) for origin, name in pairs}


_BUYER_DIRECTORY = _directories((BUYER, "buyer-request"))
_PARAMETER_NAMES = ("created", "expires", "nonce", "keyid", "alg", "tag")


@dataclass(frozen=True, slots=True, kw_only=True)
class _Exchange:
    """What a vector sends a verifier: the message, and what the verifier is held to.

    ``authority`` is the verifier's own for a request, and the origin's host
    for a response or a directory.
    """

    kind: Literal["request", "response", "directory"]
    authority: str
    request: RequestDoc
    response: ResponseDoc | None = None
    directories: dict[str, Ed25519Key] = field(default_factory=dict)
    prior: tuple[RequestDoc, ...] = ()

    def operation(self, now: UnixSeconds) -> VectorOperation:
        """The one operation that grades the vector, its directories signed at ``now``."""
        signed = {o: sign_directory([k], o, now) for o, k in self.directories.items()}
        origin = Origin.parse(f"https://{self.authority}")
        if self.kind == "request":
            verifier = parse_authority(self.authority)
            return VerifyRequest(
                request=self.request,
                authority=verifier,
                directories=signed,
                now=now,
                prior=self.prior,
            )
        if self.response is None:
            raise ValueError(f"a {self.kind} vector has a response")
        if self.kind == "response":
            return VerifyResponse(
                request=self.request,
                response=self.response,
                directories=signed,
                now=now,
                expected_origin=origin,
            )
        r = self.response
        fetched = DirectoryDoc(status=r.status, headers=r.headers, body=r.body)
        return VerifyDirectory(origin=origin, response=fetched, now=now)


class _About(TypedDict, total=False):
    """What a vector says about its exchange."""

    name: str
    tier: Tier
    spec: str
    spec_reference: str
    reference_now: UnixSeconds
    expected: Passes | Refuses
    expected_signature_base: dict[str, str]
    replay_cache_entries: tuple[ReplayEntry, ...]
    comment: str


def _vector(exchange: _Exchange, **about: Unpack[_About]) -> Vector:
    """The vector of ``exchange``, graded at its ``reference_now``."""
    now = about["reference_now"]
    return Vector(
        name=about["name"],
        tier=about["tier"],
        spec=about["spec"],
        spec_reference=about["spec_reference"],
        reference_now=now,
        operation=exchange.operation(now),
        replay_cache_entries=about.get("replay_cache_entries", ()),
        expected_signature_base=about.get("expected_signature_base"),
        expected=about["expected"],
        comment=about["comment"],
    )


def _accept(*, nonce: bool = False) -> AcceptSignature:
    return AcceptSignature(
        label="sig1",
        components="(" + " ".join(map(str, REQUEST.components("sig1", has_body=True))) + ")",
        parameters=_PARAMETER_NAMES,
        tag=SIGNATURE_TAG,
        nonce="verifier-chosen" if nonce else None,
    )


def _ref(heading: str) -> str:
    return f"{DOC_URL}#{heading}"


# ── the vectors, one builder each ──────────────────────────────────────────


def _positive_001(tier: Tier) -> Vector:
    request = _commit_001()
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_BUYER_DIRECTORY,
        ),
        name=f"Single signer: the buyer agent at {BUYER} commits to proposal prop_7",
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=passing(BUYER),
        comment=(
            f"The Signature-Agent member sig1 names the key directory URL {BUYER_KEYS}, so the "
            "verifier fetches it, selects the key whose kid equals keyid, and attributes the "
            f"request to the origin {BUYER}. Ed25519 is deterministic, so an implementation "
            "signing expected_signature_base with the published seed reproduces the Signature "
            "value byte for byte."
        ),
    )


def _positive_002(tier: Tier) -> Vector:
    buyer = _buyer()
    origin = Origin.parse(BUYER)
    authority = origin.authority
    published = publish_directory(origin, [buyer], now=at(-600))
    request = HTTPRequest("GET", BUYER_KEYS, {"Host": authority, "Accept": DIRECTORY_MEDIA_TYPE})
    signed = HTTPResponse(
        published.status, published.headers, published.body, HTTPRequest("GET", BUYER_KEYS)
    )
    return _vector(
        _Exchange(
            kind="directory",
            authority=authority,
            request=RequestDoc.of(request),
            response=ResponseDoc.of(signed),
        ),
        name=f"Signed key directory response for {BUYER}, one signature per key",
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(signed, ("key1", buyer)),
        expected=passing(),
        comment=(
            "Web Bot Auth Appendix B.1: the directory server signs the response once per key, "
            'covering "@authority";req and content-digest, with created, expires, the key\'s '
            "thumbprint as keyid, and tag http-message-signatures-directory. The verifier "
            "validates the signature with the key the directory itself provides and validates "
            "Content-Digest against the body. Covering the request authority stops the key set "
            "from being served again from another domain."
        ),
    )


def _response_vector(tier: Tier, response: HTTPResponse, expected: Passes | Refuses) -> Vector:
    return _vector(
        _Exchange(
            kind="response",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(response.request),
            response=ResponseDoc.of(response),
            directories=_directories((SELLER, "seller-response")),
        ),
        name=(
            f"The seller at {SELLER} answers the commit with a CommitResult, bound to the signed "
            "request"
        ),
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(response, ("sig1", key("seller-response"))),
        expected=expected,
        comment=(
            'The response covers "signature";req;key="sig1", the request\'s own signature, so '
            "it answers that exact request (RFC 9421 section 2.4). It carries no nonce: the "
            "binding gives freshness."
        ),
    )


def _positive_003(tier: Tier) -> Vector:
    return _response_vector(tier, _seller_response(), passing(SELLER))


def _positive_004(tier: Tier) -> Vector:
    origin_form = MessageDeparture(signature_agent=f'sig1="{BUYER}"')
    request = _signed(BUYER, "001-origin", origin_form)
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_BUYER_DIRECTORY,
        ),
        name=f"Draft -00 form: Signature-Agent names the bare origin {BUYER}",
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=passing(BUYER),
        comment=(
            f"A draft -00 signer names its origin. The verifier constructs {BUYER_KEYS}, the "
            "same URL a key URL member names, fetches it, and attributes the request to the same "
            "origin."
        ),
    )


def _negative_001(tier: Tier) -> Vector:
    without_nonce = MessageDeparture(parameters=SignatureParameters(nonce=None))
    request = _signed(BUYER, "none", without_nonce)
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_BUYER_DIRECTORY,
        ),
        name="Signature-Input omits the nonce parameter",
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("verification-procedure"),
        reference_now=at(10),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=refusing(
            Refusal.NONCE_MISSING,
            accept_signature=_accept(),
            rationale=(
                "The profile requires an RFC 9421 nonce on every signed request. Without one the "
                "verifier cannot detect replay."
            ),
        ),
        comment=(
            "The signature is cryptographically valid over its covered components, so a "
            "verifier that does not enforce the nonce requirement accepts it."
        ),
    )


def _negative_002(tier: Tier) -> Vector:
    request = _commit_001()
    first_nonce = nonce("001")
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_BUYER_DIRECTORY,
            prior=(RequestDoc.of(request),),
        ),
        name=(
            "Second submission of a request whose (identity, nonce) pair the verifier has "
            "already accepted"
        ),
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("verification-procedure"),
        reference_now=at(15),
        replay_cache_entries=(
            ReplayEntry(identity=Origin.parse(BUYER), nonce=first_nonce, ttl_seconds=360),
        ),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=refusing(
            Refusal.NONCE_REPLAYED,
            accept_signature=_accept(nonce=True),
            rationale=(
                "The verifier MUST reject a nonce it has already seen for the same identity "
                "within the signature's lifetime."
            ),
        ),
        comment=(
            "The request is byte-identical to positive/001-single-signer-request.json. A "
            "black-box runner verifies prior.verified_requests first, then this request; a "
            "white-box harness injects prior.replay_cache_entries instead."
        ),
    )


def _negative_003(tier: Tier) -> Vector:
    uncovered = tuple(
        c
        for c in REQUEST.components("sig1", has_body=True)
        if c != signature_agent_component("sig1")
    )
    request = _signed(BUYER, "003", MessageDeparture(components=uncovered))
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_BUYER_DIRECTORY,
        ),
        name="Signature-Agent header present, but the sig1 member is not a covered component",
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=refusing(
            Refusal.SIGNATURE_AGENT_NOT_COVERED,
            accept_signature=_accept(),
            rationale=(
                "Web Bot Auth section 5.2.1: the Signature-Agent member keyed to the signature "
                "label MUST be signed as a component. An uncovered member is an unverified claim "
                "(section 4.1)."
            ),
        ),
        comment=(
            "The signature verifies over the components it does cover, so a verifier that reads "
            "the identity from the uncovered header and skips the coverage check attributes the "
            "request to an origin nobody signed for."
        ),
    )


@cache
def _signed_for_other() -> HTTPRequest:
    """The buyer's key signs while Signature-Agent names the other origin."""
    return _signed(OTHER, "004")


_KEY_LOOKUP = (
    "Key lookup is keyed on the (origin, keyid) pair, never on keyid alone (Web Bot Auth "
    "section 5.4)."
)


def _negative_004(tier: Tier) -> Vector:
    request = _signed_for_other()
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_directories((OTHER, "other-request"), (BUYER, "buyer-request")),
        ),
        name=f"Signature-Agent names {OTHER}, but the signing key is published only by {BUYER}",
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=refusing(
            Refusal.KEY_NOT_FOUND,
            accept_signature=_accept(),
            rationale=f"{_KEY_LOOKUP} The directory at the named origin holds no key with this "
            "thumbprint.",
        ),
        comment=(
            "The signature is valid under the buyer's key, and directories lists that key under "
            "its own origin so a harness can show the trap: a verifier that indexes keys by "
            f"thumbprint alone finds the key and attributes the request to {OTHER}, an origin "
            "that never published it."
        ),
    )


def _negative_005(tier: Tier) -> Vector:
    request = _commit_001()
    malformed = dict(request.headers.items())
    malformed["Signature-Agent"] = f'sig1="{BUYER_KEYS}'
    malformed["Signature"] = "sig1=:" + "A" * 86 + "==:"
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(
                HTTPRequest(request.method, request.url, malformed, request.body)
            ),
            directories=_BUYER_DIRECTORY,
        ),
        name=(
            "Signature-Agent is not a parseable Structured Field Dictionary (unterminated string)"
        ),
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("verification-procedure"),
        reference_now=at(10),
        expected=refusing(
            Refusal.PARSE,
            rationale=(
                "Web Bot Auth section 5.4: a verifier that fails to parse Signature, "
                "Signature-Input, or Signature-Agent answers 400 Bad Request."
            ),
        ),
        comment=(
            "Signature is a 64-zero-byte placeholder: parsing fails before any key is resolved "
            "or any signature is checked, so a verifier that reaches cryptographic verification "
            "has skipped the parse step."
        ),
    )


def _negative_006(tier: Tier) -> Vector:
    both = MessageDeparture(signature_agent=f'sig1="{BUYER_KEYS}", sig2="{OTHER_KEYS}"')
    first = _signed(BUYER, "001", both)
    other = key("other-request")
    beside = MessageDeparture(
        parameters=SignatureParameters(nonce=nonce("006")),
        signature_agent=OMIT,
        keep_signatures=True,
    )
    second = RawSigner(SignerConfig(other, Origin.parse(OTHER), label="sig2"), beside).request(
        first, T0
    )
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(second),
            directories=_directories((BUYER, "buyer-request"), (OTHER, "other-request")),
        ),
        name=(
            "Two web-bot-auth signatures on one request: positive/001 plus a second valid "
            f"signature from {OTHER}"
        ),
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("verification-procedure"),
        reference_now=at(10),
        expected_signature_base=_bases(second, ("sig1", _buyer()), ("sig2", other)),
        expected=refusing(
            Refusal.MULTIPLE_SIGNATURES,
            accept_signature=_accept(),
            rationale=(
                "The profile takes exactly one web-bot-auth signature and one Signature-Agent "
                "member per request. Web Bot Auth section 5.2.2 permits more than one "
                "signature; the profile does not accept one."
            ),
        ),
        comment=(
            "The sig1 label is byte-identical to positive/001, and sig2 is a second valid "
            "signature over the same request from another identity. A verifier that accepts "
            "when each label verifies skips the count check."
        ),
    )


def _negative_007(tier: Tier) -> Vector:
    unbound = MessageDeparture(components=RESPONSE.components("sig1", has_body=True))
    expected = refusing(
        Refusal.RESPONSE_NOT_BOUND,
        rationale=(
            'A response to a request that carried a web-bot-auth signature covers "signature";'
            "req;key=<request label>. Without it, the response could answer any request."
        ),
    )
    vector = _response_vector(tier, _seller_response(unbound), expected)
    return replace(
        vector,
        name="The seller's response to a signed request, not bound to that request",
        comment=(
            "The response signature is valid over its covered components, so a verifier that "
            "does not check the binding accepts a response that could have been captured from "
            "another exchange."
        ),
    )


def _negative_008(tier: Tier) -> Vector:
    request = _signed_for_other()
    return _vector(
        _Exchange(
            kind="request",
            authority=SELLER_AUTHORITY,
            request=RequestDoc.of(request),
            directories=_directories((OTHER, "other-request"), (BUYER, "buyer-request")),
            prior=(RequestDoc.of(_commit_001()),),
        ),
        name=(
            f"negative/004 after a verified request from {BUYER}: the warm cache still keys on "
            "(origin, keyid)"
        ),
        tier=tier,
        spec=SPEC,
        spec_reference=_ref("profile-rules"),
        reference_now=at(10),
        expected_signature_base=_bases(request, ("sig1", _buyer())),
        expected=refusing(
            Refusal.KEY_NOT_FOUND,
            accept_signature=_accept(),
            rationale=f"{_KEY_LOOKUP} It holds with or without a cached directory.",
        ),
        comment=(
            "The verifier first verifies positive/001-single-signer-request.json, so the "
            f"directory of {BUYER} is cached when this request arrives. A verifier whose cache "
            "answers any lookup from any cached directory finds the buyer's key there and "
            f"attributes the request to {OTHER}."
        ),
    )


@dataclass(frozen=True)
class VectorEntry:
    """One committed vector: its path under the vector directory, its tier, and its builder."""

    path: str
    tier: Tier
    build: Callable[[Tier], Vector]


#: Every vector, its path and tier stated once. ``tier`` is what the bare
#: reference libraries answer: "wba" when they already give the expected
#: outcome, "profile" when only the profile's rules do.
VECTORS_REGISTRY: tuple[VectorEntry, ...] = (
    VectorEntry("positive/001-single-signer-request.json", "wba", _positive_001),
    VectorEntry("positive/002-signed-directory-response.json", "wba", _positive_002),
    VectorEntry("positive/003-signed-response.json", "wba", _positive_003),
    VectorEntry("positive/004-origin-form-request.json", "wba", _positive_004),
    VectorEntry("negative/001-missing-nonce.json", "profile", _negative_001),
    VectorEntry("negative/002-replayed-nonce.json", "profile", _negative_002),
    VectorEntry("negative/003-signature-agent-not-covered.json", "wba", _negative_003),
    VectorEntry("negative/004-key-not-in-named-directory.json", "wba", _negative_004),
    VectorEntry("negative/005-malformed-signature-agent.json", "wba", _negative_005),
    VectorEntry("negative/006-two-signatures.json", "wba", _negative_006),
    VectorEntry("negative/007-response-not-bound.json", "profile", _negative_007),
    VectorEntry("negative/008-key-not-in-named-directory-warm-cache.json", "wba", _negative_008),
)


# ── writing ────────────────────────────────────────────────────────────────


def documents() -> dict[str, object]:
    """Every generated file, keyed by its path under the vector directory."""
    return {
        "keys.json": keys_document(),
        "refusals.json": refusals_document(),
        "scenarios.json": build_scenarios(),
        **{entry.path: entry.build(entry.tier) for entry in VECTORS_REGISTRY},
    }


#: A field line as indent=2 spreads it: ``[``, the name, the value, and ``]``.
_FIELD_LINE = re.compile(r'\[\n\s+("(?:[^"\\]|\\.)*"),\n\s+("(?:[^"\\]|\\.)*")\n\s+\]')


def render(document: object) -> str:
    """The JSON text of a generated file, with each field line on one line."""
    text = json.dumps(dump(document), indent=2, ensure_ascii=False)
    return _FIELD_LINE.sub(r"[\1, \2]", text) + "\n"


#: The files the generator owns at the top of a vector directory.
_TOP = ("keys.json", "refusals.json", "scenarios.json")


def _committed(directory: Path) -> set[str]:
    """The generator's own files under ``directory``: the three top-level documents and
    the vectors in ``positive/`` and ``negative/``. Nothing else is ever touched."""
    vectors = (p for group in ("positive", "negative") for p in (directory / group).glob("*.json"))
    found = {p.relative_to(directory).as_posix() for p in vectors}
    return found | {name for name in _TOP if (directory / name).exists()}


def _source_checkout(directory: Path) -> bool:
    """True when ``directory`` is in a source tree, not an installed package."""
    return any((parent / "pyproject.toml").exists() for parent in directory.resolve().parents)


def _checked_target(directory: Path) -> None:
    """Refuses a directory that isn't a vector directory, and an installed package's."""
    if directory.exists() and any(directory.iterdir()) and not (directory / "keys.json").exists():
        raise ValueError(f"{directory} is not a vector directory: it has files and no keys.json")
    if directory.resolve() == SOURCE.resolve() and not _source_checkout(directory):
        raise ValueError(f"{directory} is an installed package; regenerate in a source checkout")


def write(directory: Path = SOURCE) -> list[Path]:
    """Writes every generated file under ``directory`` and deletes its own stale vectors.

    Only the generator's layout is written or deleted; any other file there is
    left alone. Raises ``ValueError`` for a directory that isn't a vector
    directory, and for the package's own directory outside a source checkout.
    """
    _checked_target(directory)
    generated = documents()
    for stale in sorted(_committed(directory) - set(generated)):
        (directory / stale).unlink()
    written = []
    for relative, document in generated.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(document))
        written.append(path)
    return written


@dataclass(frozen=True, slots=True)
class Drift:
    """How a vector directory departs from the generator, file by file."""

    differs: tuple[str, ...]
    missing: tuple[str, ...]
    unknown: tuple[str, ...]

    def __bool__(self) -> bool:
        return bool(self.differs or self.missing or self.unknown)

    def lines(self) -> list[str]:
        """One line per file: what is wrong with it, and its path."""
        return [
            *(f"differs from the generator: {name}" for name in self.differs),
            *(f"missing: {name}" for name in self.missing),
            *(f"not generated: {name}" for name in self.unknown),
        ]


def check(directory: Path = SOURCE) -> Drift:
    """The files under ``directory`` that differ from the generator, are missing, or are its
    own kind of file but not generated."""
    generated = documents()
    missing = tuple(r for r in generated if not (directory / r).exists())
    differs = tuple(
        r
        for r, document in generated.items()
        if r not in missing and (directory / r).read_text() != render(document)
    )
    unknown = tuple(sorted(_committed(directory) - set(generated)))
    return Drift(differs, missing, unknown)


__all__ = [
    "SOURCE",
    "VECTORS_REGISTRY",
    "Drift",
    "VectorEntry",
    "check",
    "documents",
    "keys_document",
    "refusals_document",
    "render",
    "write",
]
