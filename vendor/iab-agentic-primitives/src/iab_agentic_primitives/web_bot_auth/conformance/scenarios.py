"""The failure scenarios of ``scenarios.json``, as data for a harness to sign at run time.

Each scenario names its expected outcome; a refusal names its rule. A
scenario states only what departs from the baseline: ``base`` defaults to
``post`` and ``tier`` to ``wba``.
"""

from __future__ import annotations

from ..directory import DEFAULT_PUBLISH
from ..errors import Refusal
from ..message import HeaderLines
from ..rules import REQUEST, RESPONSE, SIGNATURE_TAG
from ..values import DIRECTORY_PATH, Origin, RequestAuthority
from .fixtures import (
    BUYER,
    BUYER_KEYS,
    COMMIT_BODY,
    COMMIT_RESULT_BODY,
    COMMIT_URL,
    DOC_URL,
    OTHER_KEYS,
    SELLER,
    SELLER_AUTHORITY,
    SELLER_KEYS,
    SPEC,
    key,
    p256_public_jwk,
)
from .models import (
    DirectoryEdits,
    DirectoryScenario,
    ExtraSignature,
    NonceSpec,
    Party,
    RequestDoc,
    RequestEdits,
    RequestScenario,
    ResponseDoc,
    ResponseEdits,
    ResponseScenario,
    ScenariosDocument,
    SignatureParameters,
    passing,
    refusing,
)
from .signing import specs

_BUYER = passing(BUYER)
_SELLER = passing(SELLER)
_DIRECTORY = passing()
_no = refusing

#: The profile's components, from the rules, with ``{label}`` and ``{request_label}``
#: for the labels the harness signs with.
_POST = specs(REQUEST.components("{label}", has_body=True))
_GET = specs(REQUEST.components("{label}", has_body=False))
_BOUND = specs(RESPONSE.components("{label}", has_body=True, request_label="{request_label}"))
_UNBOUND = specs(RESPONSE.components("{label}", has_body=True))
#: The post components without the Signature-Agent member, for the scenarios that change it.
_POST_BODY = _POST[:-1]
_VALUE_RULE = (
    f"Profile: the value is exactly https://<host>{DIRECTORY_PATH} or https://<host>, "
    "compared without normalizing"
)
_NO_PARAMETERS = (
    "WBA -01 section 5.2.1: members MUST NOT carry parameters, and a verifier MUST ignore "
    "one that does"
)


def _value_scenario(
    sid: str, name: str, value: str, basis: str, directories: tuple[str, ...] = ()
) -> RequestScenario:
    """A ``Signature-Agent`` value the profile refuses."""
    return RequestScenario(
        id=sid,
        name=name,
        signature_agent=f'sig1="{value}"',
        directories={directories[0]: (str(key("buyer-request").thumbprint),)}
        if directories
        else None,
        expected=_no(Refusal.SIGNATURE_AGENT_VALUE),
        tier="profile",
        basis=f"{_VALUE_RULE}; {basis}",
    )


def _value_scenarios() -> tuple[RequestScenario, ...]:
    port = f"{BUYER}:8443"
    return (
        _value_scenario(
            "R17",
            "Path other than the well-known path",
            f"{BUYER}/jwks.json",
            "the library does not check it",
        ),
        _value_scenario(
            "R17a", "Well-known path with a trailing /", f"{BUYER_KEYS}/", "no trailing /"
        ),
        _value_scenario(
            "R17b",
            "Well-known path in another case",
            f"{BUYER}/.well-known/HTTP-Message-Signatures-Directory",
            "the path is compared as a string",
        ),
        _value_scenario("R17c", "Origin with a trailing /", f"{BUYER}/", "no trailing /"),
        _value_scenario(
            "R17d",
            "Uppercase host",
            f"https://BUYER.example.com{DIRECTORY_PATH}",
            "a lowercase host",
        ),
        _value_scenario("R17e", "Explicit :443", f"{BUYER}:443{DIRECTORY_PATH}", "no port"),
        _value_scenario("R17f", "Other port", f"{port}{DIRECTORY_PATH}", "no port", (port,)),
        _value_scenario("R17g", "Query", f"{BUYER_KEYS}?v=1", "no query"),
        _value_scenario("R17h", "Fragment", f"{BUYER_KEYS}#k", "no fragment"),
        _value_scenario(
            "R17i", "Userinfo", f"https://agent@buyer.example.com{DIRECTORY_PATH}", "no userinfo"
        ),
        _value_scenario("R17j", "Origin with a query", f"{BUYER}?v=1", "no query"),
    )


def _window_and_nonce_scenarios() -> tuple[RequestScenario, ...]:
    return (
        RequestScenario(
            id="R03",
            name="Expired",
            parameters=SignatureParameters(created=-400, expires=-100),
            expected=_no(Refusal.EXPIRED),
            basis="RFC 9421 section 3.2.1",
        ),
        RequestScenario(
            id="R04",
            name="created 120 seconds in the future",
            parameters=SignatureParameters(created=120, expires=400),
            expected=_no(Refusal.CREATED_IN_FUTURE),
            basis="Profile: 60 seconds of clock skew",
        ),
        RequestScenario(
            id="R05",
            name="created 30 seconds in the future",
            parameters=SignatureParameters(created=30, expires=300),
            expected=_BUYER,
            tier="profile",
            basis="Profile: 60 seconds of clock skew; the library allows none by default",
        ),
        RequestScenario(
            id="R06",
            name="Lifetime of 3600 seconds",
            parameters=SignatureParameters(created=-5, expires=3595),
            expected=_no(Refusal.LIFETIME),
            tier="profile",
            basis="Profile: expires at most 300 seconds after created",
        ),
        RequestScenario(
            id="R07",
            name="Nonce of 32 bytes",
            parameters=SignatureParameters(nonce=NonceSpec(bytes=32, encoding="base64url")),
            expected=_no(Refusal.NONCE_INVALID),
            basis="Profile: 64-byte nonce; validateNonce",
        ),
        RequestScenario(
            id="R08",
            name="Nonce in canonical padded base64",
            parameters=SignatureParameters(nonce=NonceSpec(bytes=64, encoding="base64")),
            expected=_BUYER,
            basis="Profile: unpadded base64url or canonical padded base64",
        ),
        RequestScenario(
            id="R09",
            name="Nonce in padded base64url",
            parameters=SignatureParameters(nonce=NonceSpec(bytes=64, encoding="base64url-padded")),
            expected=_no(Refusal.NONCE_INVALID),
            basis="Profile: unpadded base64url or canonical padded base64",
        ),
        RequestScenario(
            id="R10",
            name="No alg parameter",
            parameters=SignatureParameters(alg=None),
            expected=_no(Refusal.ALG),
            basis="Profile: alg required",
        ),
        RequestScenario(
            id="R11",
            name="alg other than ed25519",
            parameters=SignatureParameters(alg="ecdsa-p256-sha256"),
            expected=_no(Refusal.ALG),
            basis="Profile: alg is ed25519 and matches the key; RFC 9421 section 3.2",
        ),
    )


def _component_scenarios() -> tuple[RequestScenario, ...]:
    return (
        RequestScenario(
            id="R12",
            name="GET covering only @authority and the Signature-Agent member",
            base="get",
            components=("@authority", "signature-agent;key=sig1"),
            expected=_no(Refusal.COMPONENTS),
            tier="profile",
            basis=(
                "Profile: cover @method, @target-uri, and @authority; WBA section 5.2 needs one "
                "of @authority or @target-uri"
            ),
        ),
        RequestScenario(
            id="R13",
            name="Body without content-digest covered",
            components=(
                "@method",
                "@target-uri",
                "@authority",
                "content-type",
                "signature-agent;key=sig1",
            ),
            expected=_no(Refusal.COMPONENTS),
            tier="profile",
            basis=(
                "Profile: a request with a body covers content-type and content-digest; WBA "
                "section 5.2"
            ),
        ),
        RequestScenario(
            id="R13b",
            name="Body without content-type covered",
            components=(
                "@method",
                "@target-uri",
                "@authority",
                "content-digest",
                "signature-agent;key=sig1",
            ),
            expected=_no(Refusal.COMPONENTS),
            tier="profile",
            basis="Profile: a request with a body covers content-type and content-digest",
        ),
        RequestScenario(
            id="R14",
            name="tag other than web-bot-auth",
            parameters=SignatureParameters(tag="other-profile/v1"),
            expected=_no(Refusal.SIGNATURE_MISSING),
            basis="WBA section 5.2: tag MUST be web-bot-auth",
        ),
        RequestScenario(
            id="R23",
            name="Components in another order",
            components=(
                "signature-agent;key=sig1",
                "@authority",
                "content-digest",
                "@target-uri",
                "content-type",
                "@method",
            ),
            expected=_BUYER,
            basis="RFC 9421: the order is the signer's",
        ),
        RequestScenario(
            id="R24",
            name="No nonce",
            parameters=SignatureParameters(nonce=None),
            expected=_no(Refusal.NONCE_MISSING),
            tier="profile",
            basis="Profile: a nonce on every signed request; WBA leaves it to deployment policy",
        ),
        RequestScenario(
            id="R25",
            name="GET with the profile's components",
            base="get",
            expected=_BUYER,
            basis="Profile rules; a request without a body covers no content-digest",
        ),
    )


def _agent_scenarios() -> tuple[RequestScenario, ...]:
    http: dict[str, tuple[str, ...]] = {
        "http://buyer.example.com": (str(key("buyer-request").thumbprint),)
    }
    return (
        RequestScenario(
            id="R15",
            name="Bare-string Signature-Agent",
            signature_agent=f'"{BUYER_KEYS}"',
            components=(*_POST_BODY, "signature-agent"),
            expected=_no(Refusal.PARSE),
            tier="profile",
            basis=(
                "Profile: dictionary form only, so the field does not parse; WBA section 5.2.1 "
                "lets a verifier accept the bare string"
            ),
        ),
        RequestScenario(
            id="R16",
            name="http:// key URL",
            signature_agent=f'sig1="http://buyer.example.com{DIRECTORY_PATH}"',
            directories=http,
            expected=_no(Refusal.SIGNATURE_AGENT_VALUE),
            tier="profile",
            basis=(
                "WBA section 5.2.1: the scheme MUST be https; the library accepts http "
                "(cloudflare/web-bot-auth#162)"
            ),
        ),
        RequestScenario(
            id="R16b",
            name="http:// origin",
            signature_agent='sig1="http://buyer.example.com"',
            directories=http,
            expected=_no(Refusal.SIGNATURE_AGENT_VALUE),
            tier="profile",
            basis="WBA section 5.2.1: the scheme MUST be https",
        ),
        *_value_scenarios(),
        RequestScenario(
            id="R18",
            name="Member with type=jwks_uri",
            signature_agent=f'sig1="{BUYER}/jwks.json";type=jwks_uri',
            expected=_no(Refusal.SIGNATURE_AGENT_PARAMETERS),
            tier="profile",
            basis="WBA -01 section 5.2.1: a verifier MUST ignore a member that carries parameters",
        ),
        RequestScenario(
            id="R18c",
            name="Origin member with type=directory as a Token",
            signature_agent=f'sig1="{BUYER}";type=directory',
            expected=_no(Refusal.SIGNATURE_AGENT_PARAMETERS),
            tier="profile",
            basis=_NO_PARAMETERS,
        ),
        RequestScenario(
            id="R18d",
            name='Key URL member with type="directory" as a String',
            signature_agent=f'sig1="{BUYER_KEYS}";type="directory"',
            expected=_no(Refusal.SIGNATURE_AGENT_PARAMETERS),
            tier="profile",
            basis=_NO_PARAMETERS,
        ),
        RequestScenario(
            id="R18e",
            name="Bare origin, the draft -00 form",
            signature_agent=f'sig1="{BUYER}"',
            expected=_BUYER,
            basis=(
                "WBA -00 section 5.5: a directory member is an origin; the verifier fetches the "
                "same well-known URL"
            ),
        ),
        RequestScenario(
            id="R19",
            name="Signature-Agent member keyed differently from the label",
            signature_agent=f'agent1="{BUYER_KEYS}"',
            components=(*_POST_BODY, "signature-agent;key=agent1"),
            expected=_no(Refusal.SIGNATURE_AGENT_MISSING),
            tier="profile",
            basis=(
                "WBA section 5.2.1: the member keyed to the label; the library does not check it"
            ),
        ),
        RequestScenario(
            id="R21",
            name="Two Signature-Agent members, one signature",
            signature_agent=f'sig1="{BUYER_KEYS}", sig2="{OTHER_KEYS}"',
            expected=_no(Refusal.MULTIPLE_SIGNATURE_AGENTS),
            tier="profile",
            basis="Profile: exactly one Signature-Agent member",
        ),
        RequestScenario(
            id="R22",
            name="Label other than sig1",
            label="wba",
            expected=_BUYER,
            basis="RFC 9421: the signer chooses the label",
        ),
    )


def _request_scenarios() -> tuple[RequestScenario, ...]:
    cdn = ExtraSignature(
        label="cdn",
        kid=key("other-request").thumbprint,
        components=("@method", "@authority"),
        parameters=SignatureParameters(created=-5, expires=295, nonce=None, tag="cdn-edge"),
    )
    return (
        RequestScenario(id="R00", name="Baseline", expected=_BUYER, basis="Profile rules"),
        RequestScenario(
            id="R01",
            name="Body changed after signing",
            after_signing=RequestEdits(append_to_body="\n"),
            expected=_no(Refusal.CONTENT_DIGEST),
            tier="profile",
            basis="Content-Digest matches the body: RFC 9530; WBA section 5.2",
        ),
        RequestScenario(
            id="R02",
            name="Covered header changed after signing",
            after_signing=RequestEdits(headers={"content-type": "text/plain"}),
            expected=_no(Refusal.SIGNATURE_INVALID),
            basis="RFC 9421 section 3.2",
        ),
        *_window_and_nonce_scenarios(),
        *_component_scenarios(),
        *_agent_scenarios(),
        RequestScenario(
            id="R20",
            name="Second signature with tag cdn-edge",
            extra_signature=cdn,
            expected=_BUYER,
            tier="profile",
            basis=(
                "Profile: Signature-Input members with other tags are not read; the library "
                "requires a label when a request carries two signatures"
            ),
        ),
        RequestScenario(
            id="R20b",
            name="Second member with tag cdn-edge whose Signature value is a token",
            after_signing=RequestEdits(
                append_members={
                    "signature-input": 'cdn=("@method" "@authority");tag="cdn-edge"',
                    "signature": "cdn=edge-token",
                }
            ),
            expected=_no(Refusal.PARSE),
            basis=(
                "RFC 9421 section 4.2: every Signature member value is a Byte Sequence, so the "
                "field is malformed whatever the member's tag"
            ),
        ),
        RequestScenario(
            id="R26",
            name="Signed for seller.example.com, verified by seller-b.example.com",
            authority=RequestAuthority("seller-b.example.com"),
            expected=_no(Refusal.AUTHORITY),
            tier="profile",
            basis=(
                "OpenProposal § 2.8.4 step 5: the signed @authority is the verifier's own "
                "configured authority, never the Host it was sent"
            ),
        ),
    )


def _directory_scenarios() -> tuple[DirectoryScenario, ...]:
    window = Refusal.DIRECTORY_WINDOW
    return (
        DirectoryScenario(id="D00", name="Baseline", expected=_DIRECTORY, basis="WBA Appendix B.1"),
        DirectoryScenario(
            id="D01",
            name="Signed for another authority",
            authority=RequestAuthority("other.example.com"),
            expected=_no(Refusal.DIRECTORY_SIGNATURE),
            basis='WBA Appendix B.1: covers "@authority";req',
        ),
        DirectoryScenario(
            id="D02",
            name="Body changed after signing",
            after_signing=DirectoryEdits(append_to_body="\n"),
            expected=_no(Refusal.DIRECTORY_CONTENT_DIGEST),
            tier="profile",
            basis=(
                "WBA Appendix B.1: the verifier MUST validate Content-Digest; the library does "
                "not compare it with the body"
            ),
        ),
        DirectoryScenario(
            id="D03",
            name="Unsigned",
            keys=(),
            unsigned_keys=({k: str(v) for k, v in key("buyer-request").public_jwk().items()},),
            expected=_no(Refusal.DIRECTORY_ONE_SIGNATURE_PER_KEY),
            basis="Profile: every Ed25519 key signs (Appendix B.1 recommends it)",
        ),
        DirectoryScenario(
            id="D04",
            name="Signature created in the future",
            parameters=SignatureParameters(created=3600, expires=90000),
            expected=_no(window),
            basis=(
                "WBA Appendix B.1: reject a future created; the profile allows the same 60 s "
                "skew as for requests"
            ),
        ),
        DirectoryScenario(
            id="D05",
            name='Covers "@authority";req only',
            components=("@authority;req",),
            expected=_no(Refusal.DIRECTORY_COMPONENTS),
            tier="profile",
            basis="WBA Appendix B.1: covers content-digest",
        ),
        DirectoryScenario(
            id="D06",
            name="Expired signature",
            parameters=SignatureParameters(created=-7200, expires=-3600),
            expected=_no(window),
            basis="RFC 9421 section 3.2.1",
        ),
        DirectoryScenario(
            id="D07",
            name="Extra P-256 key that does not sign",
            unsigned_keys=(p256_public_jwk(),),
            expected=_DIRECTORY,
            basis="Profile: ignore keys the profile does not use (RFC 7517 section 5)",
        ),
        DirectoryScenario(
            id="D08",
            name="Media type application/json",
            content_type="application/json",
            expected=_no(Refusal.DIRECTORY_MEDIA_TYPE),
            tier="profile",
            basis=(
                "WBA section 5.5.1: the well-known directory MUST be served with "
                "application/http-message-signatures-directory+json"
            ),
        ),
        DirectoryScenario(
            id="D09",
            name="Signature expired one second ago",
            parameters=SignatureParameters(created=-600, expires=-1),
            expected=_no(window),
            basis=(
                "Profile: the clock skew applies to created only; a directory verifies until its "
                "expires"
            ),
        ),
        DirectoryScenario(
            id="D10",
            name="Signature that expires now",
            parameters=SignatureParameters(created=-600, expires=0),
            expected=_DIRECTORY,
            basis="Profile: a directory verifies until its expires, that second included",
        ),
    )


def _response_scenarios() -> tuple[ResponseScenario, ...]:
    return (
        ResponseScenario(
            id="P00",
            name="Baseline, bound to the signed request",
            expected=_SELLER,
            basis="OpenProposal 3.0 § 2.8: response components; RFC 9421 section 2.4",
        ),
        ResponseScenario(
            id="P01",
            name="Body changed after signing",
            after_signing=ResponseEdits(append_to_body="\n"),
            expected=_no(Refusal.CONTENT_DIGEST),
            tier="profile",
            basis="Content-Digest matches the body: RFC 9530",
        ),
        ResponseScenario(
            id="P02",
            name="Status changed after signing",
            after_signing=ResponseEdits(status=201),
            expected=_no(Refusal.SIGNATURE_INVALID),
            basis="RFC 9421 section 2.2.9: @status is covered",
        ),
        ResponseScenario(
            id="P03",
            name="Signed request, response not bound to it",
            components=_UNBOUND,
            expected=_no(Refusal.RESPONSE_NOT_BOUND),
            tier="profile",
            basis=(
                'Profile: a response to a signed request covers "signature";req;key=<request label>'
            ),
        ),
        ResponseScenario(
            id="P04",
            name="Bound to another request",
            after_signing=ResponseEdits(request_headers={"Signature": "sig1=:" + "A" * 86 + "==:"}),
            expected=_no(Refusal.SIGNATURE_INVALID),
            basis="RFC 9421 section 2.4: the request's signature is covered",
        ),
        ResponseScenario(
            id="P05",
            name="@status not covered",
            components=_BOUND[1:],
            expected=_no(Refusal.COMPONENTS),
            tier="profile",
            basis="Profile: response components",
        ),
        ResponseScenario(
            id="P06",
            name="Lifetime of 3600 seconds",
            parameters=SignatureParameters(created=-5, expires=3595),
            expected=_no(Refusal.LIFETIME),
            tier="profile",
            basis="Profile: expires at most 300 seconds after created",
        ),
        ResponseScenario(
            id="P07",
            name="Unsigned request, response without a binding",
            request="unbound",
            expected=_SELLER,
            basis="Profile: the binding applies when the request carried a signature",
        ),
        ResponseScenario(
            id="P08",
            name="Response signed with tag other than web-bot-auth",
            parameters=SignatureParameters(tag="other-profile/v1"),
            expected=_no(Refusal.SIGNATURE_MISSING),
            tier="profile",
            basis="Profile: tag web-bot-auth",
        ),
    )


_COMMENT = (
    "Failure scenarios for the Web Bot Auth profile, as data. A harness signs each request, "
    "directory, and response scenario at run time, applies after_signing, and grades the "
    "verifier on expected: a pass, or a refusal by its status and rule (refusals.json). "
    "created and expires are offsets in seconds from the harness clock; a null parameter is "
    "omitted; a nonce object asks for that many random bytes in that encoding. verifier is the "
    "verifier's own authority, which a request scenario's authority replaces. tier \"wba\": the "
    "reference libraries with no profile rules already give the expected outcome. tier "
    '"profile": the bare libraries give the opposite outcome and only the profile\'s rules give '
    'the expected one; a WBA MUST the library does not enforce stays "profile" until it does. '
    "See README.md."
)


def build_scenarios() -> ScenariosDocument:
    buyer, seller = key("buyer-request"), key("seller-response")
    return ScenariosDocument(
        comment=_COMMENT,
        spec=SPEC,
        spec_reference=f"{DOC_URL}#profile-rules",
        signer=Party(
            identity=Origin.parse(BUYER), kid=buyer.thumbprint, signature_agent=BUYER_KEYS
        ),
        responder=Party(
            identity=Origin.parse(SELLER), kid=seller.thumbprint, signature_agent=SELLER_KEYS
        ),
        verifier=RequestAuthority(SELLER_AUTHORITY),
        requests={
            "post": RequestDoc(
                method="POST",
                url=COMMIT_URL,
                headers=HeaderLines([("content-type", "application/json")]),
                body=COMMIT_BODY,
            ),
            "get": RequestDoc(method="GET", url=f"{SELLER}/proposals/prop_7?view=a%7Eb&x=1"),
        },
        components={
            "post": _POST,
            "get": _GET,
        },
        parameters=SignatureParameters(
            created=-5,
            expires=295,
            nonce=NonceSpec(bytes=64, encoding="base64url"),
            tag=SIGNATURE_TAG,
        ),
        response=ResponseDoc(
            status=200,
            headers=HeaderLines([("content-type", "application/json")]),
            body=COMMIT_RESULT_BODY,
        ),
        response_components={
            "bound": _BOUND,
            "unbound": _UNBOUND,
        },
        response_parameters=SignatureParameters(created=-5, expires=295, tag=SIGNATURE_TAG),
        directory_parameters=SignatureParameters(created=0, expires=DEFAULT_PUBLISH.lifetime),
        directory_max_age=DEFAULT_PUBLISH.max_age,
        request_scenarios=_request_scenarios(),
        directory_scenarios=_directory_scenarios(),
        response_scenarios=_response_scenarios(),
    )


__all__ = ["build_scenarios"]
