"""Verifying requests and responses under the profile.

:class:`RequestVerifier` confirms a request's ``web-bot-auth`` signature and
returns a :class:`VerifiedRequest`; :class:`ResponseVerifier` confirms a
response's and returns a :class:`VerifiedResponse`. Neither decides anything
else: the caller maps ``origin`` to its own stored principal. Only this module
constructs the two credentials, and both are frozen. So are the verifiers.

Both run the steps of WEB_BOT_AUTH.md, "Verification procedure", in its
order. Each step below names the step it implements:

- :func:`_select`: "Parse the fields" and "Select the signature".
- :func:`_check_authority`: "Check the authority", for a request only.
- :func:`_check_parameters`: "Check the parameters".
- :func:`_check_components`: "Check the components".
- :func:`_check_signer`: "Check the signer", for a response only.
- :meth:`_Verifier._authenticate`: "Resolve the key" and "Verify the
  signature".
- :meth:`RequestVerifier._record`: "Check the nonce".
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Collection
from dataclasses import InitVar, dataclass, field
from typing import Final, Literal, TypeVar

from . import _sig
from ._wire import (
    ComponentId,
    ContentDigestError,
    SignatureFields,
    SignatureMember,
    check_content_digest,
    is_signed,
    parse_signature_fields,
)
from .directory import VerifiedDirectory
from .errors import ConfigurationError, Refusal, WebBotAuthError, refuse
from .message import HeaderLines, HTTPRequest, HTTPResponse
from .ports import KeyResolver
from .replay import NonceStore, NonceStoreUnavailable
from .rules import (
    ALGORITHM,
    CONTENT_DIGEST,
    REQUEST,
    RESPONSE,
    SIGNATURE_TAG,
    Rules,
    signature_agent_component,
    web_bot_auth_label,
)
from .values import (
    Clock,
    KeyId,
    Origin,
    Seconds,
    ServerIdentity,
    UnixSeconds,
    authority_of,
    key_id_set,
    system_clock,
)

logger = logging.getLogger(__name__)

#: The mode in which a response must carry the signature of the host the request went to.
SAME_ORIGIN: Final = "same-origin"

#: Whose signature a response must carry: an :class:`Origin`; :data:`SAME_ORIGIN`,
#: the identity of the host the request went to, :meth:`Origin.of_url` of its URL;
#: or ``None``, any identity.
ExpectedOrigin = Origin | Literal["same-origin"] | None

M = TypeVar("M", HTTPRequest, HTTPResponse)
N = TypeVar("N", str, str | None)
T = TypeVar("T")


class _Token:
    """Proof that this module made a credential: it alone holds the instance."""

    __slots__ = ()


_OWNER = _Token()


@dataclass(frozen=True, slots=True)
class _Credential:
    """What both credentials hold. Only this module can make one.

    Construction needs this module's private token, so ``dataclasses.replace``,
    ``type(v)(...)``, and a direct call raise ``TypeError``. Copying and
    pickling raise too: a credential is the result of a verification, and the
    way to get another one is to verify again.
    """

    origin: Origin
    keyid: KeyId
    label: str
    created: UnixSeconds
    expires: UnixSeconds
    components: tuple[ComponentId, ...]
    body_covered: bool
    directory: VerifiedDirectory | None = field(compare=False, repr=False)
    _token: InitVar[_Token | None] = field(default=None, kw_only=True)

    def __post_init__(self, _token: _Token | None) -> None:
        if _token is not _OWNER:
            raise TypeError(f"a {type(self).__name__} is made only by verifying a message")

    def __reduce_ex__(self, protocol: object) -> tuple[object, ...]:
        raise TypeError(f"a {type(self).__name__} can't be copied or pickled; verify again")


@dataclass(frozen=True, slots=True)
class VerifiedRequest(_Credential):
    """A verified, replay-checked ``web-bot-auth`` request signature.

    ``origin`` is the identity the request is attributed to, ``https://<host>``,
    whichever form ``Signature-Agent`` used. ``created``, ``expires``, and
    ``nonce`` are the parameters the signature authenticates, and
    ``components`` the covered component identifiers.
    ``body_covered`` is ``True`` when the signature covers ``content-digest``
    and the digest matched the body. ``directory`` is the verified key
    directory the key came from, with the response bytes as evidence, when the
    resolver provides it (:class:`DirectoryResolver` does).
    """

    nonce: str


@dataclass(frozen=True, slots=True)
class VerifiedResponse(_Credential):
    """A verified ``web-bot-auth`` response signature.

    The fields read as on :class:`VerifiedRequest`. ``bound`` is ``True`` when
    the signature covers the signature of the request it answers; it is
    ``False`` only for a response to an unsigned request.
    """

    bound: bool


# ── the steps ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Selected:
    """The one ``web-bot-auth`` member and the origin its ``Signature-Agent`` names."""

    member: SignatureMember
    origin: Origin


def select_signature_agent(fields: SignatureFields, label: str) -> Origin:
    """The origin the ``Signature-Agent`` member ``label`` names.

    The signature ``label`` must cover that member. A member that carries
    parameters is ignored (draft -01 section 5.2.1).
    """
    agents = {k: a for k, a in fields.agents.items() if not a.has_parameters}
    if label in fields.repeated_agents:
        raise refuse(
            Refusal.MULTIPLE_SIGNATURE_AGENTS, f"Signature-Agent member {label} is repeated"
        )
    if len(agents) > 1:
        raise refuse(
            Refusal.MULTIPLE_SIGNATURE_AGENTS,
            f"{len(agents)} Signature-Agent members; the profile takes one",
        )
    if label not in agents:
        if label in fields.agents:
            raise refuse(
                Refusal.SIGNATURE_AGENT_PARAMETERS,
                f"Signature-Agent member {label} carries parameters, so it is ignored",
            )
        raise refuse(
            Refusal.SIGNATURE_AGENT_MISSING, f"Signature-Agent has no member keyed to {label}"
        )
    covered = signature_agent_component(label)
    if covered not in fields[label].components:
        raise refuse(Refusal.SIGNATURE_AGENT_NOT_COVERED, f"the signature does not cover {covered}")
    return Origin.from_signature_agent(agents[label].value)


def _select(lines: HeaderLines) -> _Selected:
    """Parse the fields and select the signature: the member and the origin it names.

    A message that isn't signed (:func:`is_signed`) is refused
    ``signature-missing``: the verifier was asked for a signature it doesn't carry.
    """
    fields = parse_signature_fields(lines)
    if fields is None:
        raise refuse(Refusal.SIGNATURE_MISSING, "the message carries no Signature-Input")
    member = fields.one_tagged(SIGNATURE_TAG)
    return _Selected(member, select_signature_agent(fields, member.label))


def _check_parameters(
    member: SignatureMember, rules: Rules[M, N], now: UnixSeconds
) -> tuple[KeyId, N]:
    """Check the parameters: ``keyid``, ``alg``, the window, and the nonce rule.

    Returns the key id, and the nonce as the rule gives it.
    """
    if not member.keyid:
        raise refuse(Refusal.KEYID, "keyid is missing")
    if member.alg != ALGORITHM:
        raise refuse(Refusal.ALG, f"alg must be {ALGORITHM}, not {member.alg!r}")
    rules.window.check(member.created, member.expires, now)
    return member.keyid, rules.nonce_of(member.nonce)


def _check_components(
    member: SignatureMember, required: tuple[ComponentId, ...], rules: Rules[M, N]
) -> None:
    """Check the components: the signature covers every one the rules require."""
    for component in required:
        if component not in member.components:
            raise refuse(rules.missing(component), f"{component} is not covered")


def _check_authority(request: HTTPRequest, identity: ServerIdentity) -> None:
    """Check the authority: the request names this server's own authority."""
    try:
        authority = authority_of(request.url)
    except ValueError as e:
        raise refuse(Refusal.AUTHORITY, f"{request.url!r} is not an absolute URL") from e
    if authority != identity.request_authority:
        raise refuse(Refusal.AUTHORITY, f"the request is for {authority}, not this verifier")


def _expected_signer(response: HTTPResponse, expected: ExpectedOrigin) -> Origin | None:
    """The origin ``response`` must be signed by, under ``expected``; ``None`` for any.

    Under :data:`SAME_ORIGIN` it is the identity of the host the request went
    to (a responder names its own origin), which :meth:`Origin.of_url` maps;
    a host that can't be an identity can't have signed, so it is refused.
    """
    if expected is None or isinstance(expected, Origin):
        return expected
    url = response.request.url
    try:
        return Origin.of_url(url)
    except ConfigurationError as e:
        raise refuse(Refusal.ORIGIN_MISMATCH, f"{url!r} names no host an identity can be") from e


def _check_signer(origin: Origin, expected: Origin | None) -> None:
    """Check the signer: the response comes from ``expected``, when it is given."""
    if expected is not None and origin != expected:
        raise refuse(Refusal.ORIGIN_MISMATCH, f"the response is signed by {origin}, not {expected}")


def _covered_body(member: SignatureMember, lines: HeaderLines, body: bytes) -> bytes | None:
    """The body when the signature covers ``Content-Digest``, checked against the digest.

    The profile requires the coverage for a message with a body, so ``None``
    means an empty body that the signature doesn't cover.
    """
    if CONTENT_DIGEST not in member.components:
        return None
    try:
        check_content_digest(lines, body)
    except ContentDigestError as e:
        raise refuse(Refusal.CONTENT_DIGEST, str(e)) from e
    return body


@dataclass(frozen=True, slots=True)
class _Authenticated:
    origin: Origin
    result: _sig.VerifyResult
    directory: VerifiedDirectory | None

    def request(self, nonce: str) -> VerifiedRequest:
        """The request credential, from the parameters the library authenticated."""
        r = self.result
        return VerifiedRequest(
            self.origin,
            r.keyid,
            r.label,
            r.created,
            r.expires,
            r.components,
            r.body is not None,
            self.directory,
            nonce=nonce,
            _token=_OWNER,
        )

    def response(self, *, bound: bool) -> VerifiedResponse:
        """The response credential, from the parameters the library authenticated."""
        r = self.result
        return VerifiedResponse(
            self.origin,
            r.keyid,
            r.label,
            r.created,
            r.expires,
            r.components,
            r.body is not None,
            self.directory,
            bound=bound,
            _token=_OWNER,
        )


def _log_refusal(role: str, selected: _Selected | None, error: WebBotAuthError) -> None:
    """Logs a refusal with the origin and keyid once they are known; never a nonce or a body."""
    logger.info(
        "refused a %s: %s %s (origin %s, keyid %s): %s",
        role,
        error.status,
        error.reason,
        "unknown" if selected is None else selected.origin,
        (selected and selected.member.keyid) or "unknown",
        error,
    )


async def _logged(
    role: str, message: HTTPRequest | HTTPResponse, verify: Callable[[_Selected], Awaitable[T]]
) -> T:
    """Selects the signature on ``message`` and runs ``verify`` on it, logging a refusal."""
    selected: _Selected | None = None
    try:
        selected = _select(message.headers)
        return await verify(selected)
    except WebBotAuthError as e:
        _log_refusal(role, selected, e)
        raise


# ── the verifiers ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, init=False)
class _Verifier:
    """What both verifiers hold, fixed when they are made: the resolver, the clock, the
    key ids they refuse."""

    resolver: KeyResolver
    clock: Clock
    reject_keyids: frozenset[KeyId]

    def __init__(
        self,
        resolver: KeyResolver,
        *,
        clock: Clock = system_clock,
        reject_keyids: Collection[str] = (),
    ) -> None:
        object.__setattr__(self, "resolver", resolver)
        object.__setattr__(self, "clock", clock)
        object.__setattr__(self, "reject_keyids", key_id_set(reject_keyids))

    def _now(self, now: UnixSeconds | None) -> UnixSeconds:
        return self.clock() if now is None else now

    async def _authenticate(
        self,
        message: M,
        selected: _Selected,
        keyid: KeyId,
        required: tuple[ComponentId, ...],
        now: UnixSeconds,
    ) -> _Authenticated:
        """Resolve the key and verify the signature, with the library checking ``required``."""
        member = selected.member
        if keyid in self.reject_keyids:
            raise refuse(Refusal.REJECTED_KEY, f"key {keyid} is refused")
        resolved = await self.resolver.resolve(selected.origin, keyid, now=now)
        body = _covered_body(member, message.headers, message.body)
        result = _sig.verify(
            message, member, resolved.public_key, require_components=required, body=body
        )
        return _Authenticated(selected.origin, result, resolved.directory)


@dataclass(frozen=True, slots=True, init=False)
class RequestVerifier(_Verifier):
    """Confirms ``web-bot-auth`` request signatures. It is immutable.

    ``resolver`` finds keys (usually a :class:`DirectoryResolver`).
    ``identity`` is the verifier's own :class:`ServerIdentity`: a request
    whose URL names any authority but
    :attr:`ServerIdentity.request_authority` is refused with ``403``, so a
    request signed for one server doesn't verify at another. ``nonces``
    records nonces; share one store across every worker that verifies
    requests for the same deployment (:class:`MemoryNonceStore` serves one
    process). ``reject_keyids`` lists key ids to refuse, such as the
    published test keys (Web Bot Auth section 6.8).
    """

    identity: ServerIdentity
    nonces: NonceStore

    def __init__(
        self,
        resolver: KeyResolver,
        *,
        identity: ServerIdentity,
        nonces: NonceStore,
        clock: Clock = system_clock,
        reject_keyids: Collection[str] = (),
    ) -> None:
        _Verifier.__init__(self, resolver, clock=clock, reject_keyids=reject_keyids)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "nonces", nonces)

    async def verify(
        self, request: HTTPRequest, *, now: UnixSeconds | None = None
    ) -> VerifiedRequest:
        """Verifies ``request``; raises :class:`WebBotAuthError` on failure, and logs it."""
        at = self._now(now)

        async def verify(selected: _Selected) -> VerifiedRequest:
            _check_authority(request, self.identity)
            keyid, nonce = _check_parameters(selected.member, REQUEST, at)
            required = REQUEST.components_for(request, selected.member.label)
            _check_components(selected.member, required, REQUEST)
            authenticated = await self._authenticate(request, selected, keyid, required, at)
            await self._record(authenticated, nonce, at)
            return authenticated.request(nonce)

        return await _logged("request", request, verify)

    async def _record(self, verified: _Authenticated, nonce: str, now: UnixSeconds) -> None:
        """Check the nonce: record it once for the origin, for the window plus the skew."""
        ttl = Seconds(verified.result.expires - now + REQUEST.window.skew)
        try:
            recorded = await self.nonces.check_and_record(verified.origin, nonce, ttl)
        except NonceStoreUnavailable as e:
            raise refuse(
                Refusal.NONCE_STORE_UNAVAILABLE, f"the nonce can't be recorded: {e}"
            ) from e
        if not recorded:
            raise refuse(Refusal.NONCE_REPLAYED, f"nonce seen before for {verified.origin}")


@dataclass(frozen=True, slots=True, init=False)
class ResponseVerifier(_Verifier):
    """Confirms ``web-bot-auth`` response signatures and their binding to the request.

    When the request carried a ``web-bot-auth`` signature, the response must
    cover ``"signature";req;key=<request label>``; otherwise it is refused, so
    an unbound response never verifies. A responder names its own origin
    (OpenProposal § 2.8.2), so by default the response must be signed by the
    identity of the host the request went to. It is immutable. It takes the
    ``resolver``, ``clock``, and ``reject_keyids`` a :class:`RequestVerifier`
    takes.
    """

    async def verify(
        self,
        response: HTTPResponse,
        *,
        expected_origin: ExpectedOrigin = SAME_ORIGIN,
        now: UnixSeconds | None = None,
    ) -> VerifiedResponse:
        """Verifies ``response``; raises :class:`WebBotAuthError` on failure, and logs it.

        ``response.request`` carries the request's URL and headers as sent,
        including its own signature. ``expected_origin`` names whose signature
        the response carries: :data:`SAME_ORIGIN` (the default), the identity
        :meth:`Origin.of_url` gives for ``response.request.url``, whatever its
        scheme and port; an :class:`Origin`; or ``None`` for any identity. A
        signature by anyone else is refused ``origin-mismatch``.
        """
        if expected_origin not in (SAME_ORIGIN, None) and not isinstance(expected_origin, Origin):
            raise TypeError(
                f"expected_origin is an Origin, {SAME_ORIGIN!r}, or None, not {expected_origin!r}"
            )
        at = self._now(now)

        async def verify(selected: _Selected) -> VerifiedResponse:
            keyid, _ = _check_parameters(selected.member, RESPONSE, at)
            required = RESPONSE.components_for(response, selected.member.label)
            _check_components(selected.member, required, RESPONSE)
            _check_signer(selected.origin, _expected_signer(response, expected_origin))
            authenticated = await self._authenticate(response, selected, keyid, required, at)
            bound = web_bot_auth_label(response.request.headers) is not None
            return authenticated.response(bound=bound)

        return await _logged("response", response, verify)


__all__ = [
    "SAME_ORIGIN",
    "ExpectedOrigin",
    "RequestVerifier",
    "ResponseVerifier",
    "VerifiedRequest",
    "VerifiedResponse",
    "is_signed",
]
