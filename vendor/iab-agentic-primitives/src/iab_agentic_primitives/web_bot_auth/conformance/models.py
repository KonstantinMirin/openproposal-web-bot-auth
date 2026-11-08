"""The conformance documents as frozen, typed models.

``keys.json``, ``scenarios.json``, ``refusals.json``, each vector, each adapter
operation (``PROTOCOL.md``), and each result validate when they are read, in
Pydantic's strict mode: a boolean is a JSON ``true`` or ``false``, an integer
is a JSON integer, and a member nobody declared is refused (a result may
carry extra members). Identities validate as :class:`~..values.Origin` and
authorities as :data:`~..values.RequestAuthority`.

A sum is a union discriminated by a member, never a product of optional
fields: an outcome is a :class:`Passes` or a :class:`Refuses`, on ``ok``, and
a vector's operation is one of the three verify operations, on ``op``. A
refusal names its rule, and its status is the rule's.

Each model is a frozen, slotted, keyword-only dataclass, like the rest of the
module: :func:`read` reads JSON into a model, and :func:`dump` writes one back.
"""

from __future__ import annotations

import base64
import enum
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from typing import Annotated, ClassVar, Final, Literal, TypeVar, cast, get_args

from pydantic import (
    ConfigDict,
    Discriminator,
    Field,
    PlainSerializer,
    PlainValidator,
    Tag,
    TypeAdapter,
    model_serializer,
    model_validator,
)

from ..directory import DirectoryResponse
from ..errors import Refusal, Status
from ..keys import PrivateJwk
from ..message import Answer, HeaderLines, HTTPRequest, HTTPResponse
from ..values import Origin, RequestAuthority, UnixSeconds, parse_authority

#: ``wba``: the bare reference libraries already give the expected outcome.
#: ``profile``: only the profile's rules give it.
Tier = Literal["profile", "wba"]
#: The suites a runner grades.
Suite = Literal["vectors", "live", "scenarios"]


T = TypeVar("T")


@dataclass(frozen=True, slots=True, kw_only=True)
class Model:
    """A conformance document, read strictly, with no member it doesn't declare."""

    __pydantic_config__: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)


#: One validator per model, built on first use.
_ADAPTERS: dict[object, object] = {}


def _adapter(kind: object) -> TypeAdapter[T]:
    found = _ADAPTERS.get(kind)
    if found is None:
        found = _ADAPTERS[kind] = TypeAdapter(kind)
    return cast(TypeAdapter[T], found)


def read[T](kind: type[T], text: str | bytes) -> T:
    """Reads the JSON ``text`` as a ``kind``; ``pydantic.ValidationError`` when it isn't one."""
    adapter: TypeAdapter[T] = _adapter(kind)
    return adapter.validate_json(text)


def dump(document: object) -> object:
    """The JSON data of a model, with its aliases and without the fields left unset."""
    adapter: TypeAdapter[object] = _adapter(type(document))
    return adapter.dump_python(document, mode="json", by_alias=True, exclude_none=True)


def dump_json(document: object) -> str:
    return json.dumps(dump(document))


def _refusal(value: object) -> Refusal:
    if isinstance(value, Refusal):
        return value
    if isinstance(value, str):
        return Refusal.of(value)
    raise ValueError(f"a rule is a refusal reason code, not {value!r}")


def _code(refusal: Refusal) -> str:
    return refusal.code


#: A refusal, written as its reason code, such as ``"nonce-missing"``.
Rule = Annotated[Refusal, PlainValidator(_refusal), PlainSerializer(_code, return_type=str)]


def _status(value: object) -> Status:
    if type(value) is not int or value not in get_args(Status):
        raise ValueError(f"a status is one of {get_args(Status)}, not {value!r}")
    return cast(Status, value)


#: A refusal status, a JSON integer among 400, 403, 429, and 503.
StatusCode = Annotated[Status, PlainValidator(_status), PlainSerializer(int, return_type=int)]


def _true(value: object) -> Literal[True]:
    if value is not True:
        raise ValueError(f"ok is the JSON boolean true here, not {value!r}")
    return True


def _false(value: object) -> Literal[False]:
    if value is not False:
        raise ValueError(f"ok is the JSON boolean false here, not {value!r}")
    return False


#: ``ok`` on a pass: the JSON boolean ``true``, not a value equal to it.
OkTrue = Annotated[Literal[True], PlainValidator(_true)]
#: ``ok`` on a refusal: the JSON boolean ``false``.
OkFalse = Annotated[Literal[False], PlainValidator(_false)]


def _origin(value: object) -> Origin:
    return value if isinstance(value, Origin) else Origin.parse(value)


#: An identity, written as ``https://<host>``.
Identity = Annotated[Origin, PlainValidator(_origin), PlainSerializer(str, return_type=str)]


def _authority(value: object) -> RequestAuthority:
    return parse_authority(value)


#: A request authority, written as ``host[:port]``.
Authority = Annotated[
    RequestAuthority, PlainValidator(_authority), PlainSerializer(str, return_type=str)
]


# ── messages ───────────────────────────────────────────────────────────────


def _lines(value: object) -> HeaderLines:
    """Field lines from JSON: an array of ``[name, value]`` string pairs, in wire order."""
    if isinstance(value, HeaderLines):
        return value
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"headers are [name, value] pairs, not {value!r}")
    pairs = [tuple(line) for line in value if isinstance(line, (list, tuple))]
    if len(pairs) != len(value) or not all(
        len(pair) == 2 and all(isinstance(part, str) for part in pair) for pair in pairs
    ):
        raise ValueError(f"headers are [name, value] pairs of strings, not {value!r}")
    return HeaderLines((str(name), str(text)) for name, text in pairs)


def _pairs(lines: HeaderLines) -> list[list[str]]:
    return [[name, value] for name, value in lines]


#: Field lines, written as ``[name, value]`` pairs in order, so a repeated field survives.
Lines = Annotated[HeaderLines, PlainValidator(_lines), PlainSerializer(_pairs)]


def _body(value: object) -> bytes:
    """A body from JSON: a string of UTF-8 text, or ``{"base64": ...}`` for any other bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    encoded = value.get("base64") if isinstance(value, dict) and len(value) == 1 else None
    if not isinstance(encoded, str):
        raise ValueError(f'a body is text or {{"base64": ...}}, not {value!r}')
    return base64.b64decode(encoded, validate=True)


def _body_json(body: bytes) -> str | dict[str, str]:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(body).decode("ascii")}


#: The exact body bytes: text when they are UTF-8, ``{"base64": ...}`` otherwise.
Body = Annotated[bytes, PlainValidator(_body), PlainSerializer(_body_json)]
_NO_LINES = HeaderLines()


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestDoc(Model):
    """A request: ``method``, absolute ``url``, field lines, and the exact body."""

    method: str
    url: str
    headers: Lines = _NO_LINES
    body: Body = b""

    def message(self) -> HTTPRequest:
        return HTTPRequest(self.method, self.url, self.headers, self.body)

    @classmethod
    def of(cls, request: HTTPRequest) -> RequestDoc:
        return cls(
            method=request.method, url=request.url, headers=request.headers, body=request.body
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ResponseDoc(Model):
    """A response: ``status``, field lines, and the exact body."""

    status: int
    headers: Lines = _NO_LINES
    body: Body = b""

    def message(self, request: HTTPRequest) -> HTTPResponse:
        return HTTPResponse(self.status, self.headers, self.body, request)

    @classmethod
    def of(cls, response: HTTPResponse) -> ResponseDoc:
        return cls(status=response.status, headers=response.headers, body=response.body)


@dataclass(frozen=True, slots=True, kw_only=True)
class DirectoryDoc(Model):
    """A signed key directory response, and the ``url`` it is served at when known."""

    url: str | None = None
    status: int
    headers: Lines = _NO_LINES
    body: Body = b""

    def fetched(self, url: str, now: UnixSeconds) -> DirectoryResponse:
        return DirectoryResponse(url, self.status, self.headers, self.body, now)

    def answer(self) -> Answer:
        """The response as a directory server answers it."""
        return Answer(self.status, self.headers, self.body)

    @classmethod
    def of(cls, url: str, answer: Answer) -> DirectoryDoc:
        return cls(url=url, status=answer.status, headers=answer.headers, body=answer.body)


# ── keys.json ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class KeyEntry(Model):
    """A published test key, with its private seed."""

    identity: Identity
    seed_name: str
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    kid: str
    x: str
    use: Literal["sig"]
    private_d: Annotated[str, Field(alias="_private_d_for_test_only")]

    def private_jwk(self) -> PrivateJwk:
        return {"kty": self.kty, "crv": self.crv, "x": self.x, "d": self.private_d}


@dataclass(frozen=True, slots=True, kw_only=True)
class KeysDocument(Model):
    comment: Annotated[str, Field(alias="$comment")]
    keys: tuple[KeyEntry, ...]


# ── refusals.json ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class RefusalEntry(Model):
    rule: str
    status: StatusCode


@dataclass(frozen=True, slots=True, kw_only=True)
class RefusalsDocument(Model):
    """The refusal vocabulary, generated from :class:`Refusal`."""

    comment: Annotated[str, Field(alias="$comment")]
    refusals: tuple[RefusalEntry, ...]


# ── outcomes ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class AcceptSignature(Model):
    """The ``Accept-Signature`` member a verifier SHOULD send with a ``403`` or ``429``."""

    label: str
    components: str
    parameters: tuple[str, ...]
    tag: str
    nonce: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Passes(Model):
    """A verifier accepts, attributing the message to ``identity`` when one is named."""

    ok: OkTrue = True
    identity: Identity | None = None
    rationale: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Refuses(Model):
    """A verifier refuses with ``rule``, and so with the rule's ``status``.

    The status is the rule's when it is read and when :func:`refusing` makes one.
    """

    ok: OkFalse = False
    rule: Rule
    status: StatusCode
    accept_signature: AcceptSignature | None = None
    rationale: str | None = None

    @model_validator(mode="after")
    def _status_is_the_rules(self) -> Refuses:
        if self.status != self.rule.status:
            raise ValueError(f"status {self.status} is not the status of the rule {self.rule}")
        return self


def _outcome_tag(value: object) -> str | None:
    ok = value.get("ok") if isinstance(value, Mapping) else getattr(value, "ok", None)
    return "passes" if ok is True else "refuses" if ok is False else None


#: What a verifier must answer: :class:`Passes` or :class:`Refuses`, on ``ok``.
Outcome = Annotated[
    Annotated[Passes, Tag("passes")] | Annotated[Refuses, Tag("refuses")],
    Discriminator(_outcome_tag),
]


def passing(identity: Origin | str | None = None) -> Passes:
    """A pass, attributed to ``identity`` when it is given."""
    return Passes(identity=None if identity is None else _origin(identity))


def refusing(
    rule: Refusal, *, rationale: str | None = None, accept_signature: AcceptSignature | None = None
) -> Refuses:
    return Refuses(
        rule=rule, status=rule.status, rationale=rationale, accept_signature=accept_signature
    )


# ── scenarios.json ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class NonceSpec(Model):
    """Asks for ``bytes`` random bytes in ``encoding``."""

    bytes: int
    encoding: Literal["base64url", "base64", "base64url-padded"]


class _Unset(enum.Enum):
    UNSET = "unset"


#: A parameter a scenario leaves as the profile signs it: absent from the JSON.
UNSET: Final = _Unset.UNSET


def _absent(value: object) -> _Unset:
    raise ValueError("an absent parameter keeps the profile's value; there is no JSON for it")


#: The type of :data:`UNSET`, which no JSON value validates as.
Unset = Annotated[_Unset, PlainValidator(_absent)]


@dataclass(frozen=True, slots=True, kw_only=True)
class SignatureParameters(Model):
    """A signature's parameters, as a scenario moves them from the profile's.

    A parameter left out keeps the profile's value, and ``null`` leaves it
    out of the signature. ``created`` and ``expires`` are offsets in seconds
    from the harness clock; ``expires`` defaults to the signer's lifetime
    after ``created``. ``nonce`` is a literal or a :class:`NonceSpec`. Any
    other member is refused when the document is read.
    """

    created: int | Unset = UNSET
    expires: int | None | Unset = UNSET
    nonce: NonceSpec | str | None | Unset = UNSET
    keyid: str | Unset = UNSET
    alg: str | None | Unset = UNSET
    tag: str | None | Unset = UNSET

    def merged(self, later: SignatureParameters | None) -> SignatureParameters:
        """These parameters with each one ``later`` sets."""
        if later is None:
            return self
        changes = {f.name: getattr(later, f.name) for f in fields(later)}
        return replace(self, **{name: v for name, v in changes.items() if v is not UNSET})

    @model_serializer(mode="plain")
    def _members(self) -> dict[str, object]:
        """The parameters the scenario sets, ``null`` included; an unset one is absent."""
        values = {f.name: getattr(self, f.name) for f in fields(self)}
        return {
            name: dump(value) if isinstance(value, NonceSpec) else value
            for name, value in values.items()
            if value is not UNSET
        }


#: The parameters of the profile itself, moved nowhere.
PROFILE_PARAMETERS: Final = SignatureParameters()


@dataclass(frozen=True, slots=True, kw_only=True)
class ExtraSignature(Model):
    label: str
    kid: str
    components: tuple[str, ...]
    parameters: SignatureParameters = PROFILE_PARAMETERS


def _appended(value: str, tail: str | None) -> str:
    return value if tail is None else f"{value}, {tail}"


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestEdits(Model):
    """What a harness changes on a signed request: field values, appended members, the body."""

    headers: dict[str, str] | None = None
    append_members: dict[str, str] | None = None
    append_to_body: str | None = None

    def applied_to(self, request: HTTPRequest) -> HTTPRequest:
        """``request`` with each field in ``headers`` replaced in place, each in
        ``append_members`` longer, and ``append_to_body`` after its body."""
        changed = {name.lower(): value for name, value in (self.headers or {}).items()}
        extra = {name.lower(): value for name, value in (self.append_members or {}).items()}
        lines = HeaderLines(
            (name, _appended(changed.get(name.lower(), value), extra.get(name.lower())))
            for name, value in request.headers
        )
        body = request.body + (self.append_to_body or "").encode()
        return replace(request, headers=lines, body=body)


@dataclass(frozen=True, slots=True, kw_only=True)
class ResponseEdits(Model):
    """What a harness changes on a signed response: its status, its body, and the request
    it is shown with."""

    status: int | None = None
    append_to_body: str | None = None
    request_headers: dict[str, str] | None = None

    def applied_to(self, response: HTTPResponse) -> HTTPResponse:
        request = response.request
        for name, value in (self.request_headers or {}).items():
            request = replace(request, headers=request.headers.with_replaced(name, value))
        return HTTPResponse(
            response.status if self.status is None else self.status,
            response.headers,
            response.body + (self.append_to_body or "").encode(),
            request,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class DirectoryEdits(Model):
    """What a harness changes on a signed directory: its body."""

    append_to_body: str | None = None

    def applied_to(self, body: bytes) -> bytes:
        return body + (self.append_to_body or "").encode()


@dataclass(frozen=True, slots=True, kw_only=True)
class Party(Model):
    """Who signs: the identity, its ``kid``, and its ``Signature-Agent`` value."""

    identity: Identity
    kid: str
    signature_agent: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Scenario(Model):
    id: str
    name: str
    tier: Tier = "wba"
    basis: str
    expected: Outcome


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestScenario(Scenario):
    """A request the harness signs at run time, and the outcome its verifier gives.

    ``authority`` replaces the verifier's own authority.
    """

    base: Literal["post", "get"] = "post"
    label: str = "sig1"
    components: tuple[str, ...] | None = None
    parameters: SignatureParameters | None = None
    signature_agent: str | None = None
    directories: dict[str, tuple[str, ...]] | None = None
    extra_signature: ExtraSignature | None = None
    after_signing: RequestEdits | None = None
    authority: Authority | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DirectoryScenario(Scenario):
    """A directory the harness signs at run time, as the signer's own directory.

    ``authority`` signs it for another authority. ``parameters`` moves
    ``created`` and ``expires`` from the document's ``directory_parameters``.
    """

    keys: tuple[str, ...] | None = None
    unsigned_keys: tuple[dict[str, str], ...] | None = None
    authority: Authority | None = None
    parameters: SignatureParameters | None = None
    components: tuple[str, ...] | None = None
    content_type: str | None = None
    after_signing: DirectoryEdits | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ResponseScenario(Scenario):
    """A response the harness signs at run time, to the ``post`` request.

    ``request`` is ``bound`` when the request is signed as the baseline, so the
    response binds to it, and ``unbound`` when it is sent unsigned.
    """

    label: str = "sig1"
    components: tuple[str, ...] | None = None
    parameters: SignatureParameters | None = None
    request: Literal["bound", "unbound"] = "bound"
    after_signing: ResponseEdits | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScenariosDocument(Model):
    """The failure scenarios, with every default both interpreters sign from.

    ``parameters``, ``response_parameters``, and ``directory_parameters`` are
    what a request, a response, and a directory signature carry unless a
    scenario moves them; ``directory_max_age`` is the directory's
    ``Cache-Control`` ``max-age``.
    """

    comment: Annotated[str, Field(alias="$comment")]
    spec: str
    spec_reference: str
    signing_profile: Literal["web-bot-auth"] = "web-bot-auth"
    signer: Party
    responder: Party
    verifier: Authority
    requests: dict[Literal["post", "get"], RequestDoc]
    components: dict[Literal["post", "get"], tuple[str, ...]]
    parameters: SignatureParameters
    response: ResponseDoc
    response_components: dict[Literal["bound", "unbound"], tuple[str, ...]]
    response_parameters: SignatureParameters
    directory_parameters: SignatureParameters
    directory_max_age: int
    request_scenarios: tuple[RequestScenario, ...]
    directory_scenarios: tuple[DirectoryScenario, ...]
    response_scenarios: tuple[ResponseScenario, ...]


# ── operations and results (PROTOCOL.md) ───────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class SignRequest(Model):
    op: Literal["sign_request"] = "sign_request"
    key: PrivateJwk
    origin: Identity
    request: RequestDoc
    now: UnixSeconds
    label: str = "sig1"


@dataclass(frozen=True, slots=True, kw_only=True)
class SignDirectory(Model):
    op: Literal["sign_directory"] = "sign_directory"
    keys: tuple[PrivateJwk, ...]
    origin: Identity
    now: UnixSeconds


@dataclass(frozen=True, slots=True, kw_only=True)
class SignResponse(Model):
    op: Literal["sign_response"] = "sign_response"
    key: PrivateJwk
    origin: Identity
    request: RequestDoc
    response: ResponseDoc
    now: UnixSeconds
    label: str = "sig1"


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifyRequest(Model):
    """Verify ``request`` as the verifier whose own authority is ``authority``.

    ``prior`` lists requests verified first, with the same directories and
    clock, so the verifier's replay state is built the way it would be.
    """

    op: Literal["verify_request"] = "verify_request"
    request: RequestDoc
    authority: Authority
    directories: dict[str, DirectoryDoc] = field(default_factory=dict)
    now: UnixSeconds
    prior: tuple[RequestDoc, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifyDirectory(Model):
    op: Literal["verify_directory"] = "verify_directory"
    origin: Identity
    response: DirectoryDoc
    now: UnixSeconds


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifyResponse(Model):
    """Verify ``response`` to ``request``; from ``expected_origin`` when it is given."""

    op: Literal["verify_response"] = "verify_response"
    request: RequestDoc
    response: ResponseDoc
    directories: dict[str, DirectoryDoc] = field(default_factory=dict)
    now: UnixSeconds
    expected_origin: Identity | None = None


Operation = Annotated[
    SignRequest | SignDirectory | SignResponse | VerifyRequest | VerifyDirectory | VerifyResponse,
    Field(discriminator="op"),
]
OPERATION: TypeAdapter[Operation] = TypeAdapter(Operation)

#: The operation that grades a vector: one of the three verifications.
VectorOperation = Annotated[
    VerifyRequest | VerifyResponse | VerifyDirectory, Field(discriminator="op")
]


# ── vectors ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class ReplayEntry(Model):
    identity: Identity
    nonce: str
    ttl_seconds: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Vector(Model):
    """One committed operation and the outcome a verifier must give it.

    ``operation`` is ready to send to an adapter as it is: the message, the
    signed directories it names, the verifier's clock (``reference_now``),
    and the authority or origin it is held to. ``replay_cache_entries`` is the
    replay state its ``prior`` requests leave, for a white-box harness.
    """

    name: str
    tier: Tier
    spec: str
    spec_reference: str
    signing_profile: Literal["web-bot-auth"] = "web-bot-auth"
    reference_now: UnixSeconds
    operation: VectorOperation
    replay_cache_entries: tuple[ReplayEntry, ...] = ()
    expected_signature_base: dict[str, str] | None = None
    expected: Outcome
    comment: Annotated[str, Field(alias="$comment")]


@dataclass(frozen=True, slots=True, kw_only=True)
class ResultModel:
    """A result an adapter returns, read strictly. Members the protocol doesn't name are
    ignored."""

    __pydantic_config__: ClassVar[ConfigDict] = ConfigDict(extra="ignore", strict=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class Verified(ResultModel):
    """A verified request or response: the identity it is attributed to and its key."""

    ok: OkTrue = True
    identity: str
    keyid: str
    body_covered: bool | None = None
    bound: bool | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class KeysVerified(ResultModel):
    """A verified directory: the ids of the keys it verified."""

    ok: OkTrue = True
    keyids: tuple[str, ...]


#: The rules a harness gives a result that isn't the implementation's own answer.
AdapterRule = Literal["adapter-error", "adapter-crash", "adapter-timeout", "adapter-invalid"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Refused(ResultModel):
    """A refusal, with its status and rule.

    ``status`` is ``None`` only on a harness failure, whose ``rule`` is an
    :data:`AdapterRule`; every expected refusal fails against it.
    """

    ok: OkFalse = False
    status: StatusCode | None
    rule: str
    error: str = ""

    @classmethod
    def adapter_failure(cls, rule: AdapterRule, error: str) -> Refused:
        return cls(status=None, rule=rule, error=error[:600])


Result = Verified | KeysVerified | Refused | RequestDoc | ResponseDoc | DirectoryDoc


def result_of(op: Operation, text: str) -> Result:
    """Reads an adapter's JSON answer to ``op``: a refusal, or the operation's own result."""
    data = json.loads(text)
    if isinstance(data, Mapping) and data.get("ok") is False:
        return read(Refused, text)
    match op:
        case SignRequest():
            return read(RequestDoc, text)
        case SignDirectory():
            return read(DirectoryDoc, text)
        case SignResponse():
            return read(ResponseDoc, text)
        case VerifyDirectory():
            return read(KeysVerified, text)
        case VerifyRequest() | VerifyResponse():
            return read(Verified, text)


__all__ = [
    "OPERATION",
    "PROFILE_PARAMETERS",
    "UNSET",
    "AcceptSignature",
    "AdapterRule",
    "Authority",
    "Body",
    "DirectoryDoc",
    "DirectoryEdits",
    "DirectoryScenario",
    "ExtraSignature",
    "Identity",
    "KeyEntry",
    "KeysDocument",
    "KeysVerified",
    "Lines",
    "Model",
    "NonceSpec",
    "OkFalse",
    "OkTrue",
    "Operation",
    "Outcome",
    "Party",
    "Passes",
    "RefusalEntry",
    "RefusalsDocument",
    "Refused",
    "Refuses",
    "ReplayEntry",
    "RequestDoc",
    "RequestEdits",
    "RequestScenario",
    "ResponseDoc",
    "ResponseEdits",
    "ResponseScenario",
    "Result",
    "Rule",
    "ScenariosDocument",
    "SignDirectory",
    "SignRequest",
    "SignResponse",
    "SignatureParameters",
    "StatusCode",
    "Suite",
    "Tier",
    "Unset",
    "Vector",
    "VectorOperation",
    "Verified",
    "VerifyDirectory",
    "VerifyRequest",
    "VerifyResponse",
    "dump",
    "dump_json",
    "passing",
    "read",
    "refusing",
    "result_of",
]
