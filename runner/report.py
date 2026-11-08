"""The live runner's report: its schema, and what it may hold.

`Report` is what `latest-run.json` holds, and site/run.js reads it as the
schema states. The schema is committed as site/report.schema.json:

    uv run python -m runner.report --schema > site/report.schema.json

and a test keeps the file equal to the model. `FORMAT` is the report's
version; the site refuses a report of another format.

A report holds public data only. `public_headers` withholds credentials and the
TLS proxy's headers, and `assert_public` refuses a report that holds a
configured secret or a private JWK.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from typing import Literal

from pydantic import Field

from persistence.values import Origin
from protocol.values import JsonObject, JsonValue, Value
from transport.control import OPERATOR_HEADER, Agreed, CloudflareCheck

FORMAT: Literal[2] = 2
#: How many runs history.json keeps, newest first.
HISTORY = 20

#: Header fields a report never shows: credentials, and what the TLS proxy adds.
WITHHELD = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        OPERATOR_HEADER.lower(),
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "forwarded",
        "via",
    }
)
#: The members of a public JWK a report shows.
_PUBLIC_JWK = ("kid", "kty", "crv", "x", "use", "alg")


class _Part(Value):
    """A part of the report: a `Value`, built once its inputs are known."""


class Headers(_Part):
    """Header lines in order, lowercased, without the withheld fields; and which were withheld."""

    lines: list[tuple[str, str]]
    withheld: list[str]


class Directory(_Part):
    """A key directory response: as a party kept it, or as the runner fetched it."""

    url: str
    status: int
    #: When the party fetched it; None for the runner's own fetch.
    fetched_at: str | None = None
    #: Until when the runner's own fetch is valid; None for a kept fetch.
    expires: str | None = None
    headers: Headers
    keys: list[JsonObject]
    sha256: str | None = None


class Message(_Part):
    """A request, as a party sent or kept it."""

    method: str
    url: str
    keyid: str | None
    headers: Headers
    body: JsonValue


class Answer(_Part):
    """A response, as the buyer received and kept it."""

    status: int
    keyid: str
    headers: Headers
    body: JsonValue


class SellerSide(_Part):
    """What the seller's boundary resolved for the commit, and the signed request it kept."""

    principal_id: str
    authentication_method: str
    attributed: bool
    #: The kept request that carried the entry; None for a bearer commit.
    evidence_id: int | None = None
    request: Message | None = None
    directory: Directory | None = None


class BuyerSide(_Part):
    """The request as the buyer sent it, and the seller's signed answer as it arrived."""

    evidence_id: int
    request: Message
    response: Answer
    directory: Directory | None


class Digest(_Part):
    """Both parties' digest input, and the record_digest over it."""

    record_digest: str
    digest_input_bytes: int


class Reverified(_Part):
    """Both kept messages, verified again offline from the stored bytes."""

    request_components: list[str]
    response_components: list[str]
    response_bound: bool


class FlowRun(_Part):
    """One credential's run of the flow: signature or bearer."""

    proposal_id: str | None = None
    outcome: Agreed | None = None
    seller: SellerSide | None = None
    buyer: BuyerSide | None = None
    digest: Digest | None = None
    reverify: Reverified | None = None


class StepResult(_Part):
    id: str
    title: str
    ok: bool
    ms: int
    detail: str | None


class Report(_Part):
    format: Literal[2] = FORMAT
    started_at: str
    finished_at: str | None = None
    duration_ms: int | None = None
    ok: bool
    origins: dict[str, Origin] = Field(default_factory=dict)
    software: dict[str, str | None] = Field(default_factory=dict)
    line_item_ids: list[str] = Field(default_factory=list)
    directories: dict[str, Directory | None] = Field(default_factory=dict)
    signature: FlowRun | None = None
    bearer: FlowRun | None = None
    cloudflare: CloudflareCheck | None = None
    steps: list[StepResult]


class HistoryEntry(_Part):
    started_at: str
    ok: bool
    duration_ms: int | None
    failed: list[str]


class History(_Part):
    runs: list[HistoryEntry]


# What a report may hold


def public_headers(lines: Iterable[tuple[str, str]], *, unkept: Iterable[str] = ()) -> Headers:
    """Field lines in order, without the withheld fields, and the names of those withheld.

    `unkept` names fields the message carried but its kept lines leave out, such as
    the bearer token a party never stores; they are listed as withheld too.
    """
    shown: list[tuple[str, str]] = []
    withheld = {name.lower() for name in unkept}
    for name, value in lines:
        if name.lower() in WITHHELD:
            withheld.add(name.lower())
        else:
            shown.append((name.lower(), value))
    return Headers(lines=shown, withheld=sorted(withheld))


def public_key(jwk: JsonValue) -> JsonObject:
    """A JWK's public members only."""
    if not isinstance(jwk, dict):
        return {}
    return {k: jwk[k] for k in _PUBLIC_JWK if k in jwk}


def body_of(data: bytes) -> JsonValue:
    """A body as JSON, or as text when it isn't JSON."""
    try:
        value: JsonValue = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return data.decode("utf-8", "replace")
    return value


def _private_jwk(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return ("kty" in value and "d" in value) or any(_private_jwk(v) for v in value.values())
    if isinstance(value, list):
        return any(_private_jwk(v) for v in value)
    return False


class NotPublic(Exception):
    """The report holds something that must not be published."""

    def __init__(self, what: str) -> None:
        super().__init__(f"{what} appears in the report")


_SECRET, _PRIVATE_KEY = "a configured secret", "a private JWK"


def assert_public(report: Report, secrets: Sequence[str]) -> str:
    """The report as JSON text; raises `NotPublic` when it holds a secret or a private key."""
    text = report.model_dump_json(indent=1)
    for secret in secrets:
        if secret and secret in text:
            raise NotPublic(_SECRET)
    if _private_jwk(report.model_dump(mode="json")):
        raise NotPublic(_PRIVATE_KEY)
    return text


def withheld(report: Report, reason: NotPublic) -> Report:
    """What is published instead of a report that isn't public: a bare failure."""
    step = StepResult(
        id="publish", title="Publish the report", ok=False, ms=0, detail=f"withheld: {reason}"
    )
    return Report(started_at=report.started_at, ok=False, steps=[step])


def updated_history(previous: Sequence[HistoryEntry], report: Report) -> History:
    """The newest run first, then the earlier ones, `HISTORY` in all."""
    entry = HistoryEntry(
        started_at=report.started_at,
        ok=report.ok,
        duration_ms=report.duration_ms,
        failed=[s.id for s in report.steps if not s.ok],
    )
    return History(runs=[entry, *previous][:HISTORY])


def schema() -> str:
    """The report's JSON Schema, as site/report.schema.json holds it."""
    return json.dumps(Report.model_json_schema(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    if sys.argv[1:] != ["--schema"]:
        sys.exit("usage: python -m runner.report --schema")
    sys.stdout.write(schema())
