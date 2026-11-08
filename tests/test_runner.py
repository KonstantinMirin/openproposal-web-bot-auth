"""The live runner, run once against both agents in process (tests/stack.py).

The runner reaches the agents' controls and their directories through the
stack's network, and reads both parties' databases read-only through their
read models. The report it publishes validates against the committed schema
(site/report.schema.json), holds public data only, and keeps a short history.
The passing run's report is published to tests/site/published/, where the node
test renders it with site/run.js.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import jsonschema
import pytest
from iab_agentic_primitives.web_bot_auth import (
    HTTPRequest,
    HTTPResponse,
    ResponseSigner,
)

from persistence.values import Origin
from runner.main import main, publish, run_once
from runner.report import (
    HISTORY,
    Directory,
    History,
    HistoryEntry,
    NotPublic,
    Parties,
    Report,
    StepId,
    StepResult,
    assert_public,
    public_headers,
    schema,
)
from runner.settings import RunnerSettings
from shared.settings import SettingsError
from tests.stack import (
    BUYER,
    BUYER_KEY,
    CFBOT,
    RESELLER,
    SELLER,
    SELLER_KEY,
    TOKEN,
    Stack,
    cfbot_accepts,
    signed_request,
)
from transport.client import ControlClient, ControlFailed
from transport.control import (
    COMMIT,
    ISSUE,
    KEYS,
    OPERATOR_HEADER,
    OUTCOME,
    Agreed,
    ErrorBody,
    IssueRequest,
)

SITE = Path(__file__).resolve().parent.parent / "site"
SCHEMA_FILE = SITE / "report.schema.json"
SCHEMA = json.loads(SCHEMA_FILE.read_text())
#: Where the passing run is published for tests/site/render.test.mjs, which renders it with
#: site/run.js (make test runs it after this suite).
PUBLISHED = Path(__file__).resolve().parent / "site" / "published"


def _settings(stack: Stack, out: Path) -> RunnerSettings:
    return RunnerSettings(
        peer_seller_origin=Origin.parse(SELLER),
        peer_buyer_origin=Origin.parse(BUYER),
        peer_cfbot_origin=Origin.parse(CFBOT),
        seller_control=httpx.URL("http://seller:8000"),
        buyer_control=httpx.URL("http://buyer:8000"),
        seller_db=stack.seller_dir / "seller.db",
        buyer_db=stack.buyer_dir / "buyer.db",
        out_dir=out,
        interval=0,
        seller_operator_key=SELLER_KEY,
        buyer_operator_key=BUYER_KEY,
        secrets=(SELLER_KEY.get_secret_value(), BUYER_KEY.get_secret_value(), TOKEN),
    )


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    with Stack(tmp_path / "agents") as running:
        yield running


def _run(stack: Stack, out: Path) -> Report:
    transport = httpx.MockTransport(stack.runner_route)
    return asyncio.run(run_once(_settings(stack, out), transport=transport))


def test_a_run_passes_every_step_and_publishes_a_report_the_schema_accepts(
    stack: Stack, tmp_path: Path
) -> None:
    report = _run(stack, tmp_path / "out")
    assert report.ok, [s for s in report.steps if not s.ok]
    assert [s.id for s in report.steps] == [
        "directory-seller",
        "directory-buyer",
        "directory-cfbot",
        "signature-issue",
        "signature-commit",
        "signature-seller",
        "signature-buyer",
        "signature-digest",
        "signature-reverify",
        "bearer-issue",
        "bearer-commit",
        "bearer-seller",
        "bearer-buyer",
        "bearer-digest",
        "cloudflare",
    ]
    signature, bearer = report.signature, report.bearer
    assert signature is not None and signature.seller is not None
    assert signature.seller.principal_id == "buyer-wba"
    assert signature.seller.request is not None and signature.seller.directory is not None
    assert signature.reverify is not None and signature.reverify.response_bound
    assert bearer is not None and bearer.seller is not None and bearer.buyer is not None
    assert bearer.seller.request is None  # a bearer commit keeps no signed request
    assert "authorization" in bearer.buyer.request.headers.withheld

    shutil.rmtree(PUBLISHED, ignore_errors=True)
    publish(_settings(stack, PUBLISHED), report)
    published = json.loads((PUBLISHED / "latest-run.json").read_text())
    jsonschema.validate(published, SCHEMA)
    assert Report.model_validate_json(json.dumps(published)) == report
    history = History.model_validate_json((PUBLISHED / "history.json").read_bytes())
    assert history.runs[0] == HistoryEntry(
        started_at=report.started_at, ok=True, duration_ms=report.duration_ms, failed=[]
    )


def test_the_committed_schema_is_the_models_own() -> None:
    assert SCHEMA_FILE.read_text() == schema()


def test_a_failed_commit_fails_its_step_and_skips_what_needs_it(
    stack: Stack, tmp_path: Path
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response | None:
        return httpx.Response(503) if request.method == "POST" else None

    stack.answer = refuse  # an unsigned answer to every commit, which the buyer refuses
    report = _run(stack, tmp_path / "out")
    outcome = {s.id: s for s in report.steps}
    assert not report.ok
    assert not outcome["signature-commit"].ok
    assert "refused" in (outcome["signature-commit"].detail or "")
    later: tuple[StepId, ...] = ("signature-seller", "signature-buyer", "signature-digest")
    for step in (outcome[id] for id in later):
        assert (step.ok, step.detail) == (False, "skipped: signature-commit failed")
    assert outcome["signature-reverify"].detail == (
        "skipped: signature-seller, signature-buyer failed"
    )
    assert outcome["signature-issue"].ok and outcome["cloudflare"].ok
    jsonschema.validate(json.loads(report.model_dump_json()), SCHEMA)


#: What a run's network does to an answer the runner gets: here, the answer unchanged, or
#: another one, after changing what the parties kept.
After = Callable[[httpx.Request, httpx.Response], httpx.Response]
#: A change to the stack, made before the run, that returns what the network does after.
Corruption = Callable[[Stack], After]


@contextmanager
def _writable(path: Path) -> Iterator[sqlite3.Connection]:
    """A party's database, opened to tamper with it, committed on leaving."""
    db = sqlite3.connect(path)
    try:
        yield db
        db.commit()
    finally:
        db.close()


def _db(stack: Stack, party: str) -> Path:
    return stack.buyer_dir / "buyer.db" if party == "buyer" else stack.seller_dir / "seller.db"


def _after_commit(*changes: Callable[[Stack], None]) -> Corruption:
    """The parties' records, changed once each of the buyer's commits answers."""

    def corrupt(stack: Stack) -> After:
        def after(request: httpx.Request, response: httpx.Response) -> httpx.Response:
            if request.url.path == COMMIT.path:
                for change in changes:
                    change(stack)
            return response

        return after

    return corrupt


def _sql(party: str, statement: str, *params: object) -> Callable[[Stack], None]:
    def change(stack: Stack) -> None:
        with _writable(_db(stack, party)) as db:
            db.execute(statement, params)

    return change


def _request_signed_without_its_body(stack: Stack) -> None:
    """Tamper: the seller's kept request for the signed commit becomes one the buyer signed,
    with its own key, but without a body, so the signature covers no body."""
    url = f"{SELLER}/proposals/demo-wba-1"
    signed = signed_request("GET", url, stack.buyer_keys.active())
    headers = json.dumps([list(line) for line in signed.headers])
    with _writable(_db(stack, "seller")) as db:
        db.execute(
            "UPDATE signed_requests SET method = 'GET', url = ?, headers = ?, body = ?"
            " WHERE id = (SELECT evidence_id FROM assent"
            " WHERE role = 'commitment' AND authentication_method = 'web_bot_auth')",
            (url, headers, b""),
        )


def _answer_bound_to_nothing(stack: Stack) -> After:
    """Tamper: once the signed commit is agreed, the buyer's kept answer to it becomes one the
    seller signed, with its own key, for the request with its signature taken off, so it is
    bound to nothing."""

    def after(request: httpx.Request, response: httpx.Response) -> httpx.Response:
        if request.url.path == COMMIT.path:
            outcome = OUTCOME.validate_json(response.read())
            if isinstance(outcome, Agreed) and outcome.authentication_method == "web_bot_auth":
                _unbind(stack, outcome.evidence_id)
        return response

    return after


def _unbind(stack: Stack, evidence_id: int) -> None:
    with stack.buyer_records() as records:
        kept = records.response(evidence_id).response
    sent = kept.request
    unsigned = [line for line in sent.lines if not line[0].lower().startswith("signature")]
    request = HTTPRequest(sent.method, sent.url, unsigned, sent.body)
    answer = HTTPResponse(kept.status, [("content-type", "application/json")], kept.body, request)
    signed = ResponseSigner.of(stack.seller_key, SELLER).sign(answer)
    with _writable(_db(stack, "buyer")) as db:
        db.execute(
            "UPDATE signed_requests SET headers = ? WHERE id = ?",
            (json.dumps([list(line) for line in unsigned]), sent.id),
        )
        db.execute(
            "UPDATE signed_responses SET headers = ? WHERE id = ?",
            (json.dumps([list(line) for line in signed.headers]), evidence_id),
        )


def _answered(path: str, status: int) -> Corruption:
    """The network answers every call to `path` with `status`, whatever the agent said."""

    def corrupt(_stack: Stack) -> After:
        def after(request: httpx.Request, response: httpx.Response) -> httpx.Response:
            return httpx.Response(status, text="down") if request.url.path == path else response

        return after

    return corrupt


def _signed_commit_reported_as_bearer(_stack: Stack) -> After:
    """The network rewrites the buyer's outcome of a signed commit to name the bearer token."""

    def after(request: httpx.Request, response: httpx.Response) -> httpx.Response:
        if request.url.path != COMMIT.path:
            return response
        outcome = json.loads(response.read())
        if outcome.get("authentication_method") == "web_bot_auth":
            outcome["authentication_method"] = "bearer"
        return httpx.Response(response.status_code, json=outcome)

    return after


def _cfbot_sees_the_reseller(stack: Stack) -> After:
    """cfbot verifies the buyer's signature as another origin's."""
    stack.cfbot = lambda _: cfbot_accepts(RESELLER)
    return lambda _request, response: response


@dataclass(frozen=True)
class Corrupted:
    """A run whose network or records don't add up, and the check that catches it."""

    name: str
    corrupt: Corruption
    step: StepId
    detail: str
    #: What the step raised: a check that failed, or a control call that answered an error.
    failure: str = "CheckFailed"


CORRUPTED = [
    Corrupted(
        "the seller fails to issue",
        _answered(ISSUE.path, 500),
        "signature-issue",
        "POST /operator/issue answered 500: down",
        failure="ControlFailed",
    ),
    Corrupted(
        "the buyer fails to commit",
        _answered(COMMIT.path, 500),
        "signature-commit",
        "POST /operator/commit answered 500: down",
        failure="ControlFailed",
    ),
    Corrupted(
        "the buyer used another credential",
        _signed_commit_reported_as_bearer,
        "signature-commit",
        "the buyer used another credential",
    ),
    Corrupted(
        "the seller holds no commitment",
        _after_commit(
            _sql("seller", "DELETE FROM assent WHERE role = 'commitment'"),
        ),
        "signature-seller",
        "the seller holds no commitment entry",
    ),
    Corrupted(
        "the seller resolved another principal",
        _after_commit(
            _sql(
                "seller",
                "UPDATE assent SET principal_id = 'buyer-bearer'"
                " WHERE role = 'commitment' AND authentication_method = 'web_bot_auth'",
            )
        ),
        "signature-seller",
        "the seller resolved buyer-bearer, not buyer-wba",
    ),
    Corrupted(
        "the seller recorded another method",
        _after_commit(
            _sql(
                "seller",
                "UPDATE assent SET authentication_method = 'bearer'"
                " WHERE role = 'commitment' AND authentication_method = 'web_bot_auth'",
            )
        ),
        "signature-seller",
        "the seller recorded bearer",
    ),
    Corrupted(
        "a bearer entry with evidence",
        _after_commit(
            _sql(
                "seller", "UPDATE assent SET evidence_id = 1 WHERE authentication_method = 'bearer'"
            )
        ),
        "bearer-seller",
        "a bearer commit has no signature evidence",
    ),
    Corrupted(
        "a signed entry without its request",
        _after_commit(
            _sql(
                "seller",
                "UPDATE assent SET evidence_id = NULL WHERE authentication_method = 'web_bot_auth'",
            )
        ),
        "signature-seller",
        "a signed commit keeps its request",
    ),
    Corrupted(
        "the seller's evidence from another origin",
        _after_commit(_sql("seller", "UPDATE signed_requests SET origin = ?", RESELLER)),
        "signature-seller",
        f"evidence from {RESELLER}",
    ),
    Corrupted(
        "the buyer's evidence from another origin",
        _after_commit(_sql("buyer", "UPDATE signed_responses SET origin = ?", RESELLER)),
        "signature-buyer",
        f"answer from {RESELLER}",
    ),
    Corrupted(
        "no agreed record",
        _after_commit(_sql("seller", "DELETE FROM agreed_records")),
        "signature-digest",
        "the seller holds 0 agreed records",
    ),
    Corrupted(
        "no buyer commit",
        _after_commit(_sql("buyer", "DELETE FROM commits")),
        "signature-digest",
        "the buyer holds no such commit",
    ),
    Corrupted(
        "the digest inputs differ",
        _after_commit(_sql("buyer", "UPDATE commits SET digest_input = CAST('{}' AS BLOB)")),
        "signature-digest",
        "the parties' digest inputs differ",
    ),
    Corrupted(
        "the same digest input that isn't the agreed record's",
        _after_commit(
            _sql("buyer", "UPDATE commits SET digest_input = CAST('{}' AS BLOB)"),
            _sql("seller", "UPDATE agreed_records SET digest_input = CAST('{}' AS BLOB)"),
        ),
        "signature-digest",
        "record_digest doesn't recompute from the digest input",
    ),
    Corrupted(
        "the seller's evidence covers no body",
        _after_commit(_request_signed_without_its_body),
        "signature-reverify",
        "the seller's evidence doesn't verify again",
    ),
    Corrupted(
        "the buyer's evidence is bound to nothing",
        _answer_bound_to_nothing,
        "signature-reverify",
        "the buyer's evidence doesn't verify again",
    ),
    Corrupted(
        "cfbot sees another origin",
        _cfbot_sees_the_reseller,
        "cloudflare",
        f"cfbot saw {RESELLER}",
    ),
]


@pytest.mark.parametrize("row", CORRUPTED, ids=lambda row: row.name)
def test_a_run_fails_when_the_parties_records_dont_add_up(
    stack: Stack, tmp_path: Path, row: Corrupted
) -> None:
    after = row.corrupt(stack)

    async def route(request: httpx.Request) -> httpx.Response:
        return after(request, await stack.runner_route(request))

    transport = httpx.MockTransport(route)
    report = asyncio.run(run_once(_settings(stack, tmp_path / "out"), transport=transport))
    failed = {s.id: s.detail for s in report.steps if not s.ok}
    assert failed.get(row.step) == f"{row.failure}: {row.detail}", failed


def test_a_cfbot_refusal_fails_the_cloudflare_step(stack: Stack, tmp_path: Path) -> None:
    stack.cfbot = lambda _: httpx.Response(403, json={"ok": False, "error": "signature-invalid"})
    report = _run(stack, tmp_path / "out")
    (cloudflare,) = [s for s in report.steps if s.id == "cloudflare"]
    assert cloudflare.detail == "CheckFailed: cfbot refused: 403 signature-invalid"
    assert [s.id for s in report.steps if not s.ok] == ["cloudflare"]


def test_each_agent_refuses_another_partys_operator_key(stack: Stack) -> None:
    """Each agent's controls take its own key only, so a run passes only when the runner
    sends each agent its own."""
    seller_key, buyer_key = SELLER_KEY, BUYER_KEY
    refused = ErrorBody(error="operator-key", detail="operator key required")
    with pytest.raises(ControlFailed) as failed:
        ControlClient(stack.seller, operator_key=buyer_key).call(
            ISSUE, IssueRequest(principal_id="buyer-wba")
        )
    assert (failed.value.status, failed.value.error) == (403, refused)
    with pytest.raises(ControlFailed) as failed:
        ControlClient(stack.buyer, operator_key=seller_key).call(KEYS, None)
    assert (failed.value.status, failed.value.error) == (403, refused)
    ControlClient(stack.seller, operator_key=seller_key).call(
        ISSUE, IssueRequest(principal_id="buyer-wba")
    )
    ControlClient(stack.buyer, operator_key=buyer_key).call(KEYS, None)


@pytest.mark.parametrize("name", ["SELLER_OPERATOR_KEY", "BUYER_OPERATOR_KEY"])
def test_the_runner_refuses_to_start_without_each_agents_operator_key(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv("SELLER_OPERATOR_KEY", "seller-key")
    monkeypatch.setenv("BUYER_OPERATOR_KEY", "buyer-key")
    monkeypatch.delenv(name)
    with pytest.raises(SettingsError, match=f"^{name}: "):
        main()


# What a report may hold


def test_public_headers_withhold_credentials_and_proxy_fields() -> None:
    shown = public_headers(
        [
            ("Signature-Input", 'sig1=("@method");tag="web-bot-auth"'),
            ("Authorization", "Bearer secret-token-value"),
            (OPERATOR_HEADER, "operator-secret"),
            ("X-Forwarded-For", "203.0.113.7"),
            ("Content-Digest", "sha-256=:abc=:"),
        ]
    )
    assert shown.lines == [
        ("signature-input", 'sig1=("@method");tag="web-bot-auth"'),
        ("content-digest", "sha-256=:abc=:"),
    ]
    assert shown.withheld == ["authorization", "x-forwarded-for", "x-operator-key"]


def _report(
    detail: str,
    *,
    started_at: str = "2026-11-07T00:00:00Z",
    directories: Parties[Directory | None] | None = None,
) -> Report:
    step = StepResult(id="cloudflare", group="cloudflare", title="X", ok=True, ms=1, detail=detail)
    return Report(started_at=started_at, ok=True, directories=directories, steps=[step])


def test_a_report_with_a_secret_is_refused() -> None:
    with pytest.raises(NotPublic):
        assert_public(_report("token is secret-token-value"), ["secret-token-value"])


def test_a_report_with_a_private_jwk_is_refused() -> None:
    leaked = Directory(
        url=f"{BUYER}/.well-known/http-message-signatures-directory",
        status=200,
        headers=public_headers([]),
        keys=[{"kty": "OKP", "x": "pub", "d": "private"}],
    )
    with pytest.raises(NotPublic):
        directories = Parties[Directory | None](seller=None, buyer=leaked, cfbot=None)
        assert_public(_report("a run", directories=directories), [])


def test_publish_writes_a_bare_failure_when_the_report_isnt_public(
    stack: Stack, tmp_path: Path
) -> None:
    settings = _settings(stack, tmp_path / "out")
    publish(settings, _report(f"leaks {TOKEN}"))
    latest = (tmp_path / "out" / "latest-run.json").read_text()
    assert TOKEN not in latest
    jsonschema.validate(json.loads(latest), SCHEMA)
    published = Report.model_validate_json(latest)
    assert published.ok is False
    assert [s.id for s in published.steps] == ["publish"]


def test_history_keeps_the_newest_runs_first(stack: Stack, tmp_path: Path) -> None:
    settings = _settings(stack, tmp_path / "out")
    for n in range(HISTORY + 2):
        publish(settings, _report(f"run {n}", started_at=f"t{n}"))
    runs = History.model_validate_json((tmp_path / "out" / "history.json").read_bytes()).runs
    assert len(runs) == HISTORY
    assert runs[0].started_at == f"t{HISTORY + 1}"
