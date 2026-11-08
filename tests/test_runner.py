"""The live runner, run once against both agents in process (tests/stack.py).

The runner reaches the agents' controls and their directories through the
stack's network, and reads both parties' databases read-only through their
read models. The report it publishes validates against the committed schema
(site/report.schema.json), holds public data only, and keeps a short history.
"""

from __future__ import annotations

import asyncio
import json
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
    RequestSigner,
    ResponseSigner,
)
from pydantic import SecretStr

from persistence.values import Origin
from runner.main import main, publish, run_once
from runner.report import (
    HISTORY,
    NotPublic,
    Report,
    StepResult,
    assert_public,
    public_headers,
    schema,
)
from runner.settings import RunnerSettings
from tests.stack import BUYER, CFBOT, OPERATOR, RESELLER, SELLER, TOKEN, Stack

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "site" / "report.schema.json"
SCHEMA = json.loads(SCHEMA_FILE.read_text())


def _settings(stack: Stack, out: Path) -> RunnerSettings:
    return RunnerSettings(
        seller=Origin.parse(SELLER),
        buyer=Origin.parse(BUYER),
        cfbot=Origin.parse(CFBOT),
        seller_control="http://seller:8000",
        buyer_control="http://buyer:8000",
        seller_db=str(stack.seller_dir / "seller.db"),
        buyer_db=str(stack.buyer_dir / "buyer.db"),
        out_dir=out,
        interval=0,
        operator_key=SecretStr(OPERATOR["X-Operator-Key"]),
        secrets=(OPERATOR["X-Operator-Key"], TOKEN),
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

    publish(_settings(stack, tmp_path / "out"), report)
    published = json.loads((tmp_path / "out" / "latest-run.json").read_text())
    jsonschema.validate(published, SCHEMA)
    assert published["format"] == 2 and published["ok"] is True
    history = json.loads((tmp_path / "out" / "history.json").read_text())
    assert history["runs"][0] == {
        "started_at": report.started_at,
        "ok": True,
        "duration_ms": report.duration_ms,
        "failed": [],
    }


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
    for later in ("seller", "buyer", "digest"):
        step = outcome[f"signature-{later}"]
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
            if request.url.path == "/operator/commit":
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
    sent = HTTPRequest("GET", f"{SELLER}/proposals/demo-wba-1", [], b"")
    signed = RequestSigner(stack.buyer_keys.active(), BUYER).sign(sent)
    headers = json.dumps([list(line) for line in signed.headers])
    with _writable(_db(stack, "seller")) as db:
        db.execute(
            "UPDATE signed_requests SET method = 'GET', url = ?, headers = ?, body = ?"
            " WHERE id = (SELECT evidence_id FROM assent"
            " WHERE role = 'commitment' AND authentication_method = 'web_bot_auth')",
            (sent.url, headers, b""),
        )


def _answer_bound_to_nothing(stack: Stack) -> None:
    """Tamper: the buyer's kept answer to the signed commit becomes one the seller signed, with
    its own key, for the request with its signature taken off, so it is bound to nothing."""
    with _writable(_db(stack, "buyer")) as db:
        db.row_factory = sqlite3.Row
        kept = db.execute(
            "SELECT r.id, r.status, r.body, q.id AS request_id, q.method, q.url, q.headers,"
            " q.body AS request_body FROM signed_responses r"
            " JOIN signed_requests q ON q.id = r.request_id WHERE q.keyid IS NOT NULL"
        ).fetchone()
        unsigned = [
            (name, value)
            for name, value in json.loads(kept["headers"])
            if not name.lower().startswith("signature")
        ]
        request = HTTPRequest(kept["method"], kept["url"], unsigned, kept["request_body"])
        answer = HTTPResponse(
            kept["status"], [("content-type", "application/json")], kept["body"], request
        )
        signed = ResponseSigner(stack.seller_key, SELLER).sign(answer)
        db.execute(
            "UPDATE signed_requests SET headers = ? WHERE id = ?",
            (json.dumps([list(line) for line in unsigned]), kept["request_id"]),
        )
        db.execute(
            "UPDATE signed_responses SET headers = ? WHERE id = ?",
            (json.dumps([list(line) for line in signed.headers]), kept["id"]),
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
        if request.url.path != "/operator/commit":
            return response
        outcome = json.loads(response.read())
        if outcome.get("authentication_method") == "web_bot_auth":
            outcome["authentication_method"] = "bearer"
        return httpx.Response(response.status_code, json=outcome)

    return after


def _cfbot_sees_the_reseller(stack: Stack) -> After:
    """cfbot verifies the buyer's signature as another origin's."""
    stack.cfbot = lambda _: httpx.Response(
        200, json={"ok": True, "identity": RESELLER, "verifier": "web-bot-auth (test)"}
    )
    return lambda _request, response: response


@dataclass(frozen=True)
class Corrupted:
    """A run whose network or records don't add up, and the check that catches it."""

    name: str
    corrupt: Corruption
    step: str
    detail: str


CORRUPTED = [
    Corrupted(
        "the seller fails to issue",
        _answered("/operator/issue", 500),
        "signature-issue",
        "issue returned 500: down",
    ),
    Corrupted(
        "the buyer fails to commit",
        _answered("/operator/commit", 500),
        "signature-commit",
        "commit returned 500: down",
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
        _after_commit(_answer_bound_to_nothing),
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
    assert failed.get(row.step) == f"CheckFailed: {row.detail}", failed


def test_a_cfbot_refusal_fails_the_cloudflare_step(stack: Stack, tmp_path: Path) -> None:
    stack.cfbot = lambda _: httpx.Response(403, json={"ok": False, "reason": "signature-invalid"})
    report = _run(stack, tmp_path / "out")
    (cloudflare,) = [s for s in report.steps if s.id == "cloudflare"]
    assert not cloudflare.ok and "cfbot refused: 403" in (cloudflare.detail or "")
    assert [s.id for s in report.steps if not s.ok] == ["cloudflare"]


def test_the_runner_refuses_to_start_without_an_operator_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPERATOR_KEY", raising=False)
    with pytest.raises(SystemExit, match="OPERATOR_KEY is not set"):
        main()


# What a report may hold


def test_public_headers_withhold_credentials_and_proxy_fields() -> None:
    shown = public_headers(
        [
            ("Signature-Input", 'sig1=("@method");tag="web-bot-auth"'),
            ("Authorization", "Bearer secret-token-value"),
            ("X-Operator-Key", "operator-secret"),
            ("X-Forwarded-For", "203.0.113.7"),
            ("Content-Digest", "sha-256=:abc=:"),
        ]
    )
    assert shown.lines == [
        ("signature-input", 'sig1=("@method");tag="web-bot-auth"'),
        ("content-digest", "sha-256=:abc=:"),
    ]
    assert shown.withheld == ["authorization", "x-forwarded-for", "x-operator-key"]


def _report(detail: str) -> Report:
    step = StepResult(id="x", title="X", ok=True, ms=1, detail=detail)
    return Report(started_at="2026-11-07T00:00:00Z", ok=True, steps=[step])


def test_a_report_with_a_secret_is_refused() -> None:
    with pytest.raises(NotPublic):
        assert_public(_report("token is secret-token-value"), ["secret-token-value"])


def test_a_report_with_a_private_jwk_is_refused(stack: Stack, tmp_path: Path) -> None:
    report = _run(stack, tmp_path / "out")
    assert report.signature is not None and report.signature.seller is not None
    directory = report.signature.seller.directory
    assert directory is not None
    leaked = directory.model_copy(update={"keys": [{"kty": "OKP", "x": "pub", "d": "private"}]})
    seller = report.signature.seller.model_copy(update={"directory": leaked})
    signature = report.signature.model_copy(update={"seller": seller})
    with pytest.raises(NotPublic):
        assert_public(report.model_copy(update={"signature": signature}), [])


def test_publish_writes_a_bare_failure_when_the_report_isnt_public(
    stack: Stack, tmp_path: Path
) -> None:
    settings = _settings(stack, tmp_path / "out")
    publish(settings, _report(f"leaks {TOKEN}"))
    latest = (tmp_path / "out" / "latest-run.json").read_text()
    assert TOKEN not in latest
    published = json.loads(latest)
    jsonschema.validate(published, SCHEMA)
    assert published["ok"] is False
    assert [s["id"] for s in published["steps"]] == ["publish"]


def test_history_keeps_the_newest_runs_first(stack: Stack, tmp_path: Path) -> None:
    settings = _settings(stack, tmp_path / "out")
    for n in range(HISTORY + 2):
        publish(settings, _report(f"run {n}").model_copy(update={"started_at": f"t{n}"}))
    runs = json.loads((tmp_path / "out" / "history.json").read_text())["runs"]
    assert len(runs) == HISTORY
    assert runs[0]["started_at"] == f"t{HISTORY + 1}"
