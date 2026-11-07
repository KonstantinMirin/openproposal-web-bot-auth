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
from collections.abc import Iterator
from pathlib import Path

import httpx
import jsonschema
import pytest
from iab_agentic_primitives.web_bot_auth import Origin
from pydantic import SecretStr

from runner.main import publish, run_once
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
from tests.stack import BUYER, CFBOT, OPERATOR, SELLER, TOKEN, Stack

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


def _corrupt_after_commit(stack: Stack, path: Path, statement: str) -> httpx.MockTransport:
    """The runner's network, which changes a party's records once the buyer's commit answers."""

    async def route(request: httpx.Request) -> httpx.Response:
        response = await stack.runner_route(request)
        if request.url.path == "/operator/commit":
            db = sqlite3.connect(path)
            try:
                db.execute(statement)
                db.commit()
            finally:
                db.close()
        return response

    return httpx.MockTransport(route)


@pytest.mark.parametrize(
    ("corruption", "step", "detail"),
    [
        (
            ("buyer", "UPDATE commits SET digest_input = CAST('{}' AS BLOB)"),
            "signature-digest",
            "the parties' digest inputs differ",
        ),
        (
            ("seller", "UPDATE assent SET evidence_id = 1 WHERE authentication_method = 'bearer'"),
            "bearer-seller",
            "a bearer commit has no signature evidence",
        ),
    ],
    ids=["digest-inputs-differ", "bearer-entry-with-evidence"],
)
def test_a_run_fails_when_the_parties_records_dont_add_up(
    stack: Stack, tmp_path: Path, corruption: tuple[str, str], step: str, detail: str
) -> None:
    party, statement = corruption
    db = stack.buyer_dir / "buyer.db" if party == "buyer" else stack.seller_dir / "seller.db"
    transport = _corrupt_after_commit(stack, db, statement)
    report = asyncio.run(run_once(_settings(stack, tmp_path / "out"), transport=transport))
    failed = {s.id: s.detail for s in report.steps if not s.ok}
    assert failed.get(step) == f"CheckFailed: {detail}", failed


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
