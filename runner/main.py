"""The live runner: the whole offer flow against the deployed agents, on a schedule.

Every `RUN_INTERVAL` seconds (900 by default; `0` runs once), the runner:

1. fetches and verifies each agent's key directory over public HTTPS;
2. has the seller issue a fresh proposal to its signing buyer, and the buyer
   commit to it with a Web Bot Auth signature;
3. reads what each party kept: the signed request as each side holds it, the
   seller's signed and bound answer, the directory each side verified against,
   and both sides' `record_digest`; then verifies that evidence again offline;
4. runs the same flow with the bearer buyer's token;
5. has cfbot, on Cloudflare's library, verify a request the buyer signs.

It writes `latest-run.json` (a `Report`, runner/report.py) and `history.json`
to `OUT_DIR`, which the explainer site serves.

The runner reaches each agent's own controls inside the compose network
(`SELLER_CONTROL`, `BUYER_CONTROL`) with that agent's own operator key, through
one client per agent, so neither agent ever sees the other's key. It reads both
parties' databases from read-only mounts of their database volumes. It mounts
neither agent's key volume, so it holds no agent's signing key.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TypeVar

import httpx
from pydantic import SecretStr, ValidationError

from persistence.values import AuthMethod
from transport.control import OPERATOR_HEADER
from transport.wba import Transport, http_client, tls_context

from .checks import Done
from .observe import LINE_ITEM, Observer, instant_of
from .report import (
    Directory,
    FlowRun,
    History,
    NotPublic,
    Report,
    StepResult,
    assert_public,
    updated_history,
    withheld,
)
from .settings import RunnerSettings

log = logging.getLogger("runner")
T = TypeVar("T")

#: A step's action: sync or async, it returns its value and its detail line.
Action = Callable[[], Done[T] | Awaitable[Done[T]]]


@dataclass(frozen=True)
class CredentialPath:
    """One credential's run of the flow, as the report names it."""

    name: str
    method: AuthMethod
    principal: str
    label: str
    #: Whether the run verifies the kept messages again offline: only a signed one has both.
    reverify: bool


PATHS = (
    CredentialPath("signature", "web_bot_auth", "buyer-wba", "a Web Bot Auth signature", True),
    CredentialPath("bearer", "bearer", "buyer-bearer", "a bearer token", False),
)


@dataclass
class Run:
    """One run: its steps, in order, each with its outcome and duration."""

    steps: list[StepResult] = field(default_factory=list)
    failed: set[str] = field(default_factory=set)

    async def step(
        self, id: str, title: str, action: Action[T], *, needs: tuple[str, ...] = ()
    ) -> T | None:
        """Runs `action` unless a step it needs failed; records the outcome either way."""
        blocked = [n for n in needs if n in self.failed]
        if blocked:
            self._record(id, title, 0, f"skipped: {', '.join(blocked)} failed", ok=False)
            return None
        start = time.perf_counter()
        try:
            result = action()
            done = await result if isinstance(result, Awaitable) else result
        except Exception as e:  # noqa: BLE001 -- a stated non-defect: every failure is a step outcome
            self._record(id, title, _ms(start), f"{type(e).__name__}: {e}", ok=False)
            return None
        self._record(id, title, _ms(start), done.detail, ok=True)
        return done.value

    def _record(self, id: str, title: str, ms: int, detail: str, *, ok: bool) -> None:
        if not ok:
            self.failed.add(id)
        self.steps.append(StepResult(id=id, title=title, ok=ok, ms=ms, detail=detail))


def _ms(start: float) -> int:
    return round((time.perf_counter() - start) * 1000)


async def _path(run: Run, observer: Observer, path: CredentialPath) -> FlowRun:
    """The flow with one credential: issue, commit, and what each party kept."""
    name = path.name
    issued = await run.step(
        f"{name}-issue",
        f"Seller issues a fresh proposal to {path.principal}",
        partial(observer.issue, path.principal),
    )
    outcome = await run.step(
        f"{name}-commit",
        f"Buyer reads and commits with {path.label}; both reach agreed",
        partial(observer.commit, issued, path.method),
        needs=(f"{name}-issue",),
    )
    committed = (f"{name}-commit",)
    seller = await run.step(
        f"{name}-seller",
        "Seller's boundary resolved the stored principal",
        partial(observer.seller_side, outcome, path.method, path.principal),
        needs=committed,
    )
    buyer = await run.step(
        f"{name}-buyer",
        "Buyer verified the seller's signed answer and kept it",
        partial(observer.buyer_side, outcome),
        needs=committed,
    )
    digest = await run.step(
        f"{name}-digest",
        "Both parties computed the same record_digest",
        partial(observer.same_digest, outcome),
        needs=committed,
    )
    reverify = None
    if path.reverify:
        reverify = await run.step(
            f"{name}-reverify",
            "Both kept messages verify again, offline",
            partial(observer.reverify, seller, buyer),
            needs=(f"{name}-seller", f"{name}-buyer"),
        )
    return FlowRun(
        proposal_id=None if issued is None else issued.proposal_id,
        outcome=outcome,
        seller=seller,
        buyer=buyer,
        digest=digest,
        reverify=reverify,
    )


def _control(url: httpx.URL, key: SecretStr, transport: Transport | None) -> httpx.AsyncClient:
    """A client for one agent's controls, which carries that agent's operator key only."""
    headers = {OPERATOR_HEADER: key.get_secret_value()}
    return httpx.AsyncClient(base_url=url, timeout=60, headers=headers, transport=transport)


async def run_once(settings: RunnerSettings, *, transport: Transport | None = None) -> Report:
    """One run of every step. Never raises: a failure is a step outcome.

    `transport` answers in place of the network, for tests.
    """
    run, started = Run(), time.time()
    async with (
        _control(settings.seller_control, settings.seller_operator_key, transport) as seller,
        _control(settings.buyer_control, settings.buyer_operator_key, transport) as buyer,
        http_client(tls_context(settings.ca_bundle), timeout=10, transport=transport) as web,
    ):
        observer = Observer(settings, seller=seller, buyer=buyer, web=web)
        parties = {
            "seller": settings.peer_seller_origin,
            "buyer": settings.peer_buyer_origin,
            "cfbot": settings.peer_cfbot_origin,
        }
        directories: dict[str, Directory | None] = {}
        for party, origin in parties.items():
            directories[party] = await run.step(
                f"directory-{party}",
                f"Fetch and verify the {party}'s key directory",
                partial(observer.directory, origin),
            )
        flows = {path.name: await _path(run, observer, path) for path in PATHS}
        cloudflare = await run.step(
            "cloudflare",
            "cfbot, on Cloudflare's web-bot-auth, verifies the buyer's signature",
            observer.cloudflare,
        )
    return Report(
        started_at=instant_of(started),
        finished_at=instant_of(time.time()),
        duration_ms=round((time.time() - started) * 1000),
        ok=not run.failed,
        origins=parties,
        software={name: _version(name) for name in ("iab-agentic-primitives", "openproposal-sdk")},
        line_item_ids=[LINE_ITEM],
        directories=directories,
        signature=flows["signature"],
        bearer=flows["bearer"],
        cloudflare=cloudflare,
        steps=run.steps,
    )


def _version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


# Publishing


def _write(path: Path, text: str) -> None:
    """Replaces `path` whole, so the site never reads a half-written file."""
    pending = path.with_suffix(".json.new")
    pending.write_text(text, encoding="utf-8")
    pending.chmod(0o644)
    pending.replace(path)


def _previous(history_file: Path) -> History:
    try:
        return History.model_validate_json(history_file.read_bytes())
    except (OSError, ValidationError):
        return History(runs=[])


def publish(settings: RunnerSettings, report: Report) -> None:
    """Writes latest-run.json and history.json, or a bare failure when the report isn't public."""
    try:
        text = assert_public(report, settings.secrets)
    except NotPublic as e:
        report = withheld(report, e)
        text = report.model_dump_json(indent=1)
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    history_file = settings.out_dir / "history.json"
    history = updated_history(_previous(history_file).runs, report)
    _write(settings.out_dir / "latest-run.json", text)
    _write(history_file, history.model_dump_json(indent=1))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    settings = RunnerSettings.from_env()
    while True:
        report = asyncio.run(run_once(settings))
        publish(settings, report)
        failed = " ".join(s.id for s in report.steps if not s.ok)
        verdict = "pass" if report.ok else "FAIL"
        log.info("%s %s %s ms %s", report.started_at, verdict, report.duration_ms, failed)
        if settings.interval <= 0:
            sys.exit(0 if report.ok else 1)
        time.sleep(max(1.0, settings.interval - (report.duration_ms or 0) / 1000))


if __name__ == "__main__":
    main()
