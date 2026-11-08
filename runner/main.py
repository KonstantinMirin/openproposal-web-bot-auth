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
one `AsyncControlClient` per agent, so neither agent ever sees the other's key. It reads both
parties' databases from read-only mounts of their database volumes. It mounts
neither agent's key volume, so it holds no agent's signing key.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from functools import partial
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TypeVar

import httpx
from pydantic import ValidationError

from persistence.values import AuthMethod, Origin
from transport.client import AsyncControlClient
from transport.wba import Transport, http_client, tls_context

from .checks import Done
from .observe import LINE_ITEM, Observer, instant_of
from .report import (
    Directory,
    FlowRun,
    Group,
    History,
    NotPublic,
    Parties,
    Party,
    PathName,
    Report,
    Software,
    StepId,
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
class PathSteps:
    """The ids of one credential's steps, in the order they run."""

    issue: StepId
    commit: StepId
    seller: StepId
    buyer: StepId
    digest: StepId
    #: Verifying the kept messages again offline: only a signed run has both; None otherwise.
    reverify: StepId | None


@dataclass(frozen=True)
class CredentialPath:
    """One credential's run of the flow, as the report names it."""

    name: PathName
    method: AuthMethod
    principal: str
    label: str
    steps: PathSteps


SIGNATURE = CredentialPath(
    "signature",
    "web_bot_auth",
    "buyer-wba",
    "a Web Bot Auth signature",
    PathSteps(
        issue="signature-issue",
        commit="signature-commit",
        seller="signature-seller",
        buyer="signature-buyer",
        digest="signature-digest",
        reverify="signature-reverify",
    ),
)
BEARER = CredentialPath(
    "bearer",
    "bearer",
    "buyer-bearer",
    "a bearer token",
    PathSteps(
        issue="bearer-issue",
        commit="bearer-commit",
        seller="bearer-seller",
        buyer="bearer-buyer",
        digest="bearer-digest",
        reverify=None,
    ),
)
#: The step that fetches and verifies each party's directory.
DIRECTORY_STEPS: Mapping[Party, StepId] = {
    "seller": "directory-seller",
    "buyer": "directory-buyer",
    "cfbot": "directory-cfbot",
}


@dataclass
class Run:
    """One run: its steps, in order, each with its outcome and duration."""

    steps: list[StepResult] = field(default_factory=list)
    failed: set[StepId] = field(default_factory=set)

    async def step(
        self,
        id: StepId,
        group: Group,
        title: str,
        action: Action[T],
        *,
        needs: tuple[StepId, ...] = (),
    ) -> T | None:
        """Runs `action` unless a step it needs failed; records the outcome either way."""
        row = partial(StepResult, id=id, group=group, title=title)
        blocked = [n for n in needs if n in self.failed]
        if blocked:
            self._record(row(ok=False, ms=0, detail=f"skipped: {', '.join(blocked)} failed"))
            return None
        start = time.perf_counter()
        try:
            result = action()
            done = await result if isinstance(result, Awaitable) else result
        except Exception as e:  # noqa: BLE001 -- a stated non-defect: every failure is a step outcome
            self._record(row(ok=False, ms=_ms(start), detail=f"{type(e).__name__}: {e}"))
            return None
        self._record(row(ok=True, ms=_ms(start), detail=done.detail))
        return done.value

    def _record(self, step: StepResult) -> None:
        if not step.ok:
            self.failed.add(step.id)
        self.steps.append(step)


def _ms(start: float) -> int:
    return round((time.perf_counter() - start) * 1000)


async def _path(run: Run, observer: Observer, path: CredentialPath) -> FlowRun:
    """The flow with one credential: issue, commit, and what each party kept."""
    group, steps = path.name, path.steps
    issued = await run.step(
        steps.issue,
        group,
        f"Seller issues a fresh proposal to {path.principal}",
        partial(observer.issue, path.principal),
    )
    outcome = await run.step(
        steps.commit,
        group,
        f"Buyer reads and commits with {path.label}; both reach agreed",
        partial(observer.commit, issued, path.method),
        needs=(steps.issue,),
    )
    committed = (steps.commit,)
    seller = await run.step(
        steps.seller,
        group,
        "Seller's boundary resolved the stored principal",
        partial(observer.seller_side, outcome, path.method, path.principal),
        needs=committed,
    )
    buyer = await run.step(
        steps.buyer,
        group,
        "Buyer verified the seller's signed answer and kept it",
        partial(observer.buyer_side, outcome),
        needs=committed,
    )
    digest = await run.step(
        steps.digest,
        group,
        "Both parties computed the same record_digest",
        partial(observer.same_digest, outcome),
        needs=committed,
    )
    reverify = None
    if steps.reverify is not None:
        reverify = await run.step(
            steps.reverify,
            group,
            "Both kept messages verify again, offline",
            partial(observer.reverify, seller, buyer),
            needs=(steps.seller, steps.buyer),
        )
    return FlowRun(
        proposal_id=None if issued is None else issued.proposal_id,
        outcome=outcome,
        seller=seller,
        buyer=buyer,
        digest=digest,
        reverify=reverify,
    )


async def _directory(
    run: Run, observer: Observer, party: Party, origin: Origin
) -> Directory | None:
    return await run.step(
        DIRECTORY_STEPS[party],
        "directory",
        f"Fetch and verify the {party}'s key directory",
        partial(observer.directory, origin),
    )


async def run_once(settings: RunnerSettings, *, transport: Transport | None = None) -> Report:
    """One run of every step. Never raises: a failure is a step outcome.

    `transport` answers in place of the network, for tests.
    """
    run, started = Run(), time.time()
    async with (
        httpx.AsyncClient(timeout=60, transport=transport) as control,
        http_client(tls_context(settings.ca_bundle), timeout=10, transport=transport) as web,
    ):
        seller = AsyncControlClient(control, settings.seller_control, settings.seller_operator_key)
        buyer = AsyncControlClient(control, settings.buyer_control, settings.buyer_operator_key)
        observer = Observer(settings, seller=seller, buyer=buyer, web=web)
        origins = Parties[Origin](
            seller=settings.peer_seller_origin,
            buyer=settings.peer_buyer_origin,
            cfbot=settings.peer_cfbot_origin,
        )
        directories = Parties[Directory | None](
            seller=await _directory(run, observer, "seller", origins.seller),
            buyer=await _directory(run, observer, "buyer", origins.buyer),
            cfbot=await _directory(run, observer, "cfbot", origins.cfbot),
        )
        signature = await _path(run, observer, SIGNATURE)
        bearer = await _path(run, observer, BEARER)
        cloudflare = await run.step(
            "cloudflare",
            "cloudflare",
            "cfbot, on Cloudflare's web-bot-auth, verifies the buyer's signature",
            observer.cloudflare,
        )
    return Report(
        started_at=instant_of(started),
        finished_at=instant_of(time.time()),
        duration_ms=round((time.time() - started) * 1000),
        ok=not run.failed,
        origins=origins,
        software=Software(
            iab_agentic_primitives=_version("iab-agentic-primitives"),
            openproposal_sdk=_version("openproposal-sdk"),
        ),
        line_item_ids=[LINE_ITEM],
        directories=directories,
        signature=signature,
        bearer=bearer,
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
