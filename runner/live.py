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

It writes `latest-run.json` and `history.json` (the last `HISTORY` runs) to
`OUT_DIR`, which the explainer site serves. The report holds only public data:
`public_headers` withholds credentials and proxy headers, and `assert_public`
refuses to write a report that holds the operator key, the bearer token, or a
private JWK.

The runner reaches the agents' own controls inside the compose network
(`SELLER_CONTROL`, `BUYER_CONTROL`) with `OPERATOR_KEY`, and reads both
parties' databases from read-only mounts. It holds no agent's signing key.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import time
from collections.abc import Awaitable, Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import httpx
from iab_agentic_primitives.web_bot_auth import (
    DirectoryResponse,
    HTTPRequest,
    HTTPResponse,
    MemoryNonceStore,
    Origin,
    RequestVerifier,
    ResponseVerifier,
    ServerIdentity,
    StaticKeyResolver,
    parse_directory_response,
)

from persistence.evidence import RESPONSE_WITH_REQUEST
from protocol.record import digest_of, sha256_hex
from protocol.values import instant
from shared.auth import AuthMethod
from shared.control import OUTCOME, Agreed, CloudflareCheck, CommitTrigger, Issued, IssueRequest
from shared.operator import HEADER as OPERATOR_HEADER
from shared.wba import http_client, tls_context

from .settings import RunnerSettings

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
HISTORY = 20
LINE_ITEM = "business-daily-display"

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
# ── Sanitizing ────────────────────────────────────────────────────────────


def public_headers(lines: list[tuple[str, str]] | list[list[str]]) -> dict[str, Any]:
    """Field lines in order, without the withheld fields, and the names of those withheld."""
    shown, withheld = [], []
    for name, value in lines:
        if name.lower() in WITHHELD:
            withheld.append(name.lower())
        else:
            shown.append([name.lower(), value])
    return {"lines": shown, "withheld": sorted(set(withheld))}


def _private_jwk(value: Any) -> bool:
    if isinstance(value, dict):
        if "kty" in value and "d" in value:
            return True
        return any(_private_jwk(v) for v in value.values())
    if isinstance(value, list):
        return any(_private_jwk(v) for v in value)
    return False


class NotPublic(Exception):
    """The report holds something that must not be published."""


def assert_public(report: dict[str, Any], secrets: Sequence[str]) -> str:
    """The report as JSON text; raises `NotPublic` when it holds a secret or a private key."""
    text = json.dumps(report, indent=1, ensure_ascii=False)
    for secret in secrets:
        if secret and secret in text:
            raise NotPublic("a configured secret appears in the report")
    if _private_jwk(report):
        raise NotPublic("a private JWK appears in the report")
    return text


def _body(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return data.decode("utf-8", "replace")


def _directory_view(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """A stored directory fetch, as the party kept it."""
    if row is None:
        return None
    body = _body(row["body"])
    return {
        "url": row["url"],
        "status": row["status"],
        "fetched_at": _instant(row["fetched_at"]) if row["fetched_at"] else None,
        "headers": public_headers(json.loads(row["headers"])),
        "keys": [_public_key(k) for k in body.get("keys", [])] if isinstance(body, dict) else [],
        "sha256": sha256_hex(row["body"]),
    }


def _public_key(jwk: dict[str, Any]) -> dict[str, Any]:
    return {k: jwk[k] for k in ("kid", "kty", "crv", "x", "use", "alg") if k in jwk}


def _instant(seconds: float) -> str:
    return instant(datetime.fromtimestamp(seconds, UTC))


# ── Steps ─────────────────────────────────────────────────────────────────


class Run:
    """One run: its steps, in order, each with its outcome and duration."""

    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []
        self.failed: set[str] = set()

    async def step(
        self,
        id: str,
        title: str,
        action: Callable[[], Awaitable[Any]],
        *,
        needs: tuple[str, ...] = (),
    ) -> Any:
        """Runs `action` unless a step it needs failed; records the outcome either way."""
        blocked = [n for n in needs if n in self.failed]
        if blocked:
            self.failed.add(id)
            self.steps.append(
                {
                    "id": id,
                    "title": title,
                    "ok": False,
                    "ms": 0,
                    "detail": f"skipped: {', '.join(blocked)} failed",
                }
            )
            return None
        start = time.perf_counter()
        try:
            result = await action()
        except Exception as e:  # noqa: BLE001 - every failure is a step outcome
            self.failed.add(id)
            detail, result = f"{type(e).__name__}: {e}", None
        else:
            detail = result.pop("detail", None) if isinstance(result, dict) else None
        ms = round((time.perf_counter() - start) * 1000)
        self.steps.append(
            {"id": id, "title": title, "ok": id not in self.failed, "ms": ms, "detail": detail}
        )
        return result


class Check(Exception):
    """A step's expectation didn't hold."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise Check(message)


@contextmanager
def _database(path: str) -> Iterator[sqlite3.Connection]:
    """A party's database, read-only."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def _stored_keys(db: sqlite3.Connection, digest: str, origin: Origin) -> StaticKeyResolver:
    """The keys of a stored directory, after the library verifies the stored bytes again."""
    row = db.execute("SELECT * FROM directories WHERE digest = ?", (digest,)).fetchone()
    headers = [tuple(line) for line in json.loads(row["headers"])]
    fetched_at = int(row["fetched_at"])
    response = DirectoryResponse(row["url"], row["status"], headers, row["body"], fetched_at)
    directory = parse_directory_response(response, origin.host, fetched_at)
    return StaticKeyResolver({origin: directory.keys})


class Flow:
    """The steps of one run, against one deployment."""

    def __init__(
        self, config: RunnerSettings, control: httpx.AsyncClient, web: httpx.AsyncClient
    ) -> None:
        #: `control` reaches the agents' own controls; `web` fetches over public HTTPS.
        self.config, self.control, self.web = config, control, web

    async def directory(self, origin: Origin) -> dict[str, Any]:
        """Fetches the origin's directory as a verifier does, and verifies it with the library."""
        url = origin.directory_url
        response = await self.web.get(url, headers={"Accept-Encoding": "identity"})
        lines = response.headers.multi_items()
        now = int(time.time())
        fetched = DirectoryResponse(url, response.status_code, lines, response.content, now)
        directory = parse_directory_response(fetched, origin.host, now)
        keys = list(directory.keys)
        body = _body(response.content)
        return {
            "detail": f"{len(keys)} key(s), signed by each: {', '.join(keys)}",
            "url": url,
            "status": response.status_code,
            "headers": public_headers(lines),
            "keys": [_public_key(k) for k in body.get("keys", [])],
            "expires": _instant(directory.expires),
        }

    async def issue(self, principal_id: str) -> dict[str, Any]:
        response = await self.control.post(
            f"{self.config.seller_control}/operator/issue",
            json=IssueRequest(principal_id=principal_id).model_dump(),
        )
        expect(
            response.status_code == 200, f"issue returned {response.status_code}: {response.text}"
        )
        issued = Issued.model_validate_json(response.content)
        return {"detail": issued.proposal_id, **issued.model_dump()}

    async def commit(self, proposal_id: str, credential: AuthMethod) -> dict[str, Any]:
        trigger = CommitTrigger(
            seller=str(self.config.seller),
            proposal_id=proposal_id,
            line_item_ids=[LINE_ITEM],
            credential=credential,
        )
        response = await self.control.post(
            f"{self.config.buyer_control}/operator/commit", json=trigger.model_dump()
        )
        expect(
            response.status_code == 200, f"commit returned {response.status_code}: {response.text}"
        )
        outcome = OUTCOME.validate_json(response.content)
        if not isinstance(outcome, Agreed):
            raise Check(f"{outcome.state}: {outcome.model_dump_json()}")
        expect(outcome.authentication_method == credential, "the buyer used another credential")
        return {
            "detail": f"agreed, record_digest {outcome.record_digest}",
            "outcome": outcome.model_dump(mode="json"),
        }

    async def seller_view(self, proposal_id: str, credential: str, principal_id: str) -> dict:
        """What the seller's boundary resolved, and the signed request it kept."""
        with _database(self.config.seller_db) as db:
            entry = db.execute(
                "SELECT * FROM assent WHERE proposal_id = ? AND role = 'commitment'", (proposal_id,)
            ).fetchone()
            expect(entry is not None, "the seller holds no commitment entry")
            expect(
                entry["principal_id"] == principal_id,
                f"the seller resolved {entry['principal_id']}, not {principal_id}",
            )
            expect(
                entry["authentication_method"] == credential,
                f"the seller recorded {entry['authentication_method']}",
            )
            view: dict[str, Any] = {
                "principal_id": entry["principal_id"],
                "authentication_method": entry["authentication_method"],
                "attributed": bool(entry["attributed"]),
                "request": None,
                "directory": None,
            }
            if credential == "bearer":
                expect(entry["evidence_id"] is None, "a bearer commit has no signature evidence")
                view["detail"] = f"resolved {principal_id} by token hash; no signature evidence"
                return view
            evidence = db.execute(
                "SELECT * FROM signed_requests WHERE id = ?", (entry["evidence_id"],)
            ).fetchone()
            expect(
                evidence["origin"] == str(self.config.buyer), f"evidence from {evidence['origin']}"
            )
            view["request"] = {
                "method": evidence["method"],
                "url": evidence["url"],
                "keyid": evidence["keyid"],
                "headers": public_headers(json.loads(evidence["headers"])),
                "body": _body(evidence["body"]),
            }
            view["directory"] = _directory_view(
                db.execute(
                    "SELECT * FROM directories WHERE digest = ?", (evidence["directory_digest"],)
                ).fetchone()
            )
            view["evidence_id"], view["directory_digest"] = (
                evidence["id"],
                evidence["directory_digest"],
            )
            view["detail"] = (
                f"resolved {principal_id} from origin {evidence['origin']}, "
                f"keyid {evidence['keyid']}"
            )
            return view

    async def buyer_view(self, outcome: dict[str, Any]) -> dict[str, Any]:
        """The request as the buyer sent it, and the seller's signed answer as it arrived."""
        with _database(self.config.buyer_db) as db:
            evidence = db.execute(RESPONSE_WITH_REQUEST, (outcome["evidence_id"],)).fetchone()
            expect(evidence is not None, "the buyer kept no evidence")
            expect(
                evidence["origin"] == str(self.config.seller), f"answer from {evidence['origin']}"
            )
            directory = _directory_view(
                db.execute(
                    "SELECT * FROM directories WHERE digest = ?", (evidence["directory_digest"],)
                ).fetchone()
            )
            request_headers = public_headers(json.loads(evidence["request_headers"]))
            if outcome["authentication_method"] == "bearer":
                # The request carried the token; the buyer's evidence never stores it.
                request_headers["withheld"] = sorted(
                    {*request_headers["withheld"], "authorization"}
                )
            return {
                "detail": f"kept the seller's signed answer, keyid {evidence['keyid']}",
                "evidence_id": evidence["id"],
                "request": {
                    "method": evidence["request_method"],
                    "url": evidence["request_url"],
                    "keyid": outcome.get("keyid"),
                    "headers": request_headers,
                    "body": _body(evidence["request_body"]),
                },
                "response": {
                    "status": evidence["status"],
                    "keyid": evidence["keyid"],
                    "headers": public_headers(json.loads(evidence["headers"])),
                    "body": _body(evidence["body"]),
                },
                "directory": directory,
            }

    async def same_digest(self, proposal_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
        """Both parties hold the same digest input, and it hashes to the agreed record_digest."""
        with _database(self.config.seller_db) as seller, _database(self.config.buyer_db) as buyer:
            agreed = seller.execute(
                "SELECT * FROM agreed_records WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            bought = buyer.execute(
                "SELECT * FROM commits WHERE id = ?", (outcome["commit_id"],)
            ).fetchone()
        expect(agreed is not None, "the seller holds no agreed record")
        expect(
            bytes(agreed["digest_input"]) == bytes(bought["digest_input"]),
            "the parties' digest inputs differ",
        )
        digest = digest_of(bought["digest_input"])
        expect(
            digest == agreed["record_digest"] == outcome["record_digest"],
            "record_digest doesn't recompute from the digest input",
        )
        return {
            "detail": f"both sides: {digest}",
            "record_digest": digest,
            "digest_input_bytes": len(bought["digest_input"]),
        }

    async def reverify(self, seller: dict[str, Any], buyer: dict[str, Any]) -> dict[str, Any]:
        """Verifies both kept messages again, offline, against the directory bytes each kept."""
        with _database(self.config.seller_db) as db:
            row = db.execute(
                "SELECT * FROM signed_requests WHERE id = ?", (seller["evidence_id"],)
            ).fetchone()
            again = await RequestVerifier(
                _stored_keys(db, row["directory_digest"], self.config.buyer),
                identity=ServerIdentity.from_config(str(self.config.seller)),
                nonces=MemoryNonceStore(),
            ).verify(
                HTTPRequest(
                    row["method"],
                    row["url"],
                    [tuple(x) for x in json.loads(row["headers"])],
                    row["body"],
                )
            )
        expect(
            again.origin == self.config.buyer and again.body_covered,
            "the seller's evidence doesn't verify again",
        )
        with _database(self.config.buyer_db) as db:
            row = db.execute(RESPONSE_WITH_REQUEST, (buyer["evidence_id"],)).fetchone()
            sent = HTTPRequest(
                row["request_method"],
                row["request_url"],
                [tuple(x) for x in json.loads(row["request_headers"])],
                row["request_body"],
            )
            answered = await ResponseVerifier(
                _stored_keys(db, row["directory_digest"], self.config.seller)
            ).verify(
                HTTPResponse(
                    row["status"], [tuple(x) for x in json.loads(row["headers"])], row["body"], sent
                ),
                expected_origin=self.config.seller,
            )
        expect(
            answered.bound and answered.body_covered, "the buyer's evidence doesn't verify again"
        )
        return {
            "detail": "the signed request and the bound answer both verify from stored bytes",
            "request_components": list(again.components),
            "response_components": list(answered.components),
            "response_bound": answered.bound,
        }

    async def cloudflare(self) -> dict[str, Any]:
        response = await self.control.post(f"{self.config.buyer_control}/operator/cloudflare-check")
        expect(response.status_code == 200, f"cloudflare-check returned {response.status_code}")
        check = CloudflareCheck.model_validate_json(response.content)
        verdict = check.verdict
        expect(
            check.status == 200 and isinstance(verdict, dict) and verdict.get("ok") is True,
            f"cfbot refused: {verdict}",
        )
        assert isinstance(verdict, dict)  # noqa: S101 -- narrowed by the check above
        expect(verdict.get("identity") == str(self.config.buyer), f"cfbot saw {verdict}")
        return {
            "detail": f"{verdict.get('verifier')} accepted {verdict.get('identity')}",
            "verdict": verdict,
        }


async def run_once(config: RunnerSettings) -> dict[str, Any]:
    """One run of every step. Never raises: a failure is a step outcome."""
    run, started = Run(), time.time()
    report: dict[str, Any] = {
        "format": 1,
        "started_at": _instant(started),
        "origins": {
            "seller": str(config.seller),
            "buyer": str(config.buyer),
            "cfbot": str(config.cfbot),
        },
        "software": {
            name: _version(name) for name in ("iab-agentic-primitives", "openproposal-sdk")
        },
        "line_item_ids": [LINE_ITEM],
    }
    key = "" if config.operator_key is None else config.operator_key.get_secret_value()
    async with (
        httpx.AsyncClient(timeout=60, headers={OPERATOR_HEADER: key}) as control,
        http_client(tls_context(config.ca_bundle), timeout=10) as web,
    ):
        flow = Flow(config, control, web)
        report["directories"] = {}
        for party, origin in (
            ("seller", config.seller),
            ("buyer", config.buyer),
            ("cfbot", config.cfbot),
        ):
            report["directories"][party] = await run.step(
                f"directory-{party}",
                f"Fetch and verify the {party}'s key directory",
                lambda origin=origin: flow.directory(origin),
            )

        paths: tuple[tuple[str, AuthMethod, str], ...] = (
            ("signature", "web_bot_auth", "buyer-wba"),
            ("bearer", "bearer", "buyer-bearer"),
        )
        for path, credential, principal in paths:
            label = "a Web Bot Auth signature" if path == "signature" else "a bearer token"
            issued = await run.step(
                f"{path}-issue",
                f"Seller issues a fresh proposal to {principal}",
                lambda principal=principal: flow.issue(principal),
            )
            proposal_id = issued["proposal_id"] if issued else None
            committed = await run.step(
                f"{path}-commit",
                f"Buyer reads and commits with {label}; both reach agreed",
                lambda p=proposal_id, c=credential: flow.commit(p, c),
                needs=(f"{path}-issue",),
            )
            outcome = committed["outcome"] if committed else None
            seller = await run.step(
                f"{path}-seller",
                "Seller's boundary resolved the stored principal",
                lambda p=proposal_id, c=credential, who=principal: flow.seller_view(p, c, who),
                needs=(f"{path}-commit",),
            )
            buyer = await run.step(
                f"{path}-buyer",
                "Buyer verified the seller's signed answer and kept it",
                lambda o=outcome: flow.buyer_view(o),
                needs=(f"{path}-commit",),
            )
            digest = await run.step(
                f"{path}-digest",
                "Both parties computed the same record_digest",
                lambda p=proposal_id, o=outcome: flow.same_digest(p, o),
                needs=(f"{path}-commit",),
            )
            section = {
                "proposal_id": proposal_id,
                "outcome": outcome,
                "seller": seller,
                "buyer": buyer,
                "digest": digest,
            }
            if path == "signature":
                section["reverify"] = await run.step(
                    "signature-reverify",
                    "Both kept messages verify again, offline",
                    lambda s=seller, b=buyer: flow.reverify(s, b),
                    needs=("signature-seller", "signature-buyer"),
                )
            report[path] = section

        report["cloudflare"] = await run.step(
            "cloudflare",
            "cfbot, on Cloudflare's web-bot-auth, verifies the buyer's signature",
            flow.cloudflare,
        )

    report["steps"] = run.steps
    report["ok"] = not run.failed
    report["finished_at"] = _instant(time.time())
    report["duration_ms"] = round((time.time() - started) * 1000)
    return report


def _version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


# ── Publishing ────────────────────────────────────────────────────────────


def _write(path: Path, text: str) -> None:
    """Replaces `path` whole, so the site never reads a half-written file."""
    pending = path.with_suffix(".json.new")
    pending.write_text(text, encoding="utf-8")
    pending.chmod(0o644)
    pending.replace(path)


def history_entry(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "started_at": report["started_at"],
        "ok": report["ok"],
        "duration_ms": report.get("duration_ms"),
        "failed": [s["id"] for s in report.get("steps", []) if not s["ok"]],
    }


def updated_history(previous: list[dict[str, Any]], report: dict[str, Any]) -> list[dict[str, Any]]:
    """The newest run first, then the earlier ones, `HISTORY` in all."""
    return [history_entry(report), *previous][:HISTORY]


def publish(config: RunnerSettings, report: dict[str, Any]) -> None:
    """Writes latest-run.json and history.json, or a bare failure when the report isn't public."""
    try:
        text = assert_public(report, config.secrets)
    except NotPublic as e:
        report = {
            "format": 1,
            "started_at": report["started_at"],
            "ok": False,
            "steps": [
                {
                    "id": "publish",
                    "title": "Publish the report",
                    "ok": False,
                    "ms": 0,
                    "detail": f"withheld: {e}",
                }
            ],
        }
        text = json.dumps(report, indent=1)
    config.out_dir.mkdir(parents=True, exist_ok=True)
    history_file = config.out_dir / "history.json"
    try:
        previous = json.loads(history_file.read_text())["runs"]
    except (OSError, ValueError, KeyError):
        previous = []
    _write(config.out_dir / "latest-run.json", text)
    _write(history_file, json.dumps({"runs": updated_history(previous, report)}, indent=1))


def main() -> None:
    config = RunnerSettings.from_env()
    if config.operator_key is None:
        sys.exit("OPERATOR_KEY is not set")
    while True:
        report = asyncio.run(run_once(config))
        publish(config, report)
        failed = [s["id"] for s in report["steps"] if not s["ok"]]
        print(
            f"{report['started_at']} {'pass' if report['ok'] else 'FAIL'} "
            f"{report.get('duration_ms')} ms {' '.join(failed)}",
            flush=True,
        )
        if config.interval <= 0:
            sys.exit(0 if report["ok"] else 1)
        time.sleep(max(1.0, config.interval - report.get("duration_ms", 0) / 1000))


if __name__ == "__main__":
    main()
