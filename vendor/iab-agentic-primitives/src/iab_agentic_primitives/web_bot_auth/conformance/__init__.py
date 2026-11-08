"""Conformance vectors for the Web Bot Auth profile, and a runner.

The vectors are package data in ``web_bot_auth/vectors/``: ``keys.json``,
``scenarios.json``, ``refusals.json``, ``positive/``, and ``negative/``. Their
README states the format, and :mod:`.models` types it. ``PROTOCOL.md`` in this
package states the adapter protocol.

:func:`run_conformance` grades an implementation through an adapter (see
:mod:`.adapter`) on three suites:

- ``vectors``: the committed vectors, at each vector's ``reference_now``.
- ``live``: the adapter signs and this library verifies, then this library
  signs and the adapter verifies, at the current time.
- ``scenarios``: this library signs every scenario in ``scenarios.json``, and
  the adapter verifies it.

A check passes when the result matches the expected outcome: the identity
for a pass, and both the status and the rule for a refusal.

Run it from another repository::

    python -m iab_agentic_primitives.web_bot_auth.conformance run --adapter "<command>"

With no ``--adapter``, it grades this library.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, field, replace
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Literal

from ..errors import Refusal
from ..keys import Ed25519Key
from ..values import UnixSeconds, system_clock
from .adapter import Adapter, CommandAdapter, LibraryAdapter
from .models import (
    DirectoryDoc,
    KeysDocument,
    KeysVerified,
    Outcome,
    Passes,
    Refused,
    RequestDoc,
    RequestScenario,
    ResponseDoc,
    ResponseScenario,
    Result,
    ScenariosDocument,
    SignDirectory,
    SignRequest,
    SignResponse,
    Suite,
    Tier,
    Vector,
    VectorOperation,
    Verified,
    VerifyDirectory,
    VerifyRequest,
    VerifyResponse,
    passing,
    read,
    refusing,
)
from .signing import (
    baseline_request,
    sign_directory,
    sign_directory_scenario,
    sign_request_scenario,
    sign_response_scenario,
)

#: The committed vectors, as package data.
#: Found from this package's own name, so a vendored copy finds its own.
VECTORS: Traversable = files(__name__.rpartition(".")[0]) / "vectors"
#: The adapter protocol, as package data.
PROTOCOL: Traversable = files(__name__) / "PROTOCOL.md"


def vectors(directory: Traversable = VECTORS) -> Iterator[tuple[str, Vector]]:
    """Yields ``(id, vector)`` for each positive, then each negative vector, sorted."""
    for group in ("positive", "negative"):
        entries = sorted(
            (p for p in (directory / group).iterdir() if p.name.endswith(".json")),
            key=lambda p: p.name,
        )
        for path in entries:
            yield (
                f"{group}/{path.name.removesuffix('.json')}",
                read(Vector, path.read_text()),
            )


def keys_document(directory: Traversable = VECTORS) -> KeysDocument:
    return read(KeysDocument, (directory / "keys.json").read_text())


def scenarios_document(directory: Traversable = VECTORS) -> ScenariosDocument:
    return read(ScenariosDocument, (directory / "scenarios.json").read_text())


def published_keys(directory: Traversable = VECTORS) -> Mapping[str, Ed25519Key]:
    """The published test keys, keyed by ``kid``."""
    return {
        entry.kid: Ed25519Key.from_jwk(entry.private_jwk())
        for entry in keys_document(directory).keys
    }


def published_key_ids(directory: Traversable = VECTORS) -> frozenset[str]:
    """The ``kid`` of every published test key; a production verifier refuses them (WBA 6.8)."""
    return frozenset(published_keys(directory))


def _directories(
    refs: Mapping[str, tuple[str, ...]], keys: Mapping[str, Ed25519Key], now: UnixSeconds
) -> dict[str, DirectoryDoc]:
    """Each named root's directory, published with the keys ``refs`` names, at ``now``."""
    return {root: sign_directory([keys[k] for k in kids], root, now) for root, kids in refs.items()}


def vector_operation(vector: Vector) -> VectorOperation:
    """The one operation that grades ``vector``, as the vector carries it."""
    return vector.operation


# ── grading ────────────────────────────────────────────────────────────────


def meets(expected: Outcome, got: Result) -> bool:
    """True when ``got`` is the expected outcome.

    A pass needs a verified result, with the expected identity when one is
    named. A refusal needs a :class:`~.models.Refused` with the expected
    status and rule, so an adapter failure, whose status is ``None``, never
    meets one.
    """
    if isinstance(expected, Passes):
        named = None if expected.identity is None else str(expected.identity)
        if isinstance(got, Verified):
            return named in (None, got.identity)
        return isinstance(got, KeysVerified) and named is None
    return (
        isinstance(got, Refused)
        and got.status == expected.status
        and got.rule == expected.rule.code
    )


def describe(got: Result) -> str:
    if isinstance(got, Refused):
        return f"{got.status or 'no status'} {got.rule}: {got.error}"
    if isinstance(got, Verified):
        return f"pass as {got.identity}"
    return "pass" if isinstance(got, KeysVerified) else f"signed {type(got).__name__}"


def want(expected: Outcome) -> str:
    if isinstance(expected, Passes):
        return "pass" + ("" if expected.identity is None else f" as {expected.identity}")
    return f"{expected.status} {expected.rule.code}"


@dataclass(frozen=True)
class Check:
    suite: Suite
    id: str
    ok: bool
    expected: str
    got: str
    tier: Tier | None = None


@dataclass
class ConformanceReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def to_json(self) -> list[dict[str, object]]:
        return [asdict(c) for c in self.checks]

    def render(self) -> str:
        lines = []
        for c in self.checks:
            tier = f"[{c.tier}] " if c.tier else ""
            lines.append(f"{'pass' if c.ok else 'FAIL'}  {c.suite:<9} {tier}{c.id}")
            if not c.ok:
                lines.append(f"        expected {c.expected}\n        got      {c.got}")
        passed = len(self.checks) - len(self.failures)
        lines.append(f"\n{passed} of {len(self.checks)} checks pass.")
        return "\n".join(lines)


#: The refusals the live suite expects of tampered and replayed messages.
_REPLAYED = refusing(Refusal.NONCE_REPLAYED)
_TAMPERED = refusing(Refusal.SIGNATURE_INVALID)


class _Run:
    def __init__(self, adapter: Adapter, directory: Traversable) -> None:
        self.adapter = adapter
        self.reference = LibraryAdapter()
        self.keys = published_keys(directory)
        self.private = {e.kid: e.private_jwk() for e in keys_document(directory).keys}
        self.doc = scenarios_document(directory)
        self.directory = directory
        self.report = ConformanceReport()

    def record(
        self, suite: Suite, id: str, expected: Outcome, got: Result, tier: Tier | None = None
    ) -> None:
        self.report.checks.append(
            Check(suite, id, meets(expected, got), want(expected), describe(got), tier)
        )

    # ── vectors ──

    def run_vectors(self) -> None:
        for vid, vector in vectors(self.directory):
            got = self.adapter(vector.operation)
            self.record("vectors", vid, vector.expected, got, vector.tier)

    # ── live ──

    def _live_directory(self, now: UnixSeconds) -> DirectoryDoc:
        signer = self.doc.signer
        origin = signer.identity
        theirs = self.adapter(
            SignDirectory(keys=(self.private[signer.kid],), origin=origin, now=now)
        )
        got = (
            self.reference(VerifyDirectory(origin=origin, response=theirs, now=now))
            if isinstance(theirs, DirectoryDoc)
            else theirs
        )
        self.record("live", "adapter signs the directory, reference verifies", passing(), got)
        ours = sign_directory([self.keys[signer.kid]], str(origin), now)
        got = self.adapter(VerifyDirectory(origin=origin, response=ours, now=now))
        self.record("live", "reference signs the directory, adapter verifies", passing(), got)
        return ours

    def _live_requests(self, now: UnixSeconds, directory: DirectoryDoc) -> None:
        signer = self.doc.signer
        origin = signer.identity
        ok = passing(origin)
        dirs = {str(origin): directory}
        authority = self.doc.verifier
        for name, request in self.doc.requests.items():
            label = name.upper()
            signed = self.adapter(
                SignRequest(key=self.private[signer.kid], origin=origin, request=request, now=now)
            )
            got = (
                self.reference(
                    VerifyRequest(request=signed, authority=authority, directories=dirs, now=now)
                )
                if isinstance(signed, RequestDoc)
                else signed
            )
            self.record("live", f"adapter signs {label}, reference verifies", ok, got)
            mine = RequestDoc.of(sign_request_scenario(self.doc, _baseline(name), self.keys, now))
            op = VerifyRequest(request=mine, authority=authority, directories=dirs, now=now)
            self.record("live", f"reference signs {label}, adapter verifies", ok, self.adapter(op))
            twice = replace(op, prior=(mine,))
            self.record(
                "live",
                f"reference signs {label}, adapter verifies it twice",
                _REPLAYED,
                self.adapter(twice),
            )
            joiner = "&" if "?" in mine.url else "?"
            moved = replace(op, request=replace(mine, url=f"{mine.url}{joiner}t=1"))
            self.record(
                "live",
                f"reference signs {label}, URL changed, adapter refuses",
                _TAMPERED,
                self.adapter(moved),
            )

    def _live_response(self, now: UnixSeconds) -> None:
        responder = self.doc.responder
        ok = passing(responder.identity)
        seller = {
            str(responder.identity): sign_directory(
                [self.keys[responder.kid]], str(responder.identity), now
            )
        }
        request = RequestDoc.of(baseline_request(self.doc, self.keys, now))
        signed = self.adapter(
            SignResponse(
                key=self.private[responder.kid],
                origin=responder.identity,
                request=request,
                response=self.doc.response,
                now=now,
            )
        )
        got = (
            self.reference(
                VerifyResponse(request=request, response=signed, directories=seller, now=now)
            )
            if isinstance(signed, ResponseDoc)
            else signed
        )
        self.record(
            "live", "adapter signs a response, reference verifies it and its binding", ok, got
        )
        mine_request, mine = sign_response_scenario(self.doc, _response_baseline(), self.keys, now)
        op = VerifyResponse(request=mine_request, response=mine, directories=seller, now=now)
        self.record(
            "live",
            "reference signs a response, adapter verifies it and its binding",
            ok,
            self.adapter(op),
        )

    def run_live(self, now: UnixSeconds) -> None:
        directory = self._live_directory(now)
        self._live_requests(now, directory)
        self._live_response(now)

    # ── scenarios ──

    def run_scenarios(self, now: UnixSeconds) -> None:
        signer, responder = self.doc.signer, self.doc.responder
        default = {str(signer.identity): (signer.kid,)}
        for s in self.doc.request_scenarios:
            request = RequestDoc.of(sign_request_scenario(self.doc, s, self.keys, now))
            op = VerifyRequest(
                request=request,
                authority=s.authority or self.doc.verifier,
                directories=_directories(s.directories or default, self.keys, now),
                now=now,
            )
            self.record("scenarios", f"{s.id} {s.name}", s.expected, self.adapter(op), s.tier)
        for d in self.doc.directory_scenarios:
            signed = sign_directory_scenario(self.doc, d, self.keys, now)
            check = VerifyDirectory(origin=signer.identity, response=signed, now=now)
            self.record("scenarios", f"{d.id} {d.name}", d.expected, self.adapter(check), d.tier)
        seller = _directories({str(responder.identity): (responder.kid,)}, self.keys, now)
        for r in self.doc.response_scenarios:
            asked, answer = sign_response_scenario(self.doc, r, self.keys, now)
            pair = VerifyResponse(request=asked, response=answer, directories=seller, now=now)
            self.record("scenarios", f"{r.id} {r.name}", r.expected, self.adapter(pair), r.tier)


def _baseline(base: Literal["post", "get"]) -> RequestScenario:
    return RequestScenario(id="R00", name="Baseline", base=base, basis="", expected=passing())


def _response_baseline() -> ResponseScenario:
    return ResponseScenario(id="P00", name="Baseline", basis="", expected=passing())


def run_conformance(
    adapter: Adapter | str | None = None,
    *,
    now: UnixSeconds | None = None,
    directory: Traversable = VECTORS,
    suites: tuple[Suite, ...] = ("vectors", "live", "scenarios"),
) -> ConformanceReport:
    """Grades ``adapter``: this library when ``None``, and a command line when a string."""
    if adapter is None:
        adapter = LibraryAdapter()
    elif isinstance(adapter, str):
        adapter = CommandAdapter(adapter)
    run = _Run(adapter, directory)
    clock = system_clock() if now is None else now
    if "vectors" in suites:
        run.run_vectors()
    if "live" in suites:
        run.run_live(clock)
    if "scenarios" in suites:
        run.run_scenarios(clock)
    return run.report


__all__ = [
    "PROTOCOL",
    "VECTORS",
    "Check",
    "CommandAdapter",
    "ConformanceReport",
    "LibraryAdapter",
    "keys_document",
    "meets",
    "published_key_ids",
    "published_keys",
    "run_conformance",
    "scenarios_document",
    "vector_operation",
    "vectors",
]
