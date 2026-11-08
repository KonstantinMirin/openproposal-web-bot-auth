"""The conformance runner: replay golden vectors, emit a GapReport.

For every fixture under ``spec/fixtures/`` the runner executes:

- ``validate`` — the vector's ``data`` must validate against the shared
  model (mode ``valid`` / ``must_ignore``), or must FAIL with the vector's
  ``expected_error`` (mode ``invalid``).
- ``roundtrip`` — re-serialize the validated model and byte-compare with
  the vector under canonical JSON (sorted keys, compact separators). A
  mismatch produces a field-level diff, not two blobs.
- ``must_ignore`` — FD-13 (flagged decision 13): unknown fields and
  ``x_``-prefixed extension fields must parse and must NOT survive
  re-serialization (byte-compare against the vector's ``expected``).
- ``schema`` — validate the vector directly against the checked-in JSON
  Schema, when the optional third-party ``jsonschema`` package is
  installed; recorded as SKIP (never silently dropped) when it is not.
- ``schema_sync`` — per target: the model's generated JSON Schema must
  byte-match the checked-in ``spec/jsonschema/`` artifact. Combined with
  ``validate``, this pins every vector to the checked-in schema even
  when the ``jsonschema`` package is absent.
- ``state_sequence`` — replay legal/illegal transition sequences through
  BOTH the checked-in JSON transition exports (``spec/jsonschema/state/``)
  and the Python state machines, and fail on any disagreement.
- ``state_spec_sync`` — the machines' spec exports must byte-match the
  checked-in state artifacts.

Every failure is a structured :class:`~.report.Gap`; the assembled
:class:`~.report.GapReport` (with the standards registry) is the EP-6.2
machine-readable gap report both agent repos consume in CI.
"""

from __future__ import annotations

import json
from importlib import metadata
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..events import Event
from ..events.schema import build_event_schema
from ..primitives import WIRE_PRIMITIVES
from ..protocol import PROTOCOL_MESSAGES
from ..state import CHANGE_REQUEST_LIFECYCLE, DEAL_LIFECYCLE, ORDER_LIFECYCLE
from ..state.spec_export import render_document, state_spec_documents
from .canonical import canonical_json, json_diff
from .report import CheckRecord, CheckStatus, DiffEntry, Gap, GapReport
from .standards import standards_entries

try:  # pragma: no cover - environment-dependent optional dependency
    import jsonschema as _jsonschema
except ModuleNotFoundError:  # pragma: no cover
    _jsonschema = None

#: Repo root when running from a source checkout (src layout, 3 levels up).
_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURES_DIR = _REPO_ROOT / "spec" / "fixtures"
DEFAULT_SCHEMA_DIR = _REPO_ROOT / "spec" / "jsonschema"

#: The lifecycle machines, keyed by their spec ``machine`` name.
STATE_MACHINES = {
    "deal": DEAL_LIFECYCLE,
    "order": ORDER_LIFECYCLE,
    "change_request": CHANGE_REQUEST_LIFECYCLE,
}


def conformance_targets() -> dict[str, dict[str, type]]:
    """Every model the kit asserts over, grouped by fixture area."""
    return {
        "primitives": dict(WIRE_PRIMITIVES),
        "protocol": dict(PROTOCOL_MESSAGES),
        "events": {"Event": Event},
    }


class ConformanceRunner:
    """Loads fixtures, executes checks, and accumulates the GapReport."""

    def __init__(
        self,
        fixtures_dir: Path | None = None,
        schema_dir: Path | None = None,
    ) -> None:
        self.fixtures_dir = Path(fixtures_dir or DEFAULT_FIXTURES_DIR)
        self.schema_dir = Path(schema_dir or DEFAULT_SCHEMA_DIR)
        self.report = GapReport(library_version=_library_version())

    # -- bookkeeping -------------------------------------------------------

    def _record(
        self,
        *,
        area: str,
        target: str,
        vector: str | None,
        check: str,
        ok: bool | None,
        message: str = "",
        diff: list[dict[str, str]] | None = None,
    ) -> None:
        """Record one check; ``ok=None`` means the check was skipped."""
        status = CheckStatus.SKIP if ok is None else CheckStatus.PASS if ok else CheckStatus.FAIL
        self.report.checks.append(
            CheckRecord(
                area=area,
                target=target,
                vector=vector,
                check=check,
                status=status,
                detail=message,
            )
        )
        if status is CheckStatus.FAIL:
            self.report.gaps.append(
                Gap(
                    area=area,
                    target=target,
                    vector=vector,
                    check=check,
                    message=message or "check failed",
                    diff=[DiffEntry(**entry) for entry in (diff or [])],
                )
            )

    # -- fixture loading ---------------------------------------------------

    def _load_docs(self, area: str) -> list[dict[str, Any]]:
        area_dir = self.fixtures_dir / area
        docs = []
        for path in sorted(area_dir.glob("*.golden.json")):
            docs.append(json.loads(path.read_text()))
        return docs

    # -- model vector checks -------------------------------------------------

    def run_model_vectors(self) -> None:
        """Golden vectors for primitives, protocol envelopes, and events."""
        targets = conformance_targets()
        for area, models in targets.items():
            docs = self._load_docs(area)
            seen: set[str] = set()
            for doc in docs:
                target = doc.get("target", "?")
                seen.add(target)
                model = models.get(target)
                if model is None:
                    self._record(
                        area=area,
                        target=target,
                        vector=None,
                        check="fixture",
                        ok=False,
                        message=f"fixture references unknown {area} target {target!r}",
                    )
                    continue
                self._check_schema_sync(area, target, model)
                schema = self._load_schema(area, target)
                for vector in doc.get("vectors", []):
                    self._run_vector(area, target, model, vector, schema)
            missing = sorted(set(models) - seen)
            for target in missing:
                self._record(
                    area=area,
                    target=target,
                    vector=None,
                    check="fixture",
                    ok=False,
                    message=f"no golden fixture checked in for {area}/{target}",
                )

    def _run_vector(
        self,
        area: str,
        target: str,
        model: type,
        vector: dict[str, Any],
        schema: dict[str, Any] | None,
    ) -> None:
        name = vector.get("name", "?")
        mode = vector.get("mode", "valid")
        data = vector.get("data")

        if mode == "invalid":
            self._check_expected_invalid(area, target, model, name, vector)
            return

        # validate
        try:
            instance = model.model_validate(data)  # type: ignore[attr-defined]
        except ValidationError as exc:
            self._record(
                area=area,
                target=target,
                vector=name,
                check="validate",
                ok=False,
                message=f"golden vector failed validation: {_first_error(exc)}",
            )
            return
        self._record(area=area, target=target, vector=name, check="validate", ok=True)

        # roundtrip / must_ignore byte-compare under canonical JSON
        serialized = instance.model_dump(mode="json", by_alias=True)
        if mode == "must_ignore":
            expected = vector.get("expected", data)
            check = "must_ignore"
            failure = "unknown/x_ extension fields were not ignored on re-serialization (FD-13)"
        else:
            expected = data
            check = "roundtrip"
            failure = "re-serialized bytes differ from the golden vector"
        expected_text = canonical_json(expected)
        actual_text = canonical_json(serialized)
        if expected_text == actual_text:
            self._record(area=area, target=target, vector=name, check=check, ok=True)
        else:
            diff = json_diff(expected, serialized)
            self._record(
                area=area,
                target=target,
                vector=name,
                check=check,
                ok=False,
                message=f"{failure} ({len(diff)} differing path(s))",
                diff=diff,
            )

        # direct JSON Schema validation (optional dependency)
        if mode != "must_ignore":
            self._check_jsonschema(area, target, name, data, schema)

    def _check_expected_invalid(
        self,
        area: str,
        target: str,
        model: type,
        name: str,
        vector: dict[str, Any],
    ) -> None:
        expected_error = vector.get("expected_error", "")
        try:
            model.model_validate(vector.get("data"))  # type: ignore[attr-defined]
        except ValidationError as exc:
            message = str(exc)
            if expected_error and expected_error not in message:
                self._record(
                    area=area,
                    target=target,
                    vector=name,
                    check="expected_invalid",
                    ok=False,
                    message=(
                        f"rejected, but for the wrong reason: expected "
                        f"{expected_error!r} in {_first_error(exc)!r}"
                    ),
                )
            else:
                self._record(
                    area=area, target=target, vector=name, check="expected_invalid", ok=True
                )
            return
        self._record(
            area=area,
            target=target,
            vector=name,
            check="expected_invalid",
            ok=False,
            message=(
                "invalid vector PARSED successfully; expected rejection "
                f"containing {expected_error!r}"
            ),
        )

    # -- schema checks -------------------------------------------------------

    def _schema_path(self, area: str, target: str) -> Path:
        if area == "primitives":
            return self.schema_dir / f"{target}.json"
        if area == "protocol":
            return self.schema_dir / "protocol" / f"{target}.json"
        if area == "events":
            return self.schema_dir / "events" / "event.schema.json"
        raise ValueError(f"unknown fixture area {area!r}")

    def _load_schema(self, area: str, target: str) -> dict[str, Any] | None:
        path = self._schema_path(area, target)
        if not path.is_file():
            return None
        return json.loads(path.read_text())

    def _check_schema_sync(self, area: str, target: str, model: type) -> None:
        """The model's generated schema must byte-match the checked-in one."""
        path = self._schema_path(area, target)
        if not path.is_file():
            self._record(
                area=area,
                target=target,
                vector=None,
                check="schema_sync",
                ok=False,
                message=f"checked-in schema missing: {path.name}",
            )
            return
        if area == "events":
            generated = json.dumps(build_event_schema(), indent=2) + "\n"
        else:
            schema = model.model_json_schema()  # type: ignore[attr-defined]
            generated = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        if generated == path.read_text():
            self._record(area=area, target=target, vector=None, check="schema_sync", ok=True)
        else:
            self._record(
                area=area,
                target=target,
                vector=None,
                check="schema_sync",
                ok=False,
                message=(
                    f"model schema has drifted from checked-in {path.name}; "
                    "regenerate the spec exports"
                ),
            )

    def _check_jsonschema(
        self,
        area: str,
        target: str,
        name: str,
        data: Any,
        schema: dict[str, Any] | None,
    ) -> None:
        if _jsonschema is None:
            self._record(
                area=area,
                target=target,
                vector=name,
                check="schema",
                ok=None,
                message=(
                    "optional 'jsonschema' package not installed; covered "
                    "indirectly by validate + schema_sync"
                ),
            )
            return
        if schema is None:
            self._record(
                area=area,
                target=target,
                vector=name,
                check="schema",
                ok=False,
                message="checked-in schema missing",
            )
            return
        try:
            _jsonschema.validate(instance=data, schema=schema)
        except _jsonschema.ValidationError as exc:  # pragma: no cover - needs dep
            self._record(
                area=area,
                target=target,
                vector=name,
                check="schema",
                ok=False,
                message=f"vector does not satisfy checked-in schema: {exc.message}",
            )
            return
        self._record(area=area, target=target, vector=name, check="schema", ok=True)

    # -- state machine checks -------------------------------------------------

    def run_state_vectors(self) -> None:
        """Replay transition sequences through the JSON exports + machines."""
        self._check_state_spec_sync()
        for doc in self._load_docs("state"):
            machine_name = doc.get("machine", "?")
            machine = STATE_MACHINES.get(machine_name)
            export = self._load_state_export(machine_name)
            if machine is None or export is None:
                self._record(
                    area="state",
                    target=machine_name,
                    vector=None,
                    check="fixture",
                    ok=False,
                    message=f"unknown state machine or missing export: {machine_name!r}",
                )
                continue
            allowed = {(t["from"], t["to"]) for t in export["transitions"]}
            states = set(export["states"])
            for sequence in doc.get("sequences", []):
                self._run_sequence(machine_name, machine, allowed, states, sequence)

    def _run_sequence(
        self,
        machine_name: str,
        machine: Any,
        allowed: set[tuple[str, str]],
        states: set[str],
        sequence: dict[str, Any],
    ) -> None:
        name = sequence.get("name", "?")
        expect = sequence.get("expect", "legal")
        seq_states: list[str] = sequence.get("states", [])
        fails_at = sequence.get("fails_at")

        def fail(message: str) -> None:
            self._record(
                area="state",
                target=machine_name,
                vector=name,
                check="state_sequence",
                ok=False,
                message=message,
            )

        unknown = [s for s in seq_states if s not in states]
        if unknown or len(seq_states) < 2:
            fail(f"malformed sequence: unknown states {unknown} or too short")
            return

        enum_by_value = {member.value: member for member in machine.states}
        steps = list(zip(seq_states, seq_states[1:]))
        for index, (src, dst) in enumerate(steps):
            json_legal = (src, dst) in allowed
            machine_legal = machine.can_transition(enum_by_value[src], enum_by_value[dst])
            if json_legal != machine_legal:
                fail(
                    f"JSON export and state machine disagree on "
                    f"{src!r} -> {dst!r} (export={json_legal}, machine={machine_legal})"
                )
                return
            if expect == "legal":
                if not json_legal:
                    fail(f"legal sequence rejected at step {index}: {src!r} -> {dst!r}")
                    return
            else:  # illegal sequence
                if index < (fails_at or 0):
                    if not json_legal:
                        fail(
                            f"illegal sequence failed too early at step {index}: "
                            f"{src!r} -> {dst!r} (expected failure at {fails_at})"
                        )
                        return
                elif index == fails_at:
                    if json_legal:
                        fail(f"illegal transition ACCEPTED at step {index}: {src!r} -> {dst!r}")
                        return
                    break  # rejected exactly where expected
        else:
            if expect == "illegal":
                fail("illegal sequence completed without any rejected transition")
                return
        self._record(
            area="state", target=machine_name, vector=name, check="state_sequence", ok=True
        )

    def _load_state_export(self, machine_name: str) -> dict[str, Any] | None:
        stems = {
            "deal": "DealLifecycle",
            "order": "OrderLifecycle",
            "change_request": "ChangeRequestLifecycle",
        }
        stem = stems.get(machine_name)
        if stem is None:
            return None
        path = self.schema_dir / "state" / f"{stem}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text())

    def _check_state_spec_sync(self) -> None:
        """Machines' spec exports must byte-match the checked-in artifacts."""
        for stem, document in state_spec_documents().items():
            path = self.schema_dir / "state" / f"{stem}.json"
            if not path.is_file():
                self._record(
                    area="state",
                    target=stem,
                    vector=None,
                    check="state_spec_sync",
                    ok=False,
                    message=f"checked-in state export missing: {path.name}",
                )
                continue
            ok = render_document(document) == path.read_text()
            self._record(
                area="state",
                target=stem,
                vector=None,
                check="state_spec_sync",
                ok=ok,
                message=("" if ok else f"state machine has drifted from checked-in {path.name}"),
            )

    # -- entry point -----------------------------------------------------------

    def run(self) -> GapReport:
        self.run_model_vectors()
        self.run_state_vectors()
        self.report.standards = standards_entries()
        return self.report


def run_conformance(fixtures_dir: Path | None = None, schema_dir: Path | None = None) -> GapReport:
    """Run every conformance check and return the assembled GapReport."""
    return ConformanceRunner(fixtures_dir=fixtures_dir, schema_dir=schema_dir).run()


def _library_version() -> str:
    try:
        return metadata.version("iab-agentic-primitives")
    except metadata.PackageNotFoundError:  # pragma: no cover
        return "0.0.0+unknown"


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    loc = ".".join(str(part) for part in error.get("loc", ()))
    return f"{loc}: {error.get('msg', '')}"


__all__ = [
    "DEFAULT_FIXTURES_DIR",
    "DEFAULT_SCHEMA_DIR",
    "ConformanceRunner",
    "STATE_MACHINES",
    "conformance_targets",
    "run_conformance",
]
