"""The § 5.6.1 steps: the rules the generated types don't state, and the shared pair rule."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from openproposal import (
    AssentEntry,
    Commit,
    CommitResult,
    LineItemWrites,
    Proposal,
    dump,
    dump_json,
)
from pydantic import ValidationError

from protocol.operations import (
    ProtocolViolation,
    ResultMismatch,
    Rule,
    acceptance_for,
    check_result,
    compose_commit,
    parse_commit,
    parse_errors,
    parse_result,
    result_for,
)
from protocol.values import JsonObject, commitment_key, instant
from tests._tools import load_yaml, seed_document

PLAN = load_yaml(Path(__file__).resolve().parent.parent / "buyer" / "plan.yaml")
NOW = datetime(2027, 1, 1, 12, 30, 15, 999, tzinfo=UTC)


def _raw() -> JsonObject:
    return seed_document()


def _writes(*names: str) -> dict[str, LineItemWrites]:
    return {n: LineItemWrites.model_validate(PLAN[n]) for n in names}


def _composed(*names: str) -> tuple[Commit, bytes]:
    raw = _raw()
    composed = compose_commit(Proposal.model_validate(raw), raw, _writes(*names), at=NOW, key="k-1")
    return composed.commit, composed.digest_input


def _json(value: object) -> bytes:
    return json.dumps(value).encode()


def test_instant_is_utc_whole_seconds() -> None:
    assert instant(NOW) == "2027-01-01T12:30:15Z"


def test_a_composed_commit_round_trips() -> None:
    commit, _ = _composed("business-daily-display", "weather-app-ctv")
    parsed = parse_commit(dump_json(commit).encode())
    assert dump(parsed) == dump(commit)
    assert parsed.entry.line_item_ids == ["business-daily-display", "weather-app-ctv"]
    assert commitment_key(parsed.entry) == "k-1"


# ── parse_commit refuses what § 5.6.1 forbids ──────────────────────────────


@pytest.mark.parametrize(
    ("change", "rule"),
    [
        ({"role": "acceptance", "idempotency_key": None}, Rule.COMMIT_ENTRY),
        ({"line_item_ids": ["weather-app-ctv"]}, Rule.WRITES_KEYS),
        ({"line_item_ids": []}, Rule.LINE_ITEMS),
        ({"ground": "terms"}, Rule.GROUND),
    ],
    ids=["acceptance-entry", "writes-for-other-items", "no-line-items", "ground-on-commitment"],
)
def test_parse_commit_refuses(change: JsonObject, rule: Rule) -> None:
    commit, _ = _composed("business-daily-display")
    body = dump(commit)
    body["entry"] = {k: v for k, v in {**body["entry"], **change}.items() if v is not None}
    with pytest.raises(ProtocolViolation) as refused:
        parse_commit(_json(body))
    assert refused.value.rule is rule


def test_parse_commit_refuses_what_the_sdk_refuses() -> None:
    commit, _ = _composed("business-daily-display")
    body = dump(commit)
    del body["entry"]["idempotency_key"]
    with pytest.raises(ValidationError):
        parse_commit(_json(body))


# ── check_result refuses an answer that doesn't match ──────────────────────


def _answer(commit: Commit, *later: AssentEntry) -> CommitResult:
    return CommitResult(entries=[commit.entry, *later])


def test_check_result_returns_the_matching_acceptance() -> None:
    commit, data = _composed("business-daily-display")
    acceptance = acceptance_for(commit.entry, NOW)
    assert check_result(commit, _answer(commit, acceptance), data) == acceptance


def _other_items(commit: Commit) -> AssentEntry:
    return AssentEntry.model_validate(
        {**dump(acceptance_for(commit.entry, NOW)), "line_item_ids": ["weather-app-ctv"]}
    )


def _acceptance_first(commit: Commit) -> CommitResult:
    return CommitResult(entries=[acceptance_for(commit.entry, NOW)])


def _no_acceptance(commit: Commit) -> CommitResult:
    return _answer(commit)


def _acceptance_for_other_items(commit: Commit) -> CommitResult:
    return _answer(commit, _other_items(commit))


@pytest.mark.parametrize(
    ("answer", "rule"),
    [
        (_acceptance_first, Rule.FIRST_ENTRY),
        (_no_acceptance, Rule.ACCEPTANCE),
        (_acceptance_for_other_items, Rule.ACCEPTANCE),
    ],
    ids=["wrong-first-entry", "no-acceptance", "acceptance-for-other-items"],
)
def test_check_result_refuses(answer: Callable[[Commit], CommitResult], rule: Rule) -> None:
    commit, data = _composed("business-daily-display")
    with pytest.raises(ResultMismatch) as refused:
        check_result(commit, answer(commit), data)
    assert refused.value.rule is rule


def test_compose_and_check_leave_their_inputs_unchanged() -> None:
    raw, writes = _raw(), _writes("business-daily-display")
    proposal = Proposal.model_validate(raw)
    before = (copy.deepcopy(raw), dump(proposal), {n: dump(w) for n, w in writes.items()})
    composed = compose_commit(proposal, raw, writes, at=NOW, key="k-1")
    assert (raw, dump(proposal), {n: dump(w) for n, w in writes.items()}) == before

    answer = _answer(composed.commit, acceptance_for(composed.commit.entry, NOW))
    seen = (dump(composed.commit), dump(answer), composed.digest_input)
    check_result(composed.commit, answer, composed.digest_input)
    assert (dump(composed.commit), dump(answer), composed.digest_input) == seen


# ── The seller's result, and reading answers ───────────────────────────────


def test_result_for_is_the_entry_then_its_matching_later_entries() -> None:
    first, _ = _composed("business-daily-display")
    other, _ = _composed("weather-app-ctv")
    acceptance = acceptance_for(first.entry, NOW)
    assent = [first.entry, acceptance_for(other.entry, NOW), acceptance]
    assert result_for(assent, "k-1").entries == [first.entry, acceptance]


def test_parse_result_reads_as_a_receiver() -> None:
    commit, _ = _composed("business-daily-display")
    answer = dump(_answer(commit, acceptance_for(commit.entry, NOW)))
    answer["entries"][1]["x_unknown"] = 1
    assert len(parse_result(_json(answer)).entries) == 2
    with pytest.raises(ProtocolViolation):
        parse_result(_json({"entries": []}))


def test_parse_errors_reads_an_open_error_object() -> None:
    errors = parse_errors(
        _json({"errors": [{"code": "demo.example:busy", "detail": "d", "retry": "same", "y": 1}]})
    )
    assert [(e.code, e.retry) for e in errors] == [("demo.example:busy", "same")]
    with pytest.raises(ValidationError):
        parse_errors(_json({"errors": []}))
