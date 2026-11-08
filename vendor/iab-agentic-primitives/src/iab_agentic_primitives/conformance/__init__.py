"""Conformance kit: schema validators, golden vectors, standards checklist.

Makes standards and interop executable rather than aspirational. Golden
test vectors (checked in under ``spec/fixtures/``) map each claimed
standard -- OpenDirect 2.1, Deals API v1.0, AAMP, supply-chain
transparency, privacy signals -- to concrete assertions OR to an explicit
UNVERIFIED marker (:mod:`.standards` -- no silent coverage claims). Both
agent repos run this kit in continuous integration
(``python -m iab_agentic_primitives.conformance``) and assert that their
(de)serialization round-trips: a gap is a failing test, and a schema
change that breaks a vector fails both repos on the next dependency bump
-- the drift detector the pair of repos never had.

Public surface:

- :func:`run_conformance` -- run everything, get a :class:`GapReport`.
- :class:`ConformanceRunner` -- the same, with custom fixture/schema dirs.
- :class:`GapReport` / :class:`Gap` / :class:`CheckRecord` /
  :class:`StandardEntry` -- the EP-6.2 machine-readable report shapes.
- :mod:`.vectors` -- the golden-vector builders and fixture generator.
- ``python -m iab_agentic_primitives.conformance`` -- the CI entry point;
  writes ``gap_report.json`` and prints the human table.
"""

from .canonical import canonical_json, json_diff
from .gap_report_render import render_markdown
from .report import CheckRecord, CheckStatus, DiffEntry, Gap, GapReport, StandardEntry
from .runner import (
    DEFAULT_FIXTURES_DIR,
    DEFAULT_SCHEMA_DIR,
    ConformanceRunner,
    conformance_targets,
    run_conformance,
)
from .standards import STANDARDS, standards_entries

__all__ = [
    "DEFAULT_FIXTURES_DIR",
    "DEFAULT_SCHEMA_DIR",
    "STANDARDS",
    "CheckRecord",
    "CheckStatus",
    "ConformanceRunner",
    "DiffEntry",
    "Gap",
    "GapReport",
    "StandardEntry",
    "canonical_json",
    "conformance_targets",
    "json_diff",
    "render_markdown",
    "run_conformance",
    "standards_entries",
]
