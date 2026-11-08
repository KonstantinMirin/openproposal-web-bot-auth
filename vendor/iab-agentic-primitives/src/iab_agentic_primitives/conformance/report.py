"""Structured conformance results: the GapReport (EP-6.2 gap-report shape).

Every check the runner executes produces a :class:`CheckRecord`; every
failure additionally produces a :class:`Gap`. The :class:`GapReport`
bundles both with the external-standards registry status
(:mod:`iab_agentic_primitives.conformance.standards`) and renders two
ways: machine-readable JSON (``gap_report.json`` — what CI consumes) and
a human table (what a person reads when the build goes red). A red check
IS the gap list: the report never claims coverage it does not have, and
UNVERIFIED standards are always listed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class CheckStatus(str, Enum):
    """Outcome of one executed conformance check."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


class DiffEntry(BaseModel):
    """One field-level difference from a failed byte-compare."""

    path: str
    expected: str
    actual: str


class CheckRecord(BaseModel):
    """One executed check: (area, target, vector, check kind) -> status."""

    area: str
    target: str
    vector: str | None = None
    check: str
    status: CheckStatus
    detail: str = ""


class Gap(BaseModel):
    """One conformance failure — the machine-readable unit of the gap list."""

    area: str
    target: str
    vector: str | None = None
    check: str
    message: str
    diff: list[DiffEntry] = Field(default_factory=list)


class StandardEntry(BaseModel):
    """Registry status for one claimed standard: implemented checks or an
    explicit UNVERIFIED marker with what's missing (never a silent claim)."""

    id: str
    name: str
    version: str = ""
    status: Literal["implemented", "unverified"]
    checks: list[str] = Field(
        default_factory=list,
        description="Check kinds the runner actually executes for this standard.",
    )
    missing: str = Field(
        default="",
        description="For UNVERIFIED entries: exactly what has not been checked.",
    )


class GapReport(BaseModel):
    """The full conformance result: checks, gaps, and standards status."""

    generated_at: datetime = Field(default_factory=utc_now)
    library_version: str = "unknown"
    checks: list[CheckRecord] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    standards: list[StandardEntry] = Field(default_factory=list)

    @property
    def conformant(self) -> bool:
        """True when no executed check failed (skips are not failures,
        but they are reported — see the standards section and check list)."""
        return not self.gaps

    def _counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CheckStatus}
        for record in self.checks:
            counts[record.status.value] += 1
        return counts

    def summary(self) -> dict[str, Any]:
        """Aggregate counts for the machine-readable report."""
        counts = self._counts()
        areas: dict[str, dict[str, int]] = {}
        vectors: set[tuple[str, str, str]] = set()
        targets: set[tuple[str, str]] = set()
        for record in self.checks:
            area = areas.setdefault(record.area, {status.value: 0 for status in CheckStatus})
            area[record.status.value] += 1
            targets.add((record.area, record.target))
            if record.vector is not None:
                vectors.add((record.area, record.target, record.vector))
        return {
            "conformant": self.conformant,
            "checks": len(self.checks),
            "passed": counts["pass"],
            "failed": counts["fail"],
            "skipped": counts["skip"],
            "targets": len(targets),
            "vectors": len(vectors),
            "gaps": len(self.gaps),
            "standards_unverified": sum(
                1 for entry in self.standards if entry.status == "unverified"
            ),
            "by_area": areas,
        }

    def to_json_dict(self) -> dict[str, Any]:
        """The machine-readable gap report (``gap_report.json``)."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "library_version": self.library_version,
            "summary": self.summary(),
            "gaps": [gap.model_dump(mode="json") for gap in self.gaps],
            "standards": [entry.model_dump(mode="json") for entry in self.standards],
            "checks": [record.model_dump(mode="json") for record in self.checks],
        }

    def render_table(self) -> str:
        """The human-readable report: summary, gaps, and standards."""
        summary = self.summary()
        lines: list[str] = []
        lines.append(f"iab-agentic-primitives conformance — v{self.library_version}")
        lines.append(f"generated: {self.generated_at.isoformat()}")
        lines.append("")
        lines.append(
            "checks: {checks} total | {passed} passed | {failed} failed | {skipped} skipped".format(
                **summary
            )
        )
        lines.append(f"coverage: {summary['vectors']} vectors across {summary['targets']} targets")
        for area, counts in sorted(summary["by_area"].items()):
            lines.append(
                f"  {area:<11} pass={counts['pass']:<4} fail={counts['fail']:<3} "
                f"skip={counts['skip']}"
            )
        lines.append("")
        if self.gaps:
            lines.append(f"GAPS ({len(self.gaps)})")
            rows = [
                (
                    gap.area,
                    gap.target,
                    gap.vector or "-",
                    gap.check,
                    gap.message,
                )
                for gap in self.gaps
            ]
            lines.extend(_table(("AREA", "TARGET", "VECTOR", "CHECK", "MESSAGE"), rows))
            for gap in self.gaps:
                for entry in gap.diff:
                    lines.append(
                        f"    {gap.target}/{gap.vector or '-'} {entry.path}: "
                        f"expected {entry.expected} != actual {entry.actual}"
                    )
        else:
            lines.append("GAPS (0) — all executed checks passed")
        lines.append("")
        lines.append("STANDARDS")
        rows = [
            (
                entry.status.upper(),
                f"{entry.name} {entry.version}".strip(),
                ", ".join(entry.checks) if entry.checks else "-",
                entry.missing or "-",
            )
            for entry in self.standards
        ]
        lines.extend(_table(("STATUS", "STANDARD", "CHECKS", "MISSING"), rows))
        lines.append("")
        verdict = "CONFORMANT" if self.conformant else "NOT CONFORMANT"
        lines.append(f"result: {verdict} ({len(self.gaps)} gap(s))")
        return "\n".join(lines)


def _table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    """Render an aligned plain-text table."""
    widths = [len(cell) for cell in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(cell)), 60)

    def fmt(row: tuple[str, ...]) -> str:
        cells = []
        for i, cell in enumerate(row):
            text = cell if len(cell) <= widths[i] else cell[: widths[i] - 3] + "..."
            cells.append(text.ljust(widths[i]))
        return "  " + "  ".join(cells).rstrip()

    out = [fmt(header), "  " + "  ".join("-" * w for w in widths)]
    out.extend(fmt(row) for row in rows)
    return out


__all__ = [
    "CheckRecord",
    "CheckStatus",
    "DiffEntry",
    "Gap",
    "GapReport",
    "StandardEntry",
    "utc_now",
]
