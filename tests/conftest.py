"""The unit suite fails when any test skips.

A skip is invisible in a pass count, so a test that doesn't run is a defect
with a cause: make it run, or mark it `xfail(strict=True)`, which turns red the
moment the gap closes. There is no allowlist.
"""

from __future__ import annotations

import pytest

_SKIPPED: list[str] = []


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped and not hasattr(report, "wasxfail"):
        _SKIPPED.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if _SKIPPED and exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    if _SKIPPED:
        terminalreporter.section("skipped tests fail the suite")
        for nodeid in _SKIPPED:
            terminalreporter.line(nodeid)
