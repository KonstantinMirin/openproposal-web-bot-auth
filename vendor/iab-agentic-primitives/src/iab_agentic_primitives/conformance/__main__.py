"""Command-line entry point: ``python -m iab_agentic_primitives.conformance``.

Runs every conformance check, writes the machine-readable
``gap_report.json``, and prints the human-readable table. Exit code 0
means every executed check passed; 1 means there are gaps (the gap list
is the report); 2 means the runner itself could not start (for example
the fixtures directory was not found).

This is the command both agent repos call in CI (continuous integration):

    uv run python -m iab_agentic_primitives.conformance

Maintainers regenerate the checked-in golden fixtures with:

    uv run python -m iab_agentic_primitives.conformance --regenerate
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .gap_report_render import render_markdown
from .runner import DEFAULT_FIXTURES_DIR, DEFAULT_SCHEMA_DIR, run_conformance
from .vectors import write_fixtures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m iab_agentic_primitives.conformance",
        description="Run the shared-contract conformance kit and write a gap report.",
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=None,
        help=f"Golden-fixture directory (default: {DEFAULT_FIXTURES_DIR})",
    )
    parser.add_argument(
        "--schemas",
        type=Path,
        default=None,
        help=f"Checked-in JSON Schema directory (default: {DEFAULT_SCHEMA_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("gap_report.json"),
        help="Where to write the machine-readable gap report (default: ./gap_report.json)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human-readable table (the JSON report is still written).",
    )
    parser.add_argument(
        "--render-md",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Also render the human-facing Markdown gap report "
            "(STANDARDS_GAP_REPORT.md) from this run to PATH."
        ),
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate the checked-in golden fixtures from the vector builders, then exit.",
    )
    args = parser.parse_args(argv)

    fixtures_dir = args.fixtures or DEFAULT_FIXTURES_DIR

    if args.regenerate:
        written = write_fixtures(fixtures_dir)
        for path in written:
            print(f"wrote {path}")
        return 0

    if not fixtures_dir.is_dir():
        print(
            f"error: fixtures directory not found: {fixtures_dir}\n"
            "Run from a source checkout of iab-agentic-primitives, or pass "
            "--fixtures pointing at its spec/fixtures directory.",
            file=sys.stderr,
        )
        return 2

    report = run_conformance(fixtures_dir=fixtures_dir, schema_dir=args.schemas)
    payload = report.to_json_dict()
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    if args.render_md is not None:
        args.render_md.write_text(render_markdown(payload))
    if not args.quiet:
        print(report.render_table())
        print(f"\ngap report written to {args.output}")
        if args.render_md is not None:
            print(f"markdown gap report written to {args.render_md}")
    return 0 if report.conformant else 1


if __name__ == "__main__":
    sys.exit(main())
