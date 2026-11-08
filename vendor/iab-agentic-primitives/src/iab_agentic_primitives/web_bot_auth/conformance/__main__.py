"""Command line: ``python -m iab_agentic_primitives.web_bot_auth.conformance``.

- ``adapter [--lines]``: read one operation as JSON on standard input, run it
  on this library, and write the result as JSON (the protocol in
  ``PROTOCOL.md`` in this package). With ``--lines``, read and write one JSON
  object per line until the input ends.
- ``run [--adapter COMMAND] [--json FILE]``: grade an implementation; exit 1
  when a check fails.
- ``--regenerate [--out DIR]``: write the vectors from the generator, and
  delete the generator's own files it no longer produces; nothing else in
  DIR is touched. DIR must be a vector directory (empty, or with a
  ``keys.json``), and the package's own directory is written only in a source
  checkout. ``--check [--out DIR]`` names each file that differs from the
  generator, is missing, or is a vector the generator doesn't produce, and
  exits 1 when there is one. The upstream conformance CLI,
  ``python -m iab_agentic_primitives.conformance``, names its regeneration the
  same way.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import run_conformance
from .adapter import LibraryAdapter


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m iab_agentic_primitives.web_bot_auth.conformance"
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--regenerate", action="store_true", help="write the vectors")
    action.add_argument(
        "--check", action="store_true", help="exit 1 when a vector file differs from the generator"
    )
    parser.add_argument("--out", type=Path, help="the vector directory (default: the package's)")
    commands = parser.add_subparsers(dest="command")
    serve = commands.add_parser("adapter", help="run one operation from standard input")
    serve.add_argument(
        "--lines", action="store_true", help="run one operation per line until end of input"
    )
    run = commands.add_parser("run", help="grade an implementation")
    run.add_argument("--adapter", help="command line of an adapter; this library when omitted")
    run.add_argument("--json", type=Path, help="write the checks to this file")
    return parser


def _vectors(args: argparse.Namespace) -> int:
    from . import generate

    out = args.out or generate.SOURCE
    if args.check:
        drift = generate.check(out)
        for line in drift.lines():
            print(line)
        return 1 if drift else 0
    try:
        written = generate.write(out)
    except ValueError as e:
        print(f"not regenerated: {e}", file=sys.stderr)
        return 1
    for path in written:
        print(f"wrote {path}")
    return 0


def _adapter(lines: bool) -> int:
    adapter = LibraryAdapter()
    if not lines:
        sys.stdout.write(adapter.serve(sys.stdin.read()))
        return 0
    for line in sys.stdin:
        if line.strip():
            sys.stdout.write(adapter.serve(line) + "\n")
            sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.regenerate or args.check:
        if args.command is not None:
            parser.error("--regenerate and --check take no command")
        return _vectors(args)
    if args.command == "adapter":
        return _adapter(args.lines)
    if args.command == "run":
        report = run_conformance(args.adapter)
        print(report.render())
        if args.json:
            args.json.write_text(json.dumps(report.to_json(), indent=2))
        return 0 if report.ok else 1
    parser.error("name a command, or --regenerate or --check")


if __name__ == "__main__":
    sys.exit(main())
