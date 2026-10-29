"""Command-line interface; the library API has no argument-parser dependency."""

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from .export import convert


class Arguments(argparse.Namespace):
    input: Path
    output: Path
    companion: list[Path]
    report: Path | None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a legacy QDF v3 file to a new SQLite archive."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--companion", action="append", default=[], type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(None if argv is None else list(argv), namespace=Arguments())
    if args.report and args.report.exists():
        parser.error("Report already exists; choose a new path")
    try:
        report = convert(args.input, args.output, args.companion)
        encoded = json.dumps(report, indent=2) + "\n"
        if args.report:
            with args.report.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        print(encoded, end="")
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Recovery failed: {error}", file=sys.stderr)
        return 1
    return 0
