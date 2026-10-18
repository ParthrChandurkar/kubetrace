"""Command-line interface for fixture-driven diagnostics."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from kubetrace.engine import EvidenceValidationError, FixtureCollector, run_diagnostic
from kubetrace.reporting import report_payload, to_json, validation_error_payload


def _terminal_safe(value: str) -> str:
    """Escape control and non-ASCII characters before terminal display."""

    return value.encode("unicode_escape").decode("ascii")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kubetrace",
        description="Evaluate deterministic diagnostics from fixture evidence.",
    )
    parser.add_argument("fixture", help="path to a KubeTrace fixture JSON file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one fixture investigation and write JSON to stdout."""

    arguments = _parser().parse_args(argv)
    try:
        report = run_diagnostic(FixtureCollector(arguments.fixture))
    except EvidenceValidationError as error:
        print(to_json(validation_error_payload(error.errors)), end="")
        print(_terminal_safe(f"VALIDATION_ERROR: {error}"), file=sys.stderr)
        return 2

    print(to_json(report_payload(report)), end="")
    print(_terminal_safe(report.summary), file=sys.stderr)
    return 0
