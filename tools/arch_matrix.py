#!/usr/bin/env python3
"""Run the architecture matrix and print one row per configuration.

The tests own the assertions; this script only drives pytest and turns its
JUnit report into a compact table::

    uv run tools/arch_matrix.py
    uv run tools/arch_matrix.py -k mips          # extra pytest arguments work
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Friendly names for the non-parametrized cases.
EXTRA_CASES = {"test_write_and_undo_on_a_private_copy": "write/undo"}


def _label(case: ET.Element) -> str:
    name = case.get("name", "?")
    if "[" in name and name.endswith("]"):
        return name[name.index("[") + 1 : -1]
    return EXTRA_CASES.get(name, name)


def _status(case: ET.Element) -> tuple[str, str]:
    for tag, label in (("failure", "fail"), ("error", "error"), ("skipped", "skip")):
        child = case.find(tag)
        if child is not None:
            detail = (child.get("message") or "").strip().splitlines()
            return label, detail[0] if detail else ""
    return "pass", ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="arch_matrix.py",
        description="Run `pytest -m arch_matrix` and summarise the result per CPU.",
        epilog="Unrecognised arguments are passed to pytest (e.g. -k mips).",
    )
    _options, extra = parser.parse_known_args(argv)

    with tempfile.TemporaryDirectory(prefix="idare2-arch-matrix-") as directory:
        report = Path(directory) / "report.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-m",
            "arch_matrix",
            "-q",
            "--tb=short",
            f"--junitxml={report}",
            *extra,
        ]
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        if not report.exists():
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            return completed.returncode or 1
        root = ET.parse(report).getroot()

    rows = [_status(case) + (_label(case),) for case in root.iter("testcase")]
    width = max((len(row[2]) for row in rows), default=10)
    print(f"{'architecture'.ljust(width)}  result  detail")
    print(f"{'-' * width}  ------  ------")
    for status, detail, label in rows:
        print(f"{label.ljust(width)}  {status:<6}  {detail}")

    failures = [row for row in rows if row[0] in ("fail", "error")]
    if failures:
        print()
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
