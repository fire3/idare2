"""Command-surface probe: which radare2 commands does idare2 support?

Reproduces the 2026-11-14 parity evaluation methodically:

1. read r2's ``X?`` help for every top-level command and extract the command
   tokens;
2. run one idare2 batch session that sends ``token?`` for every token
   (``?e MARK_<token>`` markers split the stream -- markers must not start
   with ``@@``, which the parser reads as an iterator modifier);
3. classify each token as *supported* (usage printed), *excluded* (r2's
   "'X' is not supported by idare2: ..." error) or *missing*.

Usage::

    python tools/cmdsurface.py --target /tmp/sample \\
        [--r2 r2] [--idare2 idare2] [--json out.json]

The target must live in a writable directory (IDA writes the IDB next to it).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

#: Top-level commands whose ``?`` help is harvested for tokens.
TOP_LEVEL = [
    "a", "b", "c", "C", "e", "f", "i", "p", "P", "s", "t", "T", "u",
    "w", "x", "y", "S", "U", "d", "L", "q", "_", "%", "$", "'", '"',
    "*", "/", "!", "=", "-", "o", "r", "g", "k", "l", "m", "v", "V",
    "z", ":", ",", "{", "#", "<", ".",
]

_TOKEN = re.compile(r"^\|\s*([^\s]+)")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.\-#]*")


def r2_tokens(r2: str) -> list[str]:
    """Every command name r2's help tree mentions, sorted."""
    tokens: set[str] = set()
    for letter in TOP_LEVEL:
        completed = subprocess.run(
            [r2, "-qq", "-N", "-e", "scr.color=0", "-c", f"{letter}?", "-"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        for line in completed.stdout.splitlines():
            match = _TOKEN.match(line)
            if not match:
                continue
            name = _NAME.match(match.group(1))
            if name:
                tokens.add(name.group(0))
    return sorted(tokens)


def probe_idare2(idare2: str, target: Path, tokens: list[str]) -> dict[str, str]:
    """Run ``token?`` for every token in one batch session."""
    with tempfile.TemporaryDirectory() as scratch:
        script = Path(scratch) / "probe.idare2"
        lines: list[str] = []
        for token in tokens:
            lines.append(f"?e MARK_{token}")
            lines.append(f"{token}?")
        script.write_text("\n".join(lines) + "\n")
        completed = subprocess.run(
            [idare2, "-N", "-q", "-i", str(script), str(target)],
            capture_output=True,
            text=True,
            timeout=1800,
        )
    return classify(tokens, completed.stdout, completed.stderr)


def classify(tokens: list[str], stdout: str, stderr: str) -> dict[str, str]:
    """Split one probe session's output into per-token verdicts."""
    results: dict[str, list[str]] = {}
    current: str | None = None
    for line in stdout.splitlines():
        if line.startswith("MARK_"):
            current = line[5:]
            results.setdefault(current, [])
        elif current is not None:
            results[current].append(line)

    unknown = set(re.findall(r"unknown command '([^']+)'", stderr))
    excluded = {
        name: reason.strip()
        for name, reason in re.findall(
            r"'([^']*)' is not supported by idare2: (.*?)(?:\n|$)", stderr
        )
    }
    verdicts: dict[str, str] = {}
    for token in tokens:
        text = "\n".join(results.get(token, []))
        if token in excluded:
            verdicts[token] = f"excluded: {excluded[token]}"
        elif token in unknown:
            verdicts[token] = "missing"
        elif text.strip():
            verdicts[token] = "supported"
        else:
            verdicts[token] = "missing"
    return verdicts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r2", default=shutil.which("r2") or "r2")
    parser.add_argument("--idare2", default=shutil.which("idare2") or "idare2")
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--json", dest="json_path", type=Path, default=None)
    args = parser.parse_args(argv)

    tokens = r2_tokens(args.r2)
    verdicts = probe_idare2(args.idare2, args.target, tokens)

    counts: dict[str, int] = {}
    excluded: dict[str, str] = {}
    for token, verdict in verdicts.items():
        kind = verdict.split(":")[0]
        counts[kind] = counts.get(kind, 0) + 1
        if verdict.startswith("excluded"):
            excluded[token] = verdict
    total = len(tokens)
    print(f"tokens={total}")
    for kind in sorted(counts):
        print(f"{kind:10} {counts[kind]:4} ({counts[kind] * 100 // total}%)")
    for token in sorted(excluded):
        print(f"  {token:12} {excluded[token]}")
    missing = sorted(t for t, v in verdicts.items() if v == "missing")
    if missing:
        print("missing:", " ".join(missing))
    if args.json_path:
        args.json_path.write_text(
            json.dumps({"tokens": tokens, "verdicts": verdicts}, indent=1)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
