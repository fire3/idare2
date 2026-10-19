"""``|`` pipes, ``>`` redirection and ``!`` shell escape.

These are the only places idare2 shells out, so they live together.  They take
and return plain line lists, which keeps the command pipeline uniform: every
stage between the remote call and the terminal is ``list[str] -> list[str]``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from idare2.errors import CommandError, UsageError


def run_pipe(lines: list[str], command: str) -> list[str]:
    """Feed ``lines`` to ``command`` and return its stdout as lines."""
    if not command.strip():
        raise UsageError("empty pipe command")
    try:
        completed = subprocess.run(
            command,
            shell=True,
            input="\n".join(lines) + ("\n" if lines else ""),
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise CommandError(f"pipe failed: {exc}") from exc
    if completed.returncode != 0 and completed.stderr:
        # r2 forwards the command's stderr and keeps going.
        raise CommandError(completed.stderr.rstrip())
    return completed.stdout.splitlines()


def run_shell(command: str) -> list[str]:
    """Run ``!cmd`` and return its output as lines."""
    try:
        completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    except OSError as exc:
        raise CommandError(f"shell command failed: {exc}") from exc
    out = completed.stdout.splitlines()
    if completed.returncode != 0 and completed.stderr:
        raise CommandError(completed.stderr.rstrip())
    return out


def redirect(lines: list[str], target: str, *, append: bool = False) -> None:
    """Write ``lines`` to ``target`` (``>`` / ``>>``)."""
    path = Path(target).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a" if append else "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line)
                handle.write("\n")
    except OSError as exc:
        raise CommandError(f"cannot write {target}: {exc}") from exc


def capture(command: str) -> str:
    """Run a command and return its stdout as one string (backtick ``cmd``)."""
    try:
        completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    except OSError as exc:
        raise CommandError(f"shell command failed: {exc}") from exc
    return completed.stdout.rstrip("\n")
