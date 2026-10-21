"""Readline completion for the interactive REPL.

Completion is deliberately client-side and lazy.  Command names and config
keys are already in this process; flag and function names need one remote round
trip, which is cached until :meth:`Completer.invalidate` is called after a
command has had a chance to change the database or session flags.
"""

from __future__ import annotations

import contextlib
import itertools
import re
from typing import TYPE_CHECKING, Any

from idare2 import cmd, parser

if TYPE_CHECKING:
    from idare2.session import Session


_PLAIN_NAME = re.compile(r"[A-Za-z_.][A-Za-z0-9_.$:]*$")
_BUILTIN_VARS = frozenset({"", "b", "l", "s", "B", "e", "M", "o", "?"})


def _expand_pattern(pattern: str) -> set[str]:
    """Expand the ``[...]`` classes in a command pattern."""
    choices: list[list[str]] = []
    index = 0
    while index < len(pattern):
        if pattern[index] != "[":
            choices.append([pattern[index]])
            index += 1
            continue
        end = pattern.find("]", index + 1)
        if end < 0:
            choices.append([pattern[index]])
            index += 1
            continue
        choices.append(list(pattern[index + 1 : end]))
        index = end + 1
    return {"".join(parts) for parts in itertools.product(*choices)}


def command_names() -> list[str]:
    """Every concrete command name the registry can dispatch."""
    cmd.load_all()
    names: set[str] = set()
    for command in cmd.all_commands():
        names.update(_expand_pattern(command.pattern))
        for token, _args, _description in command.detail:
            token = token.strip()
            if token and " " not in token:
                names.add(token)
    return sorted(names)


class Completer:
    """Stateful readline completer with a one-shot remote-name cache."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._names: list[str] | None = None
        self._last_key: tuple[str, int, int] | None = None
        self._last_candidates: list[str] = []

    def invalidate(self) -> None:
        """Drop cached remote names and the per-completion result."""
        self._names = None
        self._last_key = None
        self._last_candidates = []

    def complete(self, text: str, state: int) -> str | None:
        """The callback signature required by :mod:`readline`."""
        try:
            import readline

            key = (
                readline.get_line_buffer(),
                readline.get_begidx(),
                readline.get_endidx(),
            )
        except (ImportError, AttributeError):
            key = (text, 0, len(text))
        if key != self._last_key:
            line, begin, end = key
            self._last_candidates = self.candidates(line, begin, end)
            self._last_key = key
        if state < len(self._last_candidates):
            return self._last_candidates[state]
        return None

    def candidates(self, line: str, begin: int, end: int) -> list[str]:
        """Candidates for ``line[begin:end]``, using the surrounding command."""
        begin = max(0, min(begin, len(line)))
        end = max(begin, min(end, len(line)))
        word = line[begin:end]

        statement_start = max(line.rfind(";", 0, begin), line.rfind("\n", 0, begin)) + 1
        before = line[statement_start:begin]
        words = parser.split_args(before)

        if not words:
            return self._prefixed(command_names(), word)

        command = words[0].lstrip(".")
        if command == "e" and len(words) == 1:
            if "=" in word:
                return []
            return self._prefixed(self.session.config.keys(), word)

        if word.startswith("$"):
            names = set(self.session.vars) | set(self.session.aliases) | _BUILTIN_VARS
            return self._prefixed({f"${name}" for name in names}, word)

        if word.startswith("@"):
            return self._prefixed({f"@{name}" for name in self._remote_names()}, word)

        if not word and words[-1] in ("@", "@@"):
            return list(self._remote_names())

        if not _PLAIN_NAME.fullmatch(word):
            return []
        return self._prefixed(self._remote_names(), word)

    def _remote_names(self) -> list[str]:
        if self._names is not None:
            return self._names

        names: set[str] = set()
        with contextlib.suppress(Exception):
            symbols, _ = self.session.remote.call_with_meta(
                "symbols", pattern=None, offset=0, count=-1
            )
            names.update(str(item["name"]) for item in symbols)
        with contextlib.suppress(Exception):
            functions, _ = self.session.remote.call_with_meta(
                "functions", pattern=None, offset=0, count=-1
            )
            names.update(str(item["name"]) for item in functions)

        # A session can already have local flags; include them without another
        # remote call when the symbol table was unavailable.
        with contextlib.suppress(Exception):
            names.update(flag.name for flag in self.session.flags.all())

        self._names = sorted(name for name in names if name)
        return self._names

    @staticmethod
    def _prefixed(names: Any, prefix: str) -> list[str]:
        return sorted({str(name) for name in names if str(name).startswith(prefix)})
