"""Command registry and prefix matching.

radare2's commands are **character prefixes**, not words: ``pd``, ``pdf``,
``pdj``, ``pdb`` are four different commands, and ``aflj`` is ``afl`` plus a
``j`` modifier.  So dispatch is longest-prefix matching over declarative
patterns -- literal characters plus ``[...]`` classes, the same shape r2 uses in
its own help strings -- rather than a dictionary lookup.

The pattern doubles as the help table, which is why ``pd?`` cannot drift from
what ``pd`` actually accepts.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from idare2.errors import NotSupported

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

Handler = Callable[["Session", "Statement"], list[str]]


@dataclass
class Command:
    pattern: str
    handler: Handler
    usage: str = ""
    summary: str = ""
    #: True for commands that change the database (they need ``-w``).
    writes: bool = False
    #: Additional rows for the ``?`` help table: ``(token, args, description)``.
    detail: list[tuple[str, str, str]] = field(default_factory=list)
    #: ``<cmd>? <arg>`` is a *query*, not a help request (r2's ``f?name``).
    #: A bare ``<cmd>?`` still prints the help table.
    query_suffix: bool = False

    def __post_init__(self) -> None:
        self._literal = _literal_count(self.pattern)


REGISTRY: list[Command] = []

_LOADED = False


def load_all() -> None:
    """Import every command module so the ``@command`` decorators run."""
    global _LOADED
    if _LOADED:
        return
    # Imported for their side effect; the names are never referenced.
    from idare2.cmd import (  # noqa: F401
        analysis,
        extras,
        flag,
        info,
        meta,
        misc,
        search,
        seek,
        types,
        write,
    )
    from idare2.cmd import print as print_family  # noqa: F401

    _LOADED = True


def command(
    pattern: str,
    *,
    usage: str = "",
    summary: str = "",
    writes: bool = False,
    detail: list[tuple[str, str, str]] | None = None,
    query_suffix: bool = False,
):
    """Register a command implementation."""

    def decorate(function: Handler) -> Handler:
        REGISTRY.append(
            Command(
                pattern=pattern,
                handler=function,
                usage=usage,
                summary=summary,
                writes=writes,
                detail=list(detail or []),
                query_suffix=query_suffix,
            )
        )
        return function

    return decorate


def _literal_count(pattern: str) -> int:
    """How many fixed characters a pattern pins down.

    Used to break ties between equally long matches: ``pdf`` (3 literals) is a
    more specific answer for ``pdf`` than ``p[dD]f?`` would be.
    """
    total = 0
    in_class = False
    for char in pattern:
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif not in_class:
            total += 1
    return total


def match_pattern(pattern: str, text: str) -> int | None:
    """Characters of ``text`` consumed by ``pattern``, or ``None``."""
    i = 0
    j = 0
    while j < len(pattern):
        char = pattern[j]
        if char == "[":
            end = pattern.find("]", j)
            if end < 0:
                raise ValueError(f"unterminated class in pattern {pattern!r}")
            if i >= len(text) or text[i] not in pattern[j + 1 : end]:
                return None
            i += 1
            j = end + 1
        else:
            if i >= len(text) or text[i] != char:
                return None
            i += 1
            j += 1
    return i


def lookup(token: str) -> tuple[Command, str] | None:
    """Best command for ``token``, with the unmatched remainder.

    Longest match wins; ties go to the pattern with more literal characters.
    """
    best: tuple[Command, int] | None = None
    for cmd in REGISTRY:
        consumed = match_pattern(cmd.pattern, token)
        if consumed is None:
            continue
        if best is None:
            best = (cmd, consumed)
            continue
        _, best_consumed = best
        if consumed > best_consumed or (
            consumed == best_consumed and cmd._literal > best[0]._literal
        ):
            best = (cmd, consumed)
    if best is None:
        return None
    cmd, consumed = best
    return cmd, token[consumed:]


# --------------------------------------------------------------------------
# help generation
# --------------------------------------------------------------------------

_HELP_WIDTH = 24


def help_for(cmd: Command) -> list[str]:
    """The ``<cmd>?`` table, in r2's ``| <pattern>  <description>`` shape."""
    header = f"Usage: {cmd.pattern}"
    if cmd.usage:
        header += f" {cmd.usage}"
    lines = [header]
    rows = list(cmd.detail)
    if not rows and cmd.summary:
        rows = [(cmd.pattern, cmd.usage, cmd.summary)]
    for token, args, description in rows:
        label = f"{token} {args}".strip()
        lines.append(f"| {label.ljust(_HELP_WIDTH)}{description}")
    return lines


def help_index() -> list[str]:
    """The bare ``?`` listing: one line per command family."""
    seen: dict[str, Command] = {}
    for cmd in REGISTRY:
        head = cmd.pattern[0]
        seen.setdefault(head, cmd)
    lines = ["Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...", ""]
    for head in sorted(seen):
        cmd = seen[head]
        lines.append(f"| {head.ljust(_HELP_WIDTH)}{cmd.summary}")
    lines.append("")
    lines.append("Append '?' to any command to get detailed help (pd?, afl?, e?)")
    return lines


def all_commands() -> Iterator[Command]:
    return iter(REGISTRY)


def not_supported(name: str, reason: str) -> None:
    """Report a radare2 command idare2 deliberately does not implement."""
    raise NotSupported(f"'{name}' is not supported by idare2: {reason}")


def require_write(session: Session, what: str) -> None:
    """Gate a mutating command behind ``-w``."""
    from idare2.errors import ReadOnlyError

    if session.readonly:
        raise ReadOnlyError(f"{what} would modify the database; re-run with -w to allow writes")


_NUMERIC = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|\d+)$")


def numeric_args(
    session: Session, statement: Statement
) -> tuple[list[str], int | None, int]:
    """Split r2-style positional arguments from idare2's ``-n``/``-o``.

    radare2 spells the count positionally (``pd 10``); idare2 accepts that *and*
    ``-n 10``, because paginated listings need an explicit resume offset that r2
    gets from the terminal instead.

    Returns ``(positional, count, offset)``.
    """
    words = statement.argv
    count: int | None = None
    offset = 0
    rest: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in ("-n", "--count") and index + 1 < len(words):
            count = session.eval(words[index + 1])
            index += 2
            continue
        if word in ("-o", "--offset") and index + 1 < len(words):
            offset = session.eval(words[index + 1])
            index += 2
            continue
        rest.append(word)
        index += 1

    if rest and count is None and _NUMERIC.match(rest[0]):
        count = session.eval(rest[0])
        rest = rest[1:]
    return rest, count, offset


def with_more(lines: list[str], meta: dict | None) -> list[str]:
    """Append r2's ``[+more; resume with -o N]`` hint to a truncated page."""
    from idare2.fmt.listing import format_truncation

    return lines + format_truncation(meta)
