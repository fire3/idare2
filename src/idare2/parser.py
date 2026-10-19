"""Command-line parsing: one input line becomes a list of statements.

The grammar is radare2's::

    [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...

Suffixes are peeled off **from the right**, which is the only order that makes
``pd 10 @ 0x1000~call`` mean "grep the output of the disassembly at 0x1000".
Everything here is a pure string transformation, so the whole grammar is
testable without a session.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from idare2.errors import UsageError

_OPEN = {"[": "]", "{": "}", "(": ")"}
_CLOSE = {v: k for k, v in _OPEN.items()}
_QUOTES = "'\"`"


@dataclass
class Statement:
    """One ``;``-separated command with all of its modifiers."""

    raw: str
    cmd: str = ""
    args: str = ""
    #: Repeat count from a leading integer (``3pd``).
    repeat: int = 1
    #: Leading ``.`` -- feed this statement's output back in as commands.
    dot: bool = False
    #: Leading ``!`` -- run through the shell.
    shell: bool = False
    #: Requesting ``<cmd>?``.
    help: bool = False
    #: Text after ``@`` (temporary seek / blocksize / range).
    tmpseek: str | None = None
    #: ``@@`` iterator spec.
    iterator: str | None = None
    #: ``@@@`` iterator spec (iterator with explicit sizes).
    iterator_size: str | None = None
    #: Text after ``~``.
    filter: str | None = None
    #: Text after ``|``.
    pipe: str | None = None
    #: Text after ``>`` / ``>>``.
    redirect: str | None = None
    append: bool = False

    @property
    def argv(self) -> list[str]:
        """``args`` split into whitespace-separated words, quotes honoured."""
        return split_args(self.args)


def split_args(text: str) -> list[str]:
    """Split an argument string on whitespace, honouring quotes."""
    out: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for ch in text:
        if quote is not None:
            if ch == quote:
                quote = None
            else:
                current.append(ch)
        elif ch in _QUOTES:
            quote = ch
        elif ch.isspace():
            if current:
                out.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        out.append("".join(current))
    return out


def split_statements(line: str) -> list[str]:
    """Split a line on top-level ``;`` or newlines.

    Newlines are separators too, so a ``-c`` argument written as a multi-line
    block behaves the way people expect without adding ``;`` everywhere.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    for ch in line:
        if quote is not None:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in _QUOTES:
            quote = ch
            current.append(ch)
            continue
        if ch in _OPEN:
            depth += 1
        elif ch in _CLOSE:
            depth = max(depth - 1, 0)
        elif (ch == ";" or ch == "\n") and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return [p for p in parts if p.strip()]


def _top_level(text: str) -> list[int]:
    """Indices of characters that sit outside quotes and outside brackets."""
    out: list[int] = []
    depth = 0
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in _QUOTES:
            quote = ch
            continue
        if ch in _OPEN:
            depth += 1
            continue
        if ch in _CLOSE:
            depth = max(depth - 1, 0)
            continue
        if depth == 0:
            out.append(i)
    return out


def _rfind_top(text: str, char: str) -> int:
    for i in reversed(_top_level(text)):
        if text[i] == char:
            return i
    return -1


def _find_top(text: str, char: str) -> int:
    for i in _top_level(text):
        if text[i] == char:
            return i
    return -1


def parse_statement(raw: str) -> Statement:
    """Parse one statement (no ``;`` inside)."""
    stmt = Statement(raw=raw)
    text = raw.strip()
    if not text:
        return stmt

    # 1. redirection -- rightmost top-level '>'
    index = _rfind_top(text, ">")
    if index >= 0:
        append = index > 0 and text[index - 1] == ">"
        stmt.append = append
        stmt.redirect = text[index + 1 :].strip()
        text = text[: index - 1 if append else index].rstrip()
        if not stmt.redirect:
            raise UsageError("redirection needs a file name")

    # 2. pipe -- rightmost top-level '|', but not the '||' operator
    index = _rfind_top(text, "|")
    while index >= 0 and (
        (index + 1 < len(text) and text[index + 1] == "|")
        or (index > 0 and text[index - 1] == "|")
    ):
        index = _rfind_top(text[:index], "|")
    if index >= 0:
        stmt.pipe = text[index + 1 :].strip()
        text = text[:index].rstrip()
        if not stmt.pipe:
            raise UsageError("pipe needs a command")

    # 3. grep -- leftmost top-level '~'.  This is peeled *before* '@' because
    #    r2's grep spec swallows everything to its right: `pd 3 @ main~add`
    #    greps the disassembly at main (verified against r2 6.2.5).
    index = _find_top(text, "~")
    if index >= 0:
        stmt.filter = text[index + 1 :]
        text = text[:index].rstrip()

    # 4. temporary seek -- rightmost top-level '@'
    index = _rfind_top(text, "@")
    if index >= 0:
        # Count the run of '@' so we know which operator this is.
        start = index
        while start > 0 and text[start - 1] == "@":
            start -= 1
        count = index - start + 1
        spec = text[index + 1 :].strip()
        if count >= 3:
            stmt.iterator_size = spec
        elif count == 2:
            stmt.iterator = spec
        else:
            stmt.tmpseek = spec
        text = text[:start].rstrip()
        if count >= 2 and not spec:
            raise UsageError("@ iteration needs an operand")

    # 5. prefixes: '.', '!', repeat count
    if text.startswith("."):
        stmt.dot = True
        text = text[1:].lstrip()
    elif text.startswith("!"):
        # `!cmd` runs a shell command: the whole remainder is the command, not
        # a command word plus arguments.
        stmt.shell = True
        stmt.args = text[1:].lstrip()
        return stmt

    # A bare number is radare2's shorthand for `s <number>`; check it before
    # the repeat prefix, which would otherwise read `0x1000` as "repeat 0".
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", text):
        stmt.cmd = "s"
        stmt.args = text
        return stmt

    match = re.match(r"(\d+)(.*)", text, re.DOTALL)
    if match and match.group(2).strip() and not match.group(2).strip()[0].isdigit():
        stmt.repeat = int(match.group(1))
        text = match.group(2).lstrip()

    if not text:
        return stmt

    # 6. command token + arguments
    parts = text.split(None, 1)
    cmd = parts[0]
    stmt.args = parts[1] if len(parts) > 1 else ""

    if cmd.endswith("?") and cmd not in ("?", "??", "???"):
        stmt.help = True
        cmd = cmd[:-1]
    elif cmd == "??":
        stmt.cmd = "?"
        stmt.args = "?"
        return stmt

    stmt.cmd = cmd
    return stmt


def parse(line: str) -> list[Statement]:
    """Parse a full input line into statements."""
    return [parse_statement(part) for part in split_statements(line)]


def is_command_line(text: str) -> bool:
    """Whether ``text`` looks like a command rather than data (used by ``.``)."""
    stripped = text.strip()
    if not stripped or stripped.startswith("#"):
        return False
    return bool(re.match(r"[!.\w?$]", stripped))
