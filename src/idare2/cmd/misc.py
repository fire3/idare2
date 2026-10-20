"""``?``, ``q``, ``b``, ``e``, ``L`` and the ``$`` variables."""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2 import cmd as cmd_module
from idare2.cmd import command
from idare2.errors import QuitRequested, UsageError
from idare2.fmt import addr_width
from idare2.fmt import listing as fmt_listing

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

QUESTION_DETAIL = [
    ("?", "expr", "evaluate a math expression"),
    ("?v", "expr", "show the hex value of an expression"),
    ("?x", "str", "hexpair of a string ('?x -hexpairs' converts back)"),
    ("?b", "num", "binary representation"),
    ("?o", "num", "octal representation"),
    ("?u", "num", "human-readable size"),
    ("?j", "expr", "the value as JSON"),
    ("?e", "msg", "echo a message"),
    ("?$", "", "list the $ variables"),
    ("?@?", "", "help for @ (temporary seek)"),
    ("?~?", "", "help for ~ (internal grep)"),
    ("?|?", "", "help for | (pipe)"),
]


@command("?", usage="[expr]", summary="help or evaluate an expression", detail=QUESTION_DETAIL)
def question(session: Session, statement: Statement) -> list[str]:
    argument = statement.args.strip()
    suffix = statement.cmd[1:]

    if not argument and not suffix:
        return cmd_module.help_index()

    if suffix == "?" or argument == "?":
        return cmd_module.help_index()

    if suffix == "$":
        return _variables(session)
    if suffix == "@":
        return _AT_HELP
    if suffix == "~":
        from idare2.filter import GREP_HELP

        return GREP_HELP.rstrip("\n").splitlines()
    if suffix == "|":
        return _PIPE_HELP

    if suffix == "e":
        return [argument]
    if suffix == "n":
        return [argument]

    if suffix == "x":
        return _hexpair(argument)
    if suffix == "b":
        return [bin(session.eval(argument))[2:]]
    if suffix == "o":
        return [oct(session.eval(argument))]
    if suffix == "u":
        return [fmt_listing.human_size(session.eval(argument))]
    if suffix == "j":
        import json

        return [json.dumps(session.eval(argument))]

    if not argument:
        return cmd_module.help_index()

    value = session.eval(argument)
    if suffix == "v":
        return [f"0x{value:x}"]
    if suffix == "q":
        return []
    return _representations(value, session)


def _representations(value: int, session: Session) -> list[str]:
    """r2's full ``?`` block: every way of reading the same number."""
    width = addr_width(session.info.get("bits"))
    mask = (1 << (width * 4)) - 1
    unsigned = value & mask
    signed = unsigned - (mask + 1) if unsigned > mask >> 1 else unsigned
    binary = bin(unsigned & 0xFFFF)[2:]
    return [
        f"int32   {signed}",
        f"uint32  {unsigned}",
        f"hex     0x{unsigned:x}",
        f"octal   0{unsigned:o}",
        f"unit    {fmt_listing.human_size(unsigned)}",
        f"segment {unsigned >> 16:04x}:{unsigned & 0xFFFF:04x}",
        f"binary  0b{binary}",
    ]


def _hexpair(argument: str) -> list[str]:
    if argument.startswith("-"):
        raw = argument[1:]
        try:
            return [bytes.fromhex(raw).decode("utf-8", errors="replace")]
        except ValueError:
            raise UsageError(f"?x -{raw}: not a hexpair string") from None
    return [argument.encode("utf-8").hex()]


def _variables(session: Session) -> list[str]:
    rows = [
        ("$$", session.format_addr(session.seek), "current seek"),
        ("$b", str(session.blocksize), "block size"),
        ("$s", str(session.info.get("filesize") or 0), "file size"),
        ("$B", session.format_addr(int(session.info.get("base_address") or 0)), "base address"),
        ("$e", session.format_addr(int(session.info.get("start_ip") or 0)), "entry point"),
        ("$?", str(session.last_result), "last command result"),
    ]
    return [f"{name:<6} {value:<20} {help}" for name, value, help in rows]


_AT_HELP = [
    "Usage: [cmd] @ [addr|expr]      # temporary seek for one command",
    "| pd 10 @ 0x1000                 # disassemble at 0x1000",
    "| pd 10 @ main+0x40              # expressions and names work",
    "| p8 16 @!64                     # @!N sets a temporary block size",
    "| pd 10 @{0x1000 0x2000}         # @{from to} sets a range",
    "| pd 5 @@f                       # @@ iterates over every function",
    "| pd 5 @@=0x1000 0x2000 0x3000   # @@= takes an explicit address list",
    "| pd 5 @@i                       # @@i iterates the current function",
]

_PIPE_HELP = [
    "Usage: [cmd] | [shell command]   # pipe the output",
    "| pd 10 | head -3                # pipe to a shell command",
    "| pd 10 > out.txt                # write to a file",
    "| pd 10 >> out.txt               # append to a file",
    "| !ls                            # run a shell command",
    "| pd 10~call                     # internal grep (see ~?)",
]


@command("q", usage="[ret]", summary="quit")
def quit_(session: Session, statement: Statement) -> list[str]:
    code = 0
    argument = statement.args.strip()
    if argument:
        code = session.eval(argument)
    raise QuitRequested(code)


@command("b", usage="[n]", summary="block size", json_suffix=True)
def blocksize(session: Session, statement: Statement) -> list[str]:
    # r2 lets the argument be glued to the command (`b+16`, `b-16`), so the
    # suffix may carry the amount as well as the sign.
    suffix = statement.cmd[1:]
    argument = statement.args.strip()
    if suffix == "j":
        return [f'{{"blocksize":{session.blocksize}}}']
    if suffix.startswith(("+", "-")):
        glued = suffix[1:].strip()
        amount = glued or argument
        delta = session.eval(amount) if amount else 1
        if suffix.startswith("-"):
            session.blocksize = max(session.blocksize - delta, 1)
        else:
            session.blocksize += delta
        return []
    if argument:
        session.blocksize = max(session.eval(argument), 1)
        return []
    return [str(session.blocksize)]


@command("e", usage="[key[=value]]", summary="configuration")
def config(session: Session, statement: Statement) -> list[str]:
    argument = statement.args.strip()
    suffix = statement.cmd[1:]
    if suffix == "?":
        return _config_help(session, argument)
    if not argument:
        return [
            f"{key.ljust(24)}{session.config.format_value(key)}"
            for key in session.config
        ]
    if "=" not in argument:
        key = argument.rstrip("?")
        if argument.endswith("?"):
            return _config_help(session, key)
        return [session.config.format_value(key)]
    key, _, value = argument.partition("=")
    session.config.set(key.strip(), value.strip())
    if key.strip() == "scr.color":
        session.colors.mode = session.config.get_int("scr.color")
    return []


def _config_help(session: Session, prefix: str) -> list[str]:
    lines = []
    for name in session.config.keys(prefix or None):
        key = session.config.describe(name)
        flag = " [read-only]" if key.readonly else ""
        lines.append(f"{name.ljust(24)}{session.config.format_value(name).ljust(10)} {key.help}{flag}")
    return lines


@command("L", usage="", summary="list registered databases")
def list_databases(session: Session, statement: Statement) -> list[str]:
    from idare2 import nexus

    rows = nexus.list_databases()
    if statement.cmd == "LL":
        return [
            f"backend   {getattr(session.handle.instance, 'backend', '?')}",
            f"record-id {getattr(session.handle.instance, 'record_id', '?')}",
            f"pid       {getattr(session.handle.instance, 'pid', '?')}",
            f"path      {session.info.get('path') or ''}",
        ]
    return fmt_listing.format_databases(rows, session)


@command("$", usage="[var]", summary="show $ variables")
def variables(session: Session, statement: Statement) -> list[str]:
    argument = statement.args.strip()
    if argument:
        value = session.get_var(argument.lstrip("$"))
        if value is None:
            raise UsageError(f"unknown variable ${argument}")
        return [session.format_addr(int(value))]
    return _variables(session)


@command("_", usage="", summary="print the last output")
def last_output(session: Session, statement: Statement) -> list[str]:
    return list(session.last_output)
