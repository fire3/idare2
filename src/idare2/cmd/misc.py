"""``?``, ``q``, ``b``, ``e``, ``L``, ``%``, ``T`` and the ``$`` variables."""

from __future__ import annotations

import base64
import json
import time
from typing import TYPE_CHECKING

from idare2 import cmd as cmd_module
from idare2.cmd import command
from idare2.errors import QuitRequested, UsageError
from idare2.fmt import addr_width
from idare2.fmt import listing as fmt_listing
from idare2.parser import Statement

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

QUESTION_DETAIL = [
    ("?", "expr", "evaluate a math expression"),
    ("?v", "expr", "show the hex value of an expression"),
    ("?vi", "[1248] expr", "signed decimal value, optionally truncated"),
    ("?vx", "expr", "zero-padded hexadecimal value"),
    ("?X", "expr", "bare hexadecimal value"),
    ("?x", "str", "hexpair of a string ('?x -hexpairs' converts back)"),
    ("?b", "num", "binary representation"),
    ("?o", "num", "octal representation"),
    ("?u", "num", "human-readable size"),
    ("?j", "expr", "the value as JSON"),
    ("?t", "cmd", "run a command and print the elapsed seconds"),
    ("?eb", "", "r2 progress bar (empty)"),
    ("?et", "title", "set the terminal title"),
    ("?(cond)", "{a}{b}", "run a or b depending on cond"),
    ("?e", "msg", "echo a message"),
    ("?h", "str", "radare2-compatible 32-bit DJB hash"),
    ("?l", "str", "string length"),
    ("?f", "num str", "map set bits to characters"),
    ("?s", "from to [step]", "number sequence"),
    ("?r", "[from] to", "random number"),
    ("?=", "expr", "set $? to an expression"),
    ("?P", "paddr", "physical to virtual address"),
    ("?p", "vaddr", "virtual to physical address"),
    ("?V", "", "version information"),
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

    if suffix == "t":
        # Time the nested command here: run_statement finishes after this
        # handler returns, so a session-level timer would report a stale value.
        if not argument:
            raise UsageError("?t needs a command")
        started = time.perf_counter()
        produced = session.run_branch(argument)
        return [*produced, f"{time.perf_counter() - started:.6f}"]
    if suffix == "et":
        # Terminal-title escape, byte-for-byte like r2.
        return [f"\x1b]0;{argument}\x07"]
    if suffix == "eb":
        return ["[]"]
    if statement.cmd.startswith("?("):
        joined = statement.cmd[1:] + (f" {statement.args}" if statement.args else "")
        return _conditional(session, joined)

    if suffix == "V":
        return _version_lines()
    if suffix == "h":
        if not argument:
            raise UsageError("?h needs a string")
        return [f"0x{_djb_hash(argument):08x}"]
    if suffix == "lq":
        session.last_result = len(argument)
        return []
    if suffix == "l":
        session.last_result = len(argument)
        return [str(session.last_result)]
    if suffix == "f":
        return _bit_flags(session, argument)
    if suffix == "s":
        return _sequence(session, argument)
    if suffix == "r":
        return _random_number(session, argument)
    if suffix == "=":
        if not argument:
            return [f"0x{session.last_result:x}"]
        session.eval(argument)
        return []
    if suffix == "==":
        return _string_compare(session, argument)
    if suffix in ("P", "p"):
        return _address_map(session, argument, physical_to_virtual=suffix == "P")

    if suffix == "e":
        return [argument]
    if suffix == "en":
        return [argument]
    if suffix == "ee":
        session.stderr(argument)
        return []

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

    if suffix.startswith(("eb", "et", "ne", "le", "ge", "eq")):
        raise UsageError(f"unsupported question command '?{suffix}' (see ?)")

    if not argument and suffix:
        raise UsageError(f"unsupported question command '?{suffix}' (see ?)")

    if not argument:
        return cmd_module.help_index()

    value = session.eval(argument)
    if suffix == "v":
        return [f"0x{value:x}"]
    if suffix == "q":
        return []
    if suffix == "vx":
        return [f"0x{value:08x}"]
    if suffix == "X":
        return [f"{value:x}"]
    if suffix.startswith("vi"):
        width = suffix[2:]
        if width and width not in ("1", "2", "4", "8"):
            raise UsageError(f"?vi{width}: width must be 1, 2, 4 or 8")
        bits = int(width) * 8 if width else 64
        mask = (1 << bits) - 1
        unsigned = value & mask
        signed = unsigned - (mask + 1) if unsigned > mask >> 1 else unsigned
        return [str(signed)]
    if suffix:
        raise UsageError(f"unsupported question command '?{suffix}' (see ?)")
    return _representations(value, session)


def _djb_hash(text: str) -> int:
    """r2's ``r_str_hash``: modified 64-bit DJB, truncated to 32 bits."""
    value = 5381
    mask = (1 << 64) - 1
    for byte in text.encode("utf-8"):
        value = ((value ^ ((value << 5) & mask)) ^ byte) & mask
    return value & 0xFFFFFFFF


def _bit_flags(session: Session, argument: str) -> list[str]:
    number, separator, letters = argument.partition(" ")
    if not separator or not letters:
        raise UsageError("?f needs a number and a bit string")
    value = session.eval(number)
    out = "".join(
        letter.upper() for index, letter in enumerate(letters) if value & (1 << index)
    )
    return [out]


def _sequence(session: Session, argument: str) -> list[str]:
    words = argument.split()
    if len(words) < 2:
        raise UsageError("?s needs from, to and an optional step")
    start = session.eval(words[0])
    end = session.eval(words[1])
    step = session.eval(words[2]) if len(words) > 2 else 1
    if step < 1:
        step = 1
    return [" ".join(str(value) for value in range(start, end + 1, step)) + " "]


def _random_number(session: Session, argument: str) -> list[str]:
    import random

    words = argument.split()
    if len(words) > 2:
        raise UsageError("?r takes at most two values")
    if not words:
        low, high = 0, 0x7FFFFFFF
    elif len(words) == 1:
        low, high = 0, session.eval(words[0])
    else:
        low, high = session.eval(words[0]), session.eval(words[1])
    value = low if high <= low else random.SystemRandom().randrange(low, high)
    session.last_result = value
    return [f"0x{value:x}"]


def _string_compare(session: Session, argument: str) -> list[str]:
    left, separator, right = argument.partition(" ")
    if not separator or not right:
        raise UsageError("?== needs two strings")
    result = (left > right) - (left < right)
    session.last_result = result
    return [str(result)]


def _address_map(session: Session, argument: str, *, physical_to_virtual: bool) -> list[str]:
    target = session.eval(argument) if argument else session.seek
    for segment in session.remote.call("segments"):
        vaddr = int(segment["vaddr"])
        vsize = int(segment["vsize"])
        paddr = segment.get("paddr")
        if paddr is None:
            continue
        paddr = int(paddr)
        if physical_to_virtual:
            if paddr <= target < paddr + vsize:
                return [f"0x{vaddr + target - paddr:08x}"]
        elif vaddr <= target < vaddr + vsize:
            return [f"0x{paddr + target - vaddr:08x}"]
    return [f"no map at 0x{target:08x}"]


def _version_lines() -> list[str]:
    from idare2 import __version__

    lines = [f"idare2      {__version__}"]
    try:
        import ida_nexus

        lines.append(f"ida-nexus   {ida_nexus.__version__}")
        lines.append(f"ida-domain  {ida_nexus.get_ida_domain_version()}")
    except Exception:
        lines.append("ida-nexus   unavailable")
    try:
        import ida_kernwin

        lines.append(f"ida         {ida_kernwin.get_kernel_version()}")
    except Exception:
        lines.append("ida         unavailable")
    return lines


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


def _conditional(session: Session, argument: str) -> list[str]:
    """``?(cond){then}{else}`` -- r2 runs the false branch on zero."""
    text = argument.strip()
    if not text.startswith("("):
        raise UsageError("?(cond) needs a parenthesised expression")
    close = text.find(")")
    if close < 0:
        raise UsageError("?(cond) is missing ')'")
    value = session.eval(text[1:close])
    rest = text[close + 1 :].strip()
    branches: list[str] = []
    while rest.startswith("{"):
        end = rest.find("}")
        if end < 0:
            raise UsageError("?(cond) is missing '}'")
        branches.append(rest[1:end])
        rest = rest[end + 1 :].strip()
    if rest:
        raise UsageError("?(cond) has trailing text")
    if not branches:
        raise UsageError("?(cond) needs a branch")
    selected = (
        (branches[1] if len(branches) > 1 else "") if value else branches[0]
    )
    return session.run_branch(selected) if selected.strip() else []


@command("q", usage="[ret]", summary="quit")
def quit_(session: Session, statement: Statement) -> list[str]:
    code = 0
    argument = statement.args.strip()
    if argument:
        code = session.eval(argument)
    raise QuitRequested(code)


BLOCK_DETAIL = [
    ("b", "[n]", "show or set the block size"),
    ("b+", "[n]", "increase the block size"),
    ("b-", "[n]", "decrease the block size"),
    ("b=", "[n]", "set the block size (r2 spelling)"),
    ("b*", "", "print the block size as an r2 command"),
    ("bj", "", "block size as JSON"),
]


@command(
    "b",
    usage="[n]",
    summary="block size",
    detail=BLOCK_DETAIL,
    json_suffix=True,
    suffixes=frozenset({"", "j", "*"}),
    suffix_prefixes=("+", "-", "="),
    suffix_label="blocksize modifier",
    suffix_help="b?",
)
def blocksize(session: Session, statement: Statement) -> list[str]:
    # r2 lets the argument be glued to the command (`b+16`, `b-16`), so the
    # suffix may carry the amount as well as the sign.
    suffix = statement.cmd[1:]
    argument = statement.args.strip()
    if suffix == "j":
        return [f'{{"blocksize":{session.blocksize}}}']
    if suffix == "*":
        return [f"b {session.blocksize}"]
    if suffix.startswith("="):
        value = suffix[1:].strip() or argument
        if not value:
            raise UsageError("b= needs a block size")
        session.blocksize = max(session.eval(value), 1)
        return []
    if suffix.startswith(("+", "-")):
        glued = suffix[1:].strip()
        amount = glued or argument
        delta = session.eval(amount) if amount else 1
        if suffix.startswith("-"):
            session.blocksize = max(session.blocksize - delta, 1)
        else:
            session.blocksize += delta
        return []
    if suffix:
        raise UsageError(f"unsupported blocksize modifier '{suffix}' (see b?)")
    if argument:
        session.blocksize = max(session.eval(argument), 1)
        return []
    return [str(session.blocksize)]


@command("%", usage="[name[=value]]", summary="environment variables")
def environment(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token == "%":
        return [f"{key}={value}" for key, value in session.env.items()]
    if token == "%j":
        return [json.dumps(session.env)]
    if token == "%*":
        return [f"%{key}={value}" for key, value in session.env.items()]
    suffix = token[1:]
    if not suffix:
        return [f"{key}={value}" for key, value in session.env.items()]
    if "=" in suffix:
        name, _, value = suffix.partition("=")
        session.env[name] = value
        return []
    if suffix in session.env:
        return [session.env[suffix]]
    raise UsageError(f"no environment variable {suffix!r}")


T_DETAIL = [
    ("T", "", "list log messages"),
    ("T message", "", "append a message"),
    ("T <id>", "", "list messages starting at id"),
    ("Tl", "", "last message id"),
    ("Tj", "", "messages as JSON"),
    ("Tm", "", "messages without ids"),
    ("T*", "", "messages as r2 commands"),
    ("T-", "", "clear the log"),
    ("T- <id>", "", "delete messages before id"),
]


@command(
    "T",
    usage="[-][ num|msg]",
    summary="text log",
    detail=T_DETAIL,
    suffixes=frozenset({"", "l", "j", "m", "*", "-"}),
    suffix_label="log command",
    suffix_help="T?",
)
def text_log(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    argument = statement.args.strip()
    entries = session.text_log

    if token == "T-":
        if argument:
            try:
                before = int(argument, 0)
            except ValueError:
                raise UsageError("T- needs a numeric id") from None
            session.text_log = [row for row in entries if int(row["id"]) >= before]
        else:
            session.text_log = []
        return []
    if token == "Tl":
        return [f"{int(entries[-1]['id']):02d}" if entries else "00"]
    if token == "Tj":
        return [json.dumps(entries)]
    if token == "Tm":
        return [str(row["msg"]) for row in entries]
    if token == "T*":
        return [
            f"T base64:{base64.b64encode(str(row['msg']).encode()).decode()}"
            for row in entries
        ]

    if argument:
        if argument.isdigit():
            start = int(argument)
            return [f"{row['id']} {row['msg']}" for row in entries if int(row["id"]) >= start]
        session.log(argument)
        return []
    return [f"{row['id']} {row['msg']}" for row in entries]


def _run_literal(session: Session, text: str) -> list[str]:
    """Run ``text`` as one command without peeling ``@``/``~``/``;``."""
    from idare2.parser import Statement

    text = text.strip()
    if not text:
        return []
    parts = text.split(None, 1)
    statement = Statement(
        raw=text,
        cmd=parts[0],
        args=parts[1] if len(parts) > 1 else "",
    )
    return session.run_statement(statement)


@command("'", usage="[cmd]", summary="run a command without evaluating special characters")
def quote_command(session: Session, statement: Statement) -> list[str]:
    text = statement.args
    if text.endswith("'"):
        text = text[:-1]
    return _run_literal(session, text)


@command('"', usage="[text]", summary="run a quoted command literally")
def quote_literal(session: Session, statement: Statement) -> list[str]:
    text = statement.args
    if text.endswith('"'):
        text = text[:-1]
    return _run_literal(session, text)


@command("*", usage="<addr>[=value]", summary="read or write a pointer")
def pointer(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    body = token[1:]
    if not body:
        raise UsageError("* needs an address")
    if "=" in body:
        address_text, _, value_text = body.partition("=")
        target = session.resolve(address_text)
        value = session.eval(value_text)
        cmd_module.require_write(session, "'*'")
        width = 8 if session.info.get("bits") == 64 else 4
        byteorder = "big" if session.info.get("endian") == "big" else "little"
        data = (value & ((1 << (width * 8)) - 1)).to_bytes(width, byteorder)
        session.remote.call("patch_bytes", ea=target, data=data.hex())
        session.invalidate_segments()
        return []
    target = session.resolve(body)
    width = 8 if session.info.get("bits") == 64 else 4
    payload = session.remote.call("read_value", ea=target, width=width)
    return [f"0x{int(payload['value']):x}"]


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


@command("_", usage="", summary="print the last output")
def last_output(session: Session, statement: Statement) -> list[str]:
    return list(session.last_output)
