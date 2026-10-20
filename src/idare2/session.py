"""Session state and the command execution pipeline.

Everything the user perceives as "where I am" lives here, not in IDA: the seek
(``$$``), the block size (``b``), flags (``f``), configuration (``e``) and the
seek history.  That is deliberate -- attaching to a GUI database must never
move the analyst's cursor, so ``s 0x1000`` changes a number in this process and
nothing else.

The pipeline for one statement is::

    resolve @tmpseek -> dispatch -> ~filter -> |pipe -> >redirect

with every stage working on ``list[str]``, which is what makes the modifiers
compose uniformly across all commands.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from idare2 import cmd, expr, parser, pipe
from idare2 import filter as grep
from idare2.config import Config
from idare2.errors import Idare2Error, UsageError
from idare2.flags import FlagStore
from idare2.fmt.colors import Colors
from idare2.parser import Statement

#: r2's default block size.
DEFAULT_BLOCKSIZE = 0x100

_NAME_RE = re.compile(r"[A-Za-z_.][A-Za-z0-9_.$:]*")


@dataclass
class SearchState:
    """What ``//`` repeats and what ``/@:0`` reads."""

    kind: str
    pattern: str
    last_hit: int | None = None


class Session:
    """One attached database plus all client-side state."""

    def __init__(
        self,
        handle: Any,
        remote: Any,
        config: Config,
        info: dict[str, Any],
        *,
        readonly: bool = True,
    ) -> None:
        self.handle = handle
        self.remote = remote
        self.config = config
        self.info = info
        self.readonly = readonly

        self.colors = Colors(config.get_int("scr.color"))
        self._resolve_color()
        base = info.get("start_ip") or info.get("base_address") or 0
        self.seek = int(base)
        self.blocksize = DEFAULT_BLOCKSIZE
        self.flags = FlagStore()
        self.vars: dict[str, int] = {}
        self.aliases: dict[str, str] = {}
        self.seek_history: list[int] = []
        self.seek_future: list[int] = []
        self.last_output: list[str] = []
        self.last_result = 0
        #: Monotonic counter behind r2's ``hit<N>_<i>`` flag labels.
        self.search_counter = 0
        self.last_search: SearchState | None = None
        self._segments: list[dict[str, Any]] | None = None
        #: Patches buffered by `e io.cache=true`; `wc+` commits them together.
        self.write_cache: list[tuple[int, bytes]] = []
        #: The `y` clipboard.
        self.yank: bytes = b""
        #: Set by ``-j``: commands with a JSON form default to it.
        self.json_default = False
        #: Set once any statement in this session has failed.
        self.failed = False
        self.last_error: Idare2Error | None = None
        self._warned: set[str] = set()
        self._comments: dict[int, str] = {}
        # Command modules register themselves on import; doing it here means a
        # Session is usable on its own, without going through the CLI.
        cmd.load_all()

    def setup(self) -> None:
        """Reflect facts that are derived from the attached database.

        ``ida.backend``, ``ida.instance`` and ``ida.hexrays`` are read-only
        config keys precisely because idare2 derives them rather than owning
        them, so they are written through ``reflect`` and never by the user.
        """
        instance = self.handle.instance
        self.config.reflect("ida.backend", getattr(instance, "backend", ""))
        self.config.reflect("ida.instance", getattr(instance, "record_id", ""))
        self.config.reflect("ida.hexrays", bool(self.info.get("hexrays")))
        self.config.reflect("cfg.bigendian", self.info.get("endian") == "big")
        self._resolve_color()

    def _resolve_color(self) -> None:
        """Colour follows the tty unless the user asked for it explicitly.

        Without this, ``idare2 -qc 'pd 10' file | grep call`` would emit ANSI
        escapes into the pipe.
        """
        mode = self.config.get_int("scr.color")
        if mode > 0 and "scr.color" not in self.config.explicit and not sys.stdout.isatty():
            mode = 0
        self.colors.mode = mode

    # -- Resolver protocol (used by expr) ----------------------------------

    def lookup_name(self, name: str) -> int | None:
        # Already-seeded flags win; then the pure dummy-name parse, which needs
        # no round trip at all (`sub_15E10` carries its own address).
        if self.flags.seeded:
            found = self.flags.lookup(name)
            if found is not None:
                return found
        embedded = _dummy_address(name)
        if embedded is not None:
            return embedded

        self._ensure_flags()
        found = self.flags.lookup(name)
        if found is not None:
            return found
        if name in self.aliases:
            return self.eval(self.aliases[name])
        return None

    def get_var(self, name: str) -> int | None:
        if name in self.vars:
            return self.vars[name]
        # `$alias` is how r2 spells "a named expression", so aliases are
        # variables too -- without this `pd 1 @ $main_addr` says "unknown
        # variable" even though `$main_addr` was just defined.
        if name in self.aliases:
            return self.eval(self.aliases[name])
        builtins = {
            "": self.seek,  # $$
            "b": self.blocksize,
            "l": self.seek_history[-1] if self.seek_history else self.seek,
            "s": int(self.info.get("filesize") or 0),
            "B": int(self.info.get("base_address") or 0),
            "e": int(self.info.get("start_ip") or 0),
            "M": self.seek,
            "o": self.seek,
            "?": self.last_result,
        }
        return builtins.get(name)

    def deref(self, addr: int, size: int) -> int:
        payload = self.remote.call("read_value", ea=addr, width=size)
        return int(payload["value"])

    # -- expressions -------------------------------------------------------

    def eval(self, text: str) -> int:
        """Evaluate an expression, remembering the result in ``$?``."""
        value = expr.evaluate(text, self)
        self.last_result = value
        return value

    def resolve(self, text: str | None, *, default: int | None = None) -> int:
        """Resolve an address argument, falling back to the current seek."""
        if text is None or not text.strip():
            if default is not None:
                return default
            return self.seek
        return self.eval(text.strip())

    # -- seek --------------------------------------------------------------

    def seek_to(self, ea: int) -> None:
        if ea != self.seek:
            self.seek_history.append(self.seek)
            self.seek_future.clear()
        self.seek = ea

    # -- execution ---------------------------------------------------------

    def run(
        self,
        line: str,
        emit: Callable[[list[str]], None] | None = None,
    ) -> list[str]:
        """Execute a full input line and return the text it produced.

        A failing statement is reported and the rest of the line still runs,
        which is what r2 does: ``?e one; bogus; ?e three`` prints all three.
        Errors go to stderr so they never contaminate ``|`` or ``>``, and the
        first failure sets :attr:`failed` so the CLI can choose an exit code.

        ``emit`` receives each statement's output as soon as it is produced.
        Without it the whole line's output is buffered and returned, which is
        what tests want -- but for a multi-statement ``-c`` the CLI needs the
        streaming form, otherwise stdout is flushed after the errors that
        happened later and the output reads out of order.
        """
        out: list[str] = []
        for statement in parser.parse(line):
            try:
                produced = self.run_statement(statement)
            except Idare2Error as exc:
                # UsageError is an Idare2Error subclass, so this covers both.
                self.failed = True
                self.last_error = exc
                self.stderr(self.colors.error(f"ERROR: {exc}"))
                continue
            out.extend(produced)
            if emit is not None:
                emit(produced)
        self.last_output = out
        return out

    def run_statement(self, statement: Statement) -> list[str]:
        if statement.shell:
            return pipe.run_shell(statement.args)

        lines: list[str] = []
        for _ in range(max(statement.repeat, 1)):
            with self._temporary(statement):
                lines = self.dispatch(statement)
        return self.postprocess(lines, statement)

    def dispatch(self, statement: Statement) -> list[str]:
        if statement.dot:
            return self._dot_source(statement)
        if statement.iterator is not None or statement.iterator_size is not None:
            return self._iterate(statement)
        return self.invoke(statement)

    def invoke(self, statement: Statement) -> list[str]:
        found = cmd.lookup(statement.cmd)
        if found is None:
            raise _unknown(statement.cmd)
        command, _remainder = found
        # `f? name` is a query, not a help request -- but only for commands that
        # opted in, so `pd? foo` keeps printing the pd table, and a bare `f?`
        # still does too.
        if statement.help and (
            not command.query_suffix or not statement.args.strip()
        ):
            return cmd.help_for(command)
        if command.writes:
            cmd.require_write(self, f"'{statement.cmd}'")
        return command.handler(self, statement)

    def postprocess(self, lines: list[str], statement: Statement) -> list[str]:
        """Apply ``~``, ``|`` and ``>`` to one statement's output."""
        if statement.filter is not None:
            lines = self._apply_filter(lines, statement.filter)
        if statement.pipe:
            lines = pipe.run_pipe(lines, statement.pipe)
        if statement.redirect:
            pipe.redirect(lines, statement.redirect, append=statement.append)
            return []
        return lines

    def _apply_filter(self, lines: list[str], spec: str) -> list[str]:
        try:
            parsed = grep.parse(spec)
        except grep._GrepHelp:
            return grep.GREP_HELP.rstrip("\n").splitlines()
        for modifier in parsed.unimplemented:
            self.warn_once(
                f"filter-{modifier}", f"~{modifier} is not implemented by idare2 and was ignored"
            )
        return parsed.apply(lines)

    # -- temporaries -------------------------------------------------------

    @contextmanager
    def _temporary(self, statement: Statement) -> Iterator[None]:
        """Apply ``@`` for the duration of one statement.

        Only statements that actually carry a temporary seek save and restore
        the seek.  Restoring unconditionally would undo ``s 0x1000`` itself,
        which is a permanent seek.
        """
        if not statement.tmpseek:
            yield
            return
        saved_seek = self.seek
        saved_blocksize = self.blocksize
        try:
            self._apply_tmpseek(statement.tmpseek)
            yield
        finally:
            self.seek = saved_seek
            self.blocksize = saved_blocksize

    def _apply_tmpseek(self, spec: str) -> None:
        spec = spec.strip()
        if spec.startswith("!"):
            self.blocksize = self.resolve(spec[1:])
            return
        if spec.startswith("{"):
            inner = spec[1:].rstrip("}").strip()
            parts = inner.split()
            if parts:
                self.seek = self.resolve(parts[0])
            return
        for prefix, setter in (
            ("e:", self._tmp_config),
            ("f:", self._tmp_flagspace),
            ("s:", self._tmp_string),
        ):
            if spec.startswith(prefix):
                setter(spec[len(prefix) :])
                return
        self.seek = self.resolve(spec)

    def _tmp_config(self, spec: str) -> None:
        for assignment in spec.split(","):
            if "=" in assignment:
                key, _, value = assignment.partition("=")
                self.config.set(key.strip(), value.strip())

    def _tmp_flagspace(self, spec: str) -> None:
        self.warn_once("flagspace", "@f: flag spaces are not implemented by idare2 and were ignored")

    def _tmp_string(self, spec: str) -> None:
        self.seek = self.eval(spec)

    # -- iterators ---------------------------------------------------------

    def _iterate(self, statement: Statement) -> list[str]:
        spec = statement.iterator or statement.iterator_size or ""
        inner = replace(statement, iterator=None, iterator_size=None, tmpseek=None)
        lines: list[str] = []
        for ea in self._iterator_addresses(spec):
            lines.extend(self.run_statement(replace(inner, tmpseek=f"0x{ea:x}")))
        return lines

    def _iterator_addresses(self, spec: str) -> list[int]:
        spec = spec.strip()
        if spec.startswith("="):
            body = spec[1:].lstrip("=").strip()
            if not body:
                return []
            return [self.eval(word) for word in body.split()]
        if spec.startswith("s:"):
            parts = spec[2:].split()
            if len(parts) < 2:
                raise UsageError("@@s: needs a start, an end and an optional step")
            start, end = self.eval(parts[0]), self.eval(parts[1])
            step = self.eval(parts[2]) if len(parts) > 2 else 1
            if step <= 0:
                raise UsageError("@@s: step must be positive")
            return list(range(start, end, step))
        if spec == "f" or spec.startswith("f:"):
            pattern = spec[2:] if spec.startswith("f:") else None
            payload, _ = self.remote.call_with_meta(
                "functions", pattern=pattern, offset=0, count=-1
            )
            return [int(item["ea"]) for item in payload]
        if spec == "i":
            payload, _ = self.remote.call_with_meta(
                "disasm", ea=self.seek, count=-1, mode="function"
            )
            return [int(line["ea"]) for line in payload.get("lines", [])]
        if spec == "b":
            payload = self.remote.call("blocks", ea=self.seek)
            return [int(block["start"]) for block in payload]
        if spec.startswith(":"):
            return []
        # Anything else is a flag glob.
        self._ensure_flags()
        return [flag.ea for flag in self.flags.all() if _glob(spec, flag.name)]

    # -- dot-sourcing ------------------------------------------------------

    def _dot_source(self, statement: Statement) -> list[str]:
        """``.cmd`` -- run this statement, then run its output as commands."""
        inner = replace(statement, dot=False)
        lines = self.run_statement(inner)
        out: list[str] = []
        for line in lines:
            if parser.is_command_line(line):
                out.extend(self.run(line))
        return out

    # -- flags -------------------------------------------------------------

    def search_segments(self) -> list[dict[str, Any]]:
        """Cached segment table, used to resolve ``e search.in=io.maps``."""
        if self._segments is None:
            self._segments = self.remote.call("search_ranges")
        return self._segments

    def invalidate_segments(self) -> None:
        self._segments = None

    def config_display_only(self) -> frozenset[str]:
        """Derived keys that a project should not try to restore."""
        return frozenset({"ida.backend", "ida.instance", "ida.hexrays", "cfg.bigendian"})

    def _ensure_flags(self) -> None:
        if self.flags.seeded:
            return
        payload, _ = self.remote.call_with_meta("symbols", offset=0, count=-1)
        self.flags.seed((int(item["ea"]), item["name"]) for item in payload)

    def write_flag(self, name: str, ea: int, size: int = 1) -> bool:
        """Create a flag, writing it into the IDB when that is allowed."""
        write_through = (
            not self.readonly and self.config.get_bool("ida.flags.write")
        )
        if write_through:
            try:
                self.remote.call("set_name", ea=ea, name=name)
            except Idare2Error as exc:
                self.warn_once("flag-write", f"could not write the name into the IDB: {exc}")
                write_through = False
        elif not self.readonly:
            pass
        else:
            self.warn_once(
                "readonly-flags",
                "flags are session-local; re-run with -w to write names into the database",
            )
        self.flags.add(name, ea, size, local=not write_through)
        return write_through

    # -- comments (cached per statement) -----------------------------------

    def comment_at(self, ea: int) -> str:
        return self._comments.get(ea, "")

    def prime_comments(self, mapping: dict[int, str]) -> None:
        self._comments = mapping

    # -- diagnostics -------------------------------------------------------

    def warn_once(self, key: str, message: str) -> None:
        if key in self._warned:
            return
        self._warned.add(key)
        self.stderr(self.colors.warn(f"WARN: {message}"))

    def stderr(self, message: str) -> None:
        """Emit a diagnostic.  Overridden by the CLI to reach real stderr."""
        print(message, file=sys.stderr)

    # -- display helpers ---------------------------------------------------

    @property
    def addr_width(self) -> int:
        from idare2.fmt import addr_width

        return addr_width(self.info.get("bits"))

    def format_addr(self, ea: int) -> str:
        from idare2.fmt import fmt_addr

        return fmt_addr(ea, self.addr_width)

    def prompt(self) -> str:
        return f"[{self.format_addr(self.seek)}]> "


def _unknown(token: str) -> Idare2Error:
    from idare2.errors import UnknownCommand

    known = {
        "d": "the debugger",
        "ae": "ESIL",
        "g": "the r_egg shellcode generator",
        "k": "the sdb key-value store",
        "m": "the magic/fs subsystem",
        "z": "zignatures",
        "Z": "zignatures",
        "V": "visual mode",
        "v": "panels mode",
        "=": "remote commands",
        "#": "the rlang hashbang",
        "o": "opening files (use --idb to target another database)",
        "r": "resizing the file",
        "y": "the yank clipboard",
    }
    reason = known.get(token)
    if reason:
        return UnknownCommand(f"'{token}' is not supported by idare2: {reason} is a radare2 feature")
    return UnknownCommand(f"unknown command '{token}' (see '?' for the command list)")


def _dummy_address(name: str) -> int | None:
    match = re.fullmatch(
        r"(?:sub|loc|locret|off|seg|asc|byte|word|dword|qword|oword|xmmword|ymmword|zmmword"
        r"|flt|dbl|tbyte|packreal|stru|unk|algn|def|jpt|custdata)_([0-9A-Fa-f]+)",
        name,
    )
    return int(match.group(1), 16) if match else None


def _glob(pattern: str, name: str) -> bool:
    return fnmatch.fnmatch(name, pattern)
