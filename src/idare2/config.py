"""The ``e`` configuration table.

Keys follow radare2 where idare2 has the same concept, so muscle memory and
scripts carry over.  A handful of keys are **read-only** because IDA owns the
underlying fact: ``asm.arch`` and ``asm.bits`` reflect the database, and cannot
be changed mid-session any more than IDA can swap disassemblers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from idare2.errors import UsageError

BOOL = "bool"
INT = "int"
STR = "str"


@dataclass(frozen=True)
class Key:
    name: str
    default: Any
    kind: str
    help: str = ""
    readonly: bool = False
    #: Only meaningful when ``kind`` is ``INT``.
    minimum: int | None = None
    maximum: int | None = None


KEYS: tuple[Key, ...] = (
    # -- screen ------------------------------------------------------------
    Key("scr.color", 1, INT, "colour mode: 0 off, 1 on, 2 more, 3 rainbow", minimum=0, maximum=3),
    Key("scr.null", False, BOOL, "discard command output"),
    Key("scr.prompt", True, BOOL, "show the prompt"),
    Key("scr.interactive", True, BOOL, "interactive session"),
    Key("scr.rows", 0, INT, "terminal rows (0 = auto)", minimum=0),
    Key("scr.cols", 0, INT, "terminal columns (0 = auto)", minimum=0),
    Key("scr.pager", "", STR, "pager command for long output"),
    # -- disassembly -------------------------------------------------------
    Key("asm.bytes", True, BOOL, "show the instruction bytes column"),
    Key("asm.bytespace", True, BOOL, "put a space between byte groups"),
    Key("asm.lines", True, BOOL, "show the flow gutter inside functions"),
    Key("asm.comments", True, BOOL, "show the comment column"),
    #: r2 6.2.5's default, measured: comments start at an absolute column, not
    #: a dynamic one, so a long instruction pushes its own comment out rather
    #: than shifting the whole block.
    Key("asm.cmt.col", 71, INT, "absolute column where comments start", minimum=1),
    Key("asm.flags", True, BOOL, "resolve names in the disassembly text"),
    Key("asm.offset", True, BOOL, "show the address column"),
    Key("asm.sub.names", True, BOOL, "show IDA's sub_/loc_ dummy names"),
    Key("asm.describe", False, BOOL, "describe operands"),
    Key("asm.emu", False, BOOL, "reserved; idare2 does not emulate"),
    #: Derived from the database, like cfg.bigendian.  They exist so scripts
    #: that read `e asm.arch` work; `set()` refuses them, because the only way
    #: to change the architecture is to import the file with -a/-b.
    Key("asm.arch", "unknown", STR, "architecture (reflects the database)", readonly=True),
    Key("asm.bits", 0, INT, "word size in bits (reflects the database)", readonly=True),
    # -- hexdump -----------------------------------------------------------
    Key("hex.cols", 16, INT, "bytes per hexdump row", minimum=1, maximum=64),
    Key("hex.pairs", True, BOOL, "group hexdump bytes in pairs"),
    Key("hex.offset", True, BOOL, "show the offset column"),
    Key("hex.ascii", True, BOOL, "show the ASCII column"),
    Key("hex.header", True, BOOL, "show the hexdump header row"),
    # -- general -----------------------------------------------------------
    Key("cfg.bigendian", False, BOOL, "big-endian mode (reflects the database)", readonly=True),
    Key("cfg.debug", False, BOOL, "debugger mode (idare2 has none)", readonly=True),
    Key("cfg.editor", "", STR, "editor for `-` and `CC!` (defaults to $EDITOR)"),
    Key("cfg.sandbox", False, BOOL, "refuse every write operation"),
    Key("cfg.fortunes", False, BOOL, "print a tip on startup"),
    # -- search ------------------------------------------------------------
    Key("search.in", "io.maps", STR, "search scope: io.maps or raw"),
    Key("search.from", 0, INT, "search start address (0 = auto)", minimum=0),
    Key("search.to", 0, INT, "search end address (0 = auto)", minimum=0),
    Key("search.prefix", "hit", STR, "flag prefix for search results"),
    Key("search.limit", 1000, INT, "maximum hits per search", minimum=1),
    # -- io ----------------------------------------------------------------
    Key("io.cache", False, BOOL, "buffer writes until `wc` commits them"),
    # -- idare2 specific ---------------------------------------------------
    Key("ida.backend", "", STR, "gui or idalib (read-only)", readonly=True),
    Key("ida.instance", "", STR, "Nexus record id (read-only)", readonly=True),
    Key("ida.hexrays", False, BOOL, "Hex-Rays availability (read-only)", readonly=True),
    Key("ida.flags.write", True, BOOL, "`f` also writes the name into the IDB"),
    Key("ida.save_on_close", False, BOOL, "save the IDB when a writable session ends"),
    Key("ida.timeout", 30, INT, "per-operation timeout in seconds", minimum=1),
    Key("ida.autoanalysis", "wait", STR, "wait | poll | skip"),
    Key("ida.batch", True, BOOL, "merge `@@` iterations into one round trip"),
    Key("ida.follow_gui", False, BOOL, "follow the IDA GUI cursor"),
)

_BY_NAME = {key.name: key for key in KEYS}


def _coerce(key: Key, value: Any) -> Any:
    if key.kind == BOOL:
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("true", "1", "yes", "on"):
            return True
        if text in ("false", "0", "no", "off", ""):
            return False
        raise UsageError(f"e {key.name}: expected a boolean, not {value!r}")
    if key.kind == INT:
        try:
            number = int(str(value).strip(), 0)
        except ValueError:
            raise UsageError(f"e {key.name}: expected a number, not {value!r}") from None
        if key.minimum is not None and number < key.minimum:
            raise UsageError(f"e {key.name}: must be at least {key.minimum}")
        if key.maximum is not None and number > key.maximum:
            raise UsageError(f"e {key.name}: must be at most {key.maximum}")
        return number
    return str(value)


class Config:
    """A flat, typed key/value store with r2-compatible names."""

    def __init__(self) -> None:
        self._values: dict[str, Any] = {key.name: key.default for key in KEYS}
        #: Keys the user set explicitly, so the session can tell "default" from
        #: "wanted" (e.g. scr.color defaults to on, but only for a tty).
        self.explicit: set[str] = set()

    def get(self, name: str) -> Any:
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        return self._values[name]

    def get_bool(self, name: str) -> bool:
        return bool(self.get(name))

    def get_int(self, name: str) -> int:
        return int(self.get(name))

    def get_str(self, name: str) -> str:
        return str(self.get(name))

    def set(self, name: str, value: Any) -> None:
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        if key.readonly:
            raise UsageError(
                f"e {name} is read-only in idare2: it reflects the IDA database, "
                "which cannot be reconfigured mid-session"
            )
        self._values[name] = _coerce(key, value)
        self.explicit.add(name)

    def reflect(self, name: str, value: Any) -> None:
        """Set a read-only key from the facts of the attached database.

        Read-only keys are exactly the ones idare2 *derives* rather than
        controls, so the session writes them here instead of using ``set()``.
        """
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        if not key.readonly:
            raise UsageError(f"e {name} is not a derived key; use set()")
        self._values[name] = _coerce(key, value)

    def __iter__(self):
        return iter(self.keys())

    def keys(self, prefix: str | None = None) -> list[str]:
        names = sorted(_BY_NAME)
        if prefix:
            names = [name for name in names if name.startswith(prefix)]
        return names

    def describe(self, name: str) -> Key:
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        return key

    def as_dict(self) -> dict[str, Any]:
        return dict(self._values)

    def load(self, values: dict[str, Any]) -> None:
        """Apply a set of values, skipping read-only keys (project restore)."""
        for name, value in values.items():
            key = _BY_NAME.get(name)
            if key is None or key.readonly:
                continue
            self._values[name] = _coerce(key, value)

    def format_value(self, name: str) -> str:
        value = self.get(name)
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)
