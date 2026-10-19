"""radare2-flavoured argument parsing.

``argparse`` cannot express what r2's CLI actually does: clustered short flags
(``-qc 'pd 10'``), doubled letters that mean something different from a repeat
(``-qq`` is "quit before the prompt", ``-AA`` is "deep analysis"), and repeated
``-c``/``-e``.  So this is hand-rolled.

The flag set is deliberately a subset.  Three tiers:

**Implemented** -- kept with r2's meaning.
**Accepted but ignored** -- harmless in an r2 script, meaningless here; each one
warns once.  Hard-failing on ``-T`` would only break scripts for no gain.
**Rejected** -- anything that would silently produce a *wrong* result, such as
``-d`` (debugger), where the user would think they were debugging.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from idare2.errors import UsageError

#: Short flags that take a value.
VALUE_FLAGS = frozenset("abcBeikmpst")
#: Short flags that take no value.
BOOLEAN_FLAGS = frozenset("0A1E2fhjLnNqQSTuvVw")
#: Doubled letters with their own meaning, checked before single letters.
DOUBLED = ("AA", "NN", "qq", "LL", "nn")
#: Accepted and ignored, with the reason shown in the warning.
IGNORED = {
    "0": "output is never NUL-separated",
    "1": "use the shell's 2>&1 instead",
    "2": "use the shell's 2>&1 instead",
    "E": "edit ~/.idare2rc directly",
    "f": "use `b $s` to set the block size to the file size",
    "k": "idare2 does not do syscall resolution",
    "M": "use -e asm.demangle=false",
    "nn": "-n already covers this",
    "Q": "the teardown saving is negligible",
    "S": "use -e cfg.sandbox=true",
    "t": "IDA analyses the database itself",
    "T": "IDA's hashes are precomputed, so there is no cost to skip",
    "u": "idare2 does not filter symbol names",
}
#: Rejected outright, with the reason.
REJECTED = {
    "d": "the debugger is not available through idalib",
    "D": "the debugger is not available through idalib",
    "r": "there is no debugger to profile",
    "R": "there is no debugger to profile",
    "x": "load permissions come from IDA's loader",
    "X": "extraction plugins are IDA's business",
    "P": "rapatch would write to the IDB with different semantics",
}

LONG_WITH_VALUE = frozenset(
    {
        "attach",
        "idb",
        "backend",
        "linger",
        "idle",
        "timeout",
        "startup-timeout",
        "color",
    }
)
LONG_BOOLEAN = frozenset(
    {
        "help",
        "version",
        "no-spawn",
        "save-on-close",
        "no-save-on-close",
        "sessions",
        "json",
    }
)


@dataclass
class Options:
    """Everything the CLI parsed off the command line."""

    file: str | None = None
    commands: list[str] = field(default_factory=list)
    evals: list[tuple[str, str]] = field(default_factory=list)
    pre_scripts: list[str] = field(default_factory=list)
    post_scripts: list[str] = field(default_factory=list)
    ignored: list[tuple[str, str]] = field(default_factory=list)

    analyze: int = 0
    quiet: int = 0
    json: bool = False
    readonly: bool = True
    skip_rc: int = 0
    color: int | None = None
    seek: str | None = None
    project: str | None = None

    arch: str | None = None
    bits: str | None = None
    base: str | None = None
    no_analysis: bool = False

    attach: str | None = None
    idb: str | None = None
    spawn: bool = True
    backend: str = "any"
    linger: float | None = None
    idle: float | None = None
    timeout: float | None = None
    startup_timeout: float | None = None
    save_on_close: bool | None = None

    show_help: bool = False
    show_version: int = 0
    list_sessions: bool = False

    @property
    def wants_database(self) -> bool:
        return not (self.show_help or self.show_version or self.list_sessions)


def parse(argv: list[str]) -> Options:
    options = Options()
    index = 0
    only_positional = False

    while index < len(argv):
        token = argv[index]
        index += 1

        if only_positional or not token.startswith("-") or token == "-":
            _set_file(options, token)
            continue
        if token == "--":
            only_positional = True
            continue
        if token.startswith("--"):
            index = _long(options, token[2:], argv, index)
            continue
        index = _short(options, token[1:], argv, index)

    return options


def _set_file(options: Options, token: str) -> None:
    if options.file is not None:
        raise UsageError(f"only one file can be opened, got {options.file!r} and {token!r}")
    options.file = token


def _long(options: Options, body: str, argv: list[str], index: int) -> int:
    name, _, inline = body.partition("=")
    if name in LONG_WITH_VALUE:
        if inline:
            value = inline
        else:
            if index >= len(argv):
                raise UsageError(f"--{name} needs a value")
            value = argv[index]
            index += 1
        _apply_long_value(options, name, value)
        return index
    if name in LONG_BOOLEAN:
        if inline:
            raise UsageError(f"--{name} does not take a value")
        _apply_long_flag(options, name)
        return index
    raise UsageError(f"unknown option --{name}")


def _apply_long_value(options: Options, name: str, value: str) -> None:
    if name == "attach":
        options.attach = value
    elif name == "idb":
        options.idb = value
    elif name == "backend":
        if value not in ("gui", "idalib", "any"):
            raise UsageError("--backend must be gui, idalib or any")
        options.backend = value
    elif name == "linger":
        options.linger = _float(value, "--linger")
    elif name == "idle":
        options.idle = _float(value, "--idle")
    elif name == "timeout":
        options.timeout = _float(value, "--timeout")
    elif name == "startup-timeout":
        options.startup_timeout = _float(value, "--startup-timeout")
    elif name == "color":
        options.color = _int(value, "--color")


def _apply_long_flag(options: Options, name: str) -> None:
    if name == "help":
        options.show_help = True
    elif name == "version":
        options.show_version = 1
    elif name == "no-spawn":
        options.spawn = False
    elif name == "save-on-close":
        options.save_on_close = True
    elif name == "no-save-on-close":
        options.save_on_close = False
    elif name == "sessions":
        options.list_sessions = True
    elif name == "json":
        options.json = True


def _short(options: Options, cluster: str, argv: list[str], index: int) -> int:
    position = 0
    while position < len(cluster):
        doubled = cluster[position : position + 2]
        if doubled in DOUBLED:
            _apply_doubled(options, doubled)
            position += 2
            continue

        char = cluster[position]
        if char in REJECTED:
            raise UsageError(
                f"-{char} is not supported by idare2: {REJECTED[char]}"
            )
        if char in IGNORED:
            options.ignored.append((f"-{char}", IGNORED[char]))
            position += 1
            continue
        if char == "-":
            # A bare `-` means "no file" in r2 (malloc://512); idare2 has no
            # such concept, so treat it as the end of the flag cluster.
            break
        if char in VALUE_FLAGS:
            rest = cluster[position + 1 :]
            if rest:
                value = rest
            else:
                if index >= len(argv):
                    raise UsageError(f"-{char} needs a value")
                value = argv[index]
                index += 1
            _apply_short_value(options, char, value)
            return index
        if char in BOOLEAN_FLAGS:
            _apply_short_flag(options, char)
            position += 1
            continue
        raise UsageError(f"unknown option -{char}")

    return index


def _apply_doubled(options: Options, doubled: str) -> None:
    if doubled == "AA":
        options.analyze = 2
    elif doubled == "NN":
        options.skip_rc = 2
    elif doubled == "qq":
        options.quiet = 2
    elif doubled == "LL":
        options.list_sessions = True
    elif doubled == "nn":
        options.ignored.append(("-nn", IGNORED["nn"]))


def _apply_short_value(options: Options, char: str, value: str) -> None:
    if char == "a":
        options.arch = value
    elif char == "b":
        options.bits = value
    elif char == "B" or char == "m":
        options.base = value
    elif char == "c":
        options.commands.append(value)
    elif char == "e":
        key, separator, setting = value.partition("=")
        if not separator:
            raise UsageError(f"-e expects key=value, got {value!r}")
        options.evals.append((key.strip(), setting.strip()))
    elif char == "i":
        options.post_scripts.append(value)
    elif char == "I":
        options.pre_scripts.append(value)
    elif char == "k":
        options.ignored.append(("-k", IGNORED["k"]))
    elif char == "p":
        options.project = value
    elif char == "s":
        options.seek = value
    elif char == "t":
        options.ignored.append(("-t", IGNORED["t"]))


def _apply_short_flag(options: Options, char: str) -> None:
    if char == "A":
        options.analyze = max(options.analyze, 1)
    elif char == "h":
        options.show_help = True
    elif char == "j":
        options.json = True
    elif char == "L":
        options.list_sessions = True
    elif char == "n":
        options.no_analysis = True
    elif char == "N":
        options.skip_rc = max(options.skip_rc, 1)
    elif char == "q":
        options.quiet = max(options.quiet, 1)
    elif char == "v":
        options.show_version = 1
    elif char == "V":
        options.show_version = 2
    elif char == "w":
        options.readonly = False


def _float(value: str, what: str) -> float:
    try:
        return float(value)
    except ValueError:
        raise UsageError(f"{what} needs a number, got {value!r}") from None


def _int(value: str, what: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        raise UsageError(f"{what} needs a number, got {value!r}") from None


def iter_ignored(options: Options) -> Iterator[str]:
    return (f"WARN: {flag} ignored: {reason}" for flag, reason in options.ignored)
