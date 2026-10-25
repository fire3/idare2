"""Command-line entry point.

Two shapes, same code path:

* **Batch** -- open (or attach to) a database, run everything given by ``-c``
  and ``-i``, exit.  This is what scripts and agents use.
* **Interactive** -- hold one lease for the whole session so ``persist_globals``
  is meaningful and the prompt behaves like r2's.

Data goes to stdout, diagnostics to stderr, which is what makes
``idare2 -qc 'pd 10' file | grep call`` behave the way it should.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

from idare2 import __version__
from idare2 import argv as argv_parser
from idare2.config import Config
from idare2.errors import (
    EXIT_FAIL,
    EXIT_OK,
    EXIT_USAGE,
    Idare2Error,
    QuitRequested,
    UsageError,
)
from idare2.nexus import Target
from idare2.rpc import DEFAULT_TIMEOUT, Remote
from idare2.session import Session

HISTORY_SIZE = 1000

USAGE = """\
Usage: idare2 [file] [options] [-c cmd]...

radare2-style CLI over an IDA database, through ida-nexus.

A database is either opened from a path (Nexus spawns an idalib worker if
needed) or attached to an IDA GUI session that already has it open.

Targeting
  --idb <path>            target this IDB or executable
  --attach <record-id>    attach to exactly this Nexus instance
  --no-spawn              fail instead of spawning a worker
  --backend gui|idalib|any
  -L, --sessions          list registered databases

Behaviour
  -A, -AA                 wait for analysis (deep with -AA)
  -a <arch> -b <bits>     import hints for a database Nexus has to create
  --endian big|little     byte order for a raw binary (default: little)
  -B <baddr>, -m <addr>   load base address
  -n                      do not start autoanalysis
  -N                      skip the user rc file
  -s <addr>               initial seek
  -w                      enable writes (the default is read-only)
  -e <key=value>          set a configuration variable (repeatable)
  -c <cmd>                run a command before the prompt (repeatable)
  -i <file>               run a command script after the database is open
  -I <file>               run a command script before the -i and -c scripts
  -j                      JSON output where a command supports it
  -q, -qq                 quiet: no prompt; exit after -c/-i
  -v, -V                  version / detailed version
  -h, --help              this help

Worker lifetime
  --linger <sec>          keep the worker alive after the last lease (default 3600)
  --idle <sec>            release this lease after inactivity
  --timeout <sec>         per-operation timeout (default 30)
  --startup-timeout <sec> database open/spawn deadline (default 600)
  --save-on-close / --no-save-on-close

Conventions
  addresses   expressions: 0x401000, main+0x10, $$+4; bare digits are DECIMAL
  counts      positional (pd 10) or -n; resume a page with -o
  modifiers   [.][times][cmd][~grep][@addr][|pipe] [>file] ; ...
"""


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        options = argv_parser.parse(arguments)
    except UsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    for warning in argv_parser.iter_ignored(options):
        print(warning, file=sys.stderr)

    if options.show_help:
        print(USAGE, end="")
        return EXIT_OK
    if options.show_version:
        return _version(options) or EXIT_OK
    if options.list_sessions:
        return _list_sessions(options)

    try:
        return _run(options)
    except QuitRequested as exc:
        return exc.code
    except UsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Idare2Error as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------
# modes that do not need a database
# --------------------------------------------------------------------------


def _version(options: argv_parser.Options) -> int:
    if options.show_version < 2:
        print(f"idare2 {__version__}")
        return EXIT_OK
    import platform

    print(f"idare2   {__version__}")
    try:
        import ida_nexus

        print(f"idare-nexus {ida_nexus.__version__}")
        print(f"ida-domain  {ida_nexus.get_ida_domain_version()}")
    except Exception as exc:
        print(f"ida-nexus   unavailable ({type(exc).__name__})")
    print(f"python   {platform.python_version()}")
    try:
        import ida_kernwin
        import idapro  # noqa: F401

        print(f"ida      {ida_kernwin.get_kernel_version()}")
    except Exception:
        print("ida      (not importable from this interpreter)")
    return EXIT_OK


def _list_sessions(options: argv_parser.Options) -> int:
    from idare2 import nexus
    from idare2.fmt.listing import format_databases

    try:
        rows = nexus.list_databases()
    except Exception as exc:
        print(f"ERROR: cannot enumerate Nexus databases: {exc}", file=sys.stderr)
        return EXIT_FAIL
    for line in format_databases(rows, None):
        print(line)
    return EXIT_OK


# --------------------------------------------------------------------------
# main path
# --------------------------------------------------------------------------


def _run(options: argv_parser.Options) -> int:
    config = _config_from(options)
    target = _target_from(options)
    interactive = options.quiet == 0 and sys.stdin.isatty()

    from idare2.nexus import connect

    linger = options.linger if options.linger is not None else 3600.0
    startup = options.startup_timeout if options.startup_timeout is not None else 600.0
    if options.no_analysis:
        analysis_mode = "skip"
    elif options.analyze:
        analysis_mode = "wait"
    else:
        analysis_mode = config.get_str("ida.autoanalysis")

    with connect(target, timeout=startup, linger=linger, wait=analysis_mode) as handle:
        remote = Remote(handle, timeout=options.timeout or DEFAULT_TIMEOUT)
        info = remote.call("open_summary")
        session = Session(handle, remote, config, info, readonly=options.readonly)
        session.json_default = options.json
        session.setup()

        if options.seek:
            session.seek_to(session.resolve(options.seek))

        _load_rc(session, options)
        if options.project:
            _load_project(session, options.project)

        code = _run_scripts(session, options)
        if code is not None:
            return code

        if interactive:
            return _repl(session, options)
        # A batch run's exit code reflects whether every command succeeded,
        # the way r2's does.
        return EXIT_FAIL if session.failed else EXIT_OK


def _config_from(options: argv_parser.Options) -> Config:
    config = Config()
    for key, value in options.evals:
        config.set(key, value)
    if options.color is not None:
        config.set("scr.color", options.color)
    if options.json:
        config.set("scr.color", 0)
    return config


def _target_from(options: argv_parser.Options) -> Target:
    if options.attach and options.idb:
        raise UsageError("pass either --attach or --idb, not both")
    path = options.idb or options.file
    return Target(
        path=path,
        record_id=options.attach,
        spawn=options.spawn,
        backend=options.backend,
        processor=options.arch,
        bits=_parse_bits(options.bits) if options.bits else None,
        endian=options.endian,
        image_base=_parse_base(options.base) if options.base else None,
        auto_analysis=not options.no_analysis,
        save_on_close=bool(options.save_on_close),
        readonly=options.readonly,
    )


def _parse_address(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise UsageError(f"expected a number, got {text!r}") from None


def _parse_base(text: str) -> int:
    value = _parse_address(text)
    if value < 0:
        raise UsageError(f"load base must be non-negative, got {text!r}")
    if value % 16:
        raise UsageError(f"load base must be 16-byte aligned, got {text!r}")
    return value


def _parse_bits(text: str) -> int:
    try:
        bits = int(text, 0)
    except ValueError:
        raise UsageError(f"expected a bit width, got {text!r}") from None
    if bits not in (16, 32, 64):
        raise UsageError(f"-b must be 16, 32 or 64, not {bits}")
    return bits


def _run_scripts(session: Session, options: argv_parser.Options) -> int | None:
    for script in options.pre_scripts:
        _run_file(session, script)
    for script in options.post_scripts:
        _run_file(session, script)
    for command in options.commands:
        session.run(command, emit=_emit)
    return None


def _run_file(session: Session, path: str) -> None:
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise UsageError(f"cannot read script {path}: {exc}") from exc
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        session.run(stripped, emit=_emit)


def _emit(lines: list[str]) -> None:
    for line in lines:
        sys.stdout.write(line)
        sys.stdout.write("\n")
    sys.stdout.flush()


def _load_rc(session: Session, options: argv_parser.Options) -> None:
    if options.skip_rc:
        return
    configured = os.environ.get("IDARE2_RCFILE")
    if configured:
        explicit = Path(configured).expanduser()
        if not explicit.is_file():
            reason = "not a regular file" if explicit.exists() else "no such file"
            print(f"WARN: cannot read rc file {explicit}: {reason}", file=sys.stderr)
            return
    for path in _rc_paths():
        if path.is_file():
            try:
                _run_file(session, str(path))
            except Idare2Error as exc:
                print(f"WARN: {path}: {exc}", file=sys.stderr)


def _rc_paths() -> list[Path]:
    configured = os.environ.get("IDARE2_RCFILE")
    if configured:
        return [Path(configured).expanduser()]

    home = Path.home()
    config_home = _xdg_home("XDG_CONFIG_HOME", home / ".config")
    paths = [home / ".idare2rc", config_home / "idare2" / "rc"]

    rc_dir = config_home / "idare2" / "rc.d"
    if rc_dir.is_dir():
        try:
            entries = list(rc_dir.iterdir())
        except OSError:
            entries = []
        paths.extend(sorted(path for path in entries if path.is_file()))

    project = _find_project_rc()
    if project is not None:
        paths.append(project)

    return _unique_paths(paths)


def _xdg_home(variable: str, fallback: Path) -> Path:
    """Return an XDG base directory, ignoring relative values per the spec."""
    configured = os.environ.get(variable)
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_absolute():
            return candidate
    return fallback


def _find_project_rc(start: Path | None = None) -> Path | None:
    try:
        current = (start or Path.cwd()).resolve()
    except OSError:
        return None
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        candidate = directory / ".idare2rc"
        if candidate.is_file():
            return candidate
    return None


def _unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    result: list[Path] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            result.append(path)
    return result


def _history_path() -> Path:
    state_home = _xdg_home("XDG_STATE_HOME", Path.home() / ".local" / "state")
    return state_home / "idare2" / "history"


def _load_history(readline) -> None:
    path = _history_path()
    try:
        readline.set_history_length(HISTORY_SIZE)
        readline.read_history_file(str(path))
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"WARN: cannot read history {path}: {exc}", file=sys.stderr)


def _save_history(readline) -> None:
    path = _history_path()
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        readline.write_history_file(str(path))
    except OSError as exc:
        print(f"WARN: cannot save history {path}: {exc}", file=sys.stderr)
        return
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def _load_project(session: Session, name: str) -> None:
    from idare2.errors import NotFoundError

    candidate = Path(name).expanduser()
    if not candidate.suffix:
        candidate = candidate.with_suffix(".idare2.json")
    if not candidate.is_file():
        raise NotFoundError(f"no such project: {name}")
    import json

    data = json.loads(candidate.read_text(encoding="utf-8"))
    session.seek_to(int(data.get("seek", session.seek)))
    session.blocksize = int(data.get("blocksize", session.blocksize))
    session.config.load(data.get("config") or {})
    session.aliases.update(data.get("aliases") or {})


# --------------------------------------------------------------------------
# interactive
# --------------------------------------------------------------------------


def _repl(session: Session, options: argv_parser.Options) -> int:
    readline = _import_readline()
    completer = _install_completion(session, readline)
    if readline is not None:
        _load_history(readline)

    if session.config.get_bool("scr.prompt"):
        _banner(session)

    try:
        while True:
            try:
                line = input(session.prompt() if session.config.get_bool("scr.prompt") else "")
            except EOFError:
                print()
                return EXIT_OK
            except KeyboardInterrupt:
                print()
                continue
            if not line.strip():
                continue
            try:
                session.run(line, emit=_emit)
            except QuitRequested as exc:
                return exc.code
            except Idare2Error as exc:
                _error(str(exc), session)
            finally:
                if completer is not None:
                    completer.invalidate()
    finally:
        if readline is not None:
            _save_history(readline)


def _import_readline():
    try:
        import readline
    except ImportError:
        return None
    return readline


def _install_completion(session: Session, readline=None):
    """Wire the cached completer into readline, when readline is available."""
    if readline is None:
        readline = _import_readline()
    if readline is None:
        return None
    from idare2.complete import Completer

    completer = Completer(session)
    readline.set_completer(completer.complete)
    # Keep @ and $ in the word so `@ma<TAB>` and `$al<TAB>` can be completed.
    readline.set_completer_delims(" \t\n;|")
    readline.parse_and_bind("tab: complete")
    return completer


def _error(message: str, session: Session) -> None:
    print(session.colors.error(f"ERROR: {message}"), file=sys.stderr)


def _banner(session: Session) -> None:
    info = session.info
    instance = getattr(session.handle, "instance", None)
    backend = getattr(instance, "backend", "?")
    record = getattr(instance, "record_id", "?")
    arch = info.get("architecture") or "?"
    bits = info.get("bitness") or "?"
    endian = info.get("endian") or "?"
    fmt = (info.get("format") or "?").split()[0]
    attrs = f"{arch}/{bits}/{endian[0]}"
    print(
        f" -- idare2 {__version__} · IDA · {backend} {record} · {attrs} · {fmt} --",
        file=sys.stderr,
    )
    print(" -- type '?' for help --", file=sys.stderr)
