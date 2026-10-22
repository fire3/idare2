"""Session-level extras: aliases, scripts, projects, yank and block compare.

These are all client-side or near-client-side, and they are what turns a
command set into a usable workbench: ``$`` aliases shorten repeated expressions,
``S`` runs a script file, ``P`` snapshots the session, ``y`` moves bytes around
and ``c`` compares two regions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from idare2.cmd import command
from idare2.errors import NotFoundError, UsageError
from idare2.fmt import to_json

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

ALIAS_DETAIL = [
    ("$", "", "list aliases and variables"),
    ("$", "name", "print an alias or variable"),
    ("$name=expr", "", "define an alias expression"),
    ("$name-", "", "delete an alias"),
]

SCRIPT_DETAIL = [
    ("S", " file", "run a script of idare2 commands"),
    ("S.", " file", "run a script, where a leading '.' means 'execute output'"),
    ("S-", "", "read commands from stdin until an empty line"),
]

PROJECT_DETAIL = [
    ("Ps", " name", "save the session (seek, flags, config, aliases)"),
    ("Po", " name", "load a session"),
    ("P-", " name", "delete a session file"),
    ("Pj", " name", "print a session as JSON"),
    ("P", "", "list session files"),
]

YANK_DETAIL = [
    ("y", " [len]", "yank bytes at the current offset"),
    ("yy", " [@addr]", "paste the yanked bytes"),
    ("yf", " file", "yank a file"),
    ("yx", " hexpairs", "yank hexpairs"),
    ("yt", " text", "yank text"),
]

COMPARE_DETAIL = [
    ("cc", " addr1 addr2 len", "compare two blocks"),
    ("c1", " addr1 addr2 len", "compare and stop at the first difference"),
]

PROJECT_SUFFIX = ".idare2.json"


# --------------------------------------------------------------------------
# $ aliases
# --------------------------------------------------------------------------


@command("$", usage="[name[=expr]]", summary="aliases and variables", detail=ALIAS_DETAIL)
def aliases(session: Session, statement: Statement) -> list[str]:
    # `$main=main` and `$main` arrive as one command token (r2 has no space
    # there), so fall back to the token itself when there are no arguments.
    argument = statement.args.strip() or statement.cmd[1:]

    if argument in ("", "*"):
        return _list_aliases(session)

    if argument.endswith("-") and argument != "-":
        session.aliases.pop(argument[:-1], None)
        return []

    if "=" in argument:
        name, _, expression = argument.partition("=")
        name = name.strip().lstrip("$")
        if not name:
            raise UsageError("$ needs a name before '='")
        # Evaluate once so a typo is reported now, not at use site.
        session.eval(expression.strip())
        session.aliases[name] = expression.strip()
        return []

    name = argument.lstrip("$")
    if name in session.aliases:
        return [session.format_addr(session.eval(session.aliases[name]))]
    value = session.get_var(name)
    if value is None:
        raise UsageError(f"unknown alias or variable ${name}")
    return [session.format_addr(int(value))]


def _list_aliases(session: Session) -> list[str]:
    lines = [f"$$ = {session.format_addr(session.seek)}"]
    for name in sorted(session.aliases):
        value = session.eval(session.aliases[name])
        lines.append(f"${name} = {session.format_addr(value)}  ({session.aliases[name]})")
    for name, value in sorted(session.vars.items()):
        lines.append(f"${name} = {value}")
    return lines


# --------------------------------------------------------------------------
# S scripts
# --------------------------------------------------------------------------


@command("S", usage="[file]", summary="run a command script", detail=SCRIPT_DETAIL)
def run_script(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    argument = statement.args.strip()

    if token == "S-":
        return _script_from_stdin(session)
    if not argument:
        raise UsageError("S needs a script file")

    path = Path(argument).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise NotFoundError(f"cannot read script {path}: {exc}") from exc

    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.extend(session.run(stripped))
    return out


def _script_from_stdin(session: Session) -> list[str]:
    import sys

    out: list[str] = []
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            break
        out.extend(session.run(stripped))
    return out


# --------------------------------------------------------------------------
# P projects
# --------------------------------------------------------------------------


@command("P", usage="[so-]", summary="session projects", detail=PROJECT_DETAIL)
def project(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    suffix = token[1:]
    argument = statement.args.strip()

    if suffix == "":
        return _list_projects(session)
    if not argument:
        raise UsageError(f"P{suffix} needs a project name")

    path = _project_path(session, argument)
    if suffix == "s":
        return _save_project(session, path)
    if suffix == "o":
        return _load_project(session, path)
    if suffix == "-":
        return _delete_project(path)
    if suffix == "j":
        return [to_json(_project_data(session))]
    raise UsageError(f"unsupported project command '{token}' (see P?)")


def _project_path(session: Session, name: str) -> Path:
    """Resolve a project name to a file, appending the suffix if missing."""
    candidate = Path(name).expanduser()
    if not candidate.name.endswith(PROJECT_SUFFIX):
        candidate = candidate.parent / f"{candidate.name}{PROJECT_SUFFIX}"
    return candidate


def _project_data(session: Session) -> dict:
    return {
        "version": 1,
        "path": session.info.get("path"),
        "seek": session.seek,
        "blocksize": session.blocksize,
        "config": {
            key: session.config.get(key)
            for key in session.config
            if key not in session.config_display_only()
        },
        "aliases": dict(session.aliases),
        "flags": [
            {"name": flag.name, "ea": flag.ea, "size": flag.size, "local": flag.local}
            for flag in session.flags.all()
            if flag.local
        ],
    }


def _save_project(session: Session, path: Path) -> list[str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_project_data(session), indent=2), encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot write {path}: {exc}") from exc
    return [f"-- saved {path} --"]


def _load_project(session: Session, path: Path) -> list[str]:
    if not path.is_file():
        raise NotFoundError(f"no such project: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    session.seek_to(int(data.get("seek", session.seek)))
    session.blocksize = int(data.get("blocksize", session.blocksize))
    session.config.load(data.get("config") or {})
    session.aliases.update(data.get("aliases") or {})
    for flag in data.get("flags") or []:
        session.flags.add(flag["name"], int(flag["ea"]), int(flag.get("size", 1)), local=True)
    return [f"-- loaded {path} --"]


def _delete_project(path: Path) -> list[str]:
    if not path.is_file():
        raise NotFoundError(f"no such project: {path}")
    path.unlink()
    return []


def _list_projects(session: Session) -> list[str]:
    base = Path(session.info.get("path") or ".").expanduser().parent
    if not base.is_dir():
        return []
    return sorted(str(path) for path in base.glob(f"*{PROJECT_SUFFIX}"))


# --------------------------------------------------------------------------
# y yank
# --------------------------------------------------------------------------


@command("y", usage="[len]", summary="yank and paste", detail=YANK_DETAIL)
def yank(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    suffix = token[1:]
    argument = statement.args.strip()

    if suffix == "y":
        return _paste(session)
    if suffix == "x":
        if not argument:
            raise UsageError("yx needs hexpairs")
        try:
            session.yank = bytes.fromhex(argument.replace(" ", ""))
        except ValueError:
            raise UsageError(f"yx: not a hexpair string: {argument!r}") from None
        return []
    if suffix == "t":
        session.yank = argument.encode("utf-8")
        return []
    if suffix == "f":
        if not argument:
            raise UsageError("yf needs a file")
        try:
            session.yank = Path(argument).expanduser().read_bytes()
        except OSError as exc:
            raise UsageError(f"cannot read {argument}: {exc}") from exc
        return []

    # Every suffix must be explicit: unknown ones used to fall through and yank
    # from memory, silently ignoring what was asked for (e.g. `y8`, `yj`).
    if suffix:
        raise UsageError(f"unsupported yank command '{token}' (see y?)")

    length = session.eval(argument) if argument else session.blocksize
    if length <= 0:
        raise UsageError("y needs a positive length")
    payload = session.remote.call("read_bytes", ea=session.seek, count=length)
    session.yank = bytes(payload.get("data") or b"")
    return [f"-- yanked {len(session.yank)} byte(s) --"]


def _paste(session: Session) -> list[str]:
    if not session.yank:
        raise UsageError("nothing yanked")
    if session.readonly:
        from idare2.errors import ReadOnlyError

        raise ReadOnlyError("'yy' would modify the database; re-run with -w to allow writes")
    session.remote.call("patch_bytes", ea=session.seek, data=session.yank.hex())
    return [f"-- pasted {len(session.yank)} byte(s) --"]


# --------------------------------------------------------------------------
# c compare
# --------------------------------------------------------------------------


@command("c", usage="[c1]", summary="compare blocks", detail=COMPARE_DETAIL)
def compare(session: Session, statement: Statement) -> list[str]:
    # Only the implemented suffixes are accepted.  `c2`/`c4`/`c8`/`cf`/... used
    # to fall into the same two-address comparison, so the requested operation
    # was silently ignored.
    if statement.cmd not in ("c", "cc", "c1"):
        raise UsageError(f"unsupported compare command '{statement.cmd}' (see c?)")

    words = statement.argv
    if len(words) < 3:
        raise UsageError(f"{statement.cmd} needs two addresses and a length")

    first = session.eval(words[0])
    second = session.eval(words[1])
    length = session.eval(words[2])
    if length <= 0:
        raise UsageError("compare length must be positive")

    left = bytes(
        session.remote.call("read_bytes", ea=first, count=length).get("data") or b""
    )
    right = bytes(
        session.remote.call("read_bytes", ea=second, count=length).get("data") or b""
    )
    differences = [
        (index, left[index], right[index])
        for index in range(min(len(left), len(right)))
        if left[index] != right[index]
    ]

    width = session.addr_width
    lines = []
    for index, a, b in differences:
        if statement.cmd == "c1":
            lines.append(
                f"0x{first + index:0{width}x} 0x{a:02x} != 0x{b:02x}"
            )
            break
        lines.append(
            f"0x{first + index:0{width}x} {a:02x} {b:02x} "
            f"0x{second + index:0{width}x}"
        )
    if not differences:
        lines.append("-- blocks are identical --")
    return lines
