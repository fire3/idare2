"""The ``.ida*`` extension commands.

r2 reserves a leading ``.`` for "execute this command's output".  idare2 uses
the same prefix for backend control, but only for this fixed set of names --
everything else still falls through to r2's dot-source behaviour.  Dispatch
lives in :meth:`idare2.session.Session.dispatch` because the parser has already
stripped the dot by the time the statement is available.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from idare2.errors import UsageError

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

IDA_COMMANDS = frozenset(
    {
        "ida",
        "idasave",
        "idaclose",
        "idasync",
        "idawatch",
        "idaexec",
        "idahelp",
    }
)

IDA_HELP = [
    ".ida                 backend, instance, lease and database path",
    ".idasave             save the IDB (same as `w`)",
    ".idaclose [--no-save] close a managed idalib worker",
    ".idasync             refresh file metadata and cached names/segments",
    ".idawatch [n]        print the next n IDB change events (Ctrl-C to stop)",
    ".idaexec <python>    run Python inside the IDA process and print its repr",
    ".idahelp             show this list",
]


def dispatch_ida(session: Session, statement: Statement) -> list[str]:
    name = statement.cmd
    argument = statement.args.strip()
    if name == "ida":
        return _info(session)
    if name == "idasave":
        return _save(session)
    if name == "idaclose":
        return _close(session, argument)
    if name == "idasync":
        return _sync(session)
    if name == "idawatch":
        return _watch(session, argument)
    if name == "idaexec":
        return _exec(session, argument)
    if name == "idahelp":
        return list(IDA_HELP)
    raise UsageError(f"unsupported idare2 extension '.{name}'")


def _info(session: Session) -> list[str]:
    instance = getattr(session.handle, "instance", None)
    if instance is None:
        return ["backend    unknown", "lease      not attached"]
    connected = getattr(session.handle, "connected", True)
    keepalive = getattr(session.handle, "keepalive", 0.0)
    rows = [
        ("backend", getattr(instance, "backend", "")),
        ("record-id", getattr(instance, "record_id", "")),
        ("pid", getattr(instance, "pid", "")),
        ("port", getattr(instance, "port", "")),
        ("path", getattr(instance, "idb_path", "") or getattr(instance, "exe_path", "")),
        ("keepalive", f"{float(keepalive):g}s"),
        ("lease", "attached" if connected else "disconnected"),
    ]
    width = max(len(key) for key, _value in rows)
    return [f"{key.ljust(width)}  {value}" for key, value in rows]


def _save(session: Session) -> list[str]:
    from idare2 import cmd as cmd_module

    cmd_module.require_write(session, "'.idasave'")
    session.remote.call("save")
    return []


def _sync(session: Session) -> list[str]:
    payload = session.remote.call("file_info")
    session.info.update({key: value for key, value in payload.items() if value is not None})
    session.flags.invalidate()
    session.invalidate_segments()
    return []


def _close(session: Session, argument: str) -> list[str]:
    save = argument != "--no-save"
    instance = getattr(session.handle, "instance", None)
    record_id = getattr(instance, "record_id", "")
    try:
        session.handle.shutdown_database(save=save)
    except Exception as exc:  # noqa: BLE001 - translated into a CLI error
        raise UsageError(f"could not close the database worker: {exc}") from exc
    suffix = "" if save else " (discarded unsaved changes)"
    return [f"-- closed {record_id or 'database'}{suffix} --"]


def _watch(session: Session, argument: str) -> list[str]:
    count = 1
    if argument:
        try:
            count = int(argument, 10)
        except ValueError:
            raise UsageError(f".idawatch count must be a decimal number, not {argument!r}") from None
        if count < 0:
            raise UsageError(".idawatch count must not be negative")
    subscribe = getattr(session.handle, "subscribe_idb_events", None)
    if subscribe is None:
        raise UsageError("this backend does not expose IDB change events")
    subscription = subscribe()
    iterator = iter(subscription)
    lines: list[str] = []
    try:
        for _ in range(count):
            event = next(iterator)
            lines.extend(json.dumps(event, sort_keys=True).splitlines())
    finally:
        close = getattr(subscription, "close", None)
        if close is not None:
            close()
    return lines


def _exec(session: Session, argument: str) -> list[str]:
    if not argument:
        raise UsageError(".idaexec needs Python source")
    execute = getattr(session.handle, "execute_python", None)
    if execute is None:
        raise UsageError("this backend does not support .idaexec")
    payload = execute(argument)
    lines = []
    stdout = payload.get("stdout") or ""
    if stdout:
        lines.extend(stdout.rstrip("\n").splitlines())
    if payload.get("result") is not None:
        lines.append(repr(payload["result"]))
    stderr = payload.get("stderr") or ""
    if stderr:
        session.stderr(stderr.rstrip("\n"))
    return lines
