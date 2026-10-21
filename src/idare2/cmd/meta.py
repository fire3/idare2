"""The ``C`` metadata family: comments and data definitions.

The dispatch mirrors r2's character suffixes exactly: ``C`` lists, ``C.`` shows
the current address's metadata, ``CC`` adds a comment, ``CC.`` shows it,
``CC-`` removes it.  Getting that suffix split wrong silently routes ``CC.`` to
"add a comment", so each form is spelled out rather than pattern-matched.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from idare2 import cmd as cmd_module
from idare2.cmd import command
from idare2.cmd.meta_info import describe_metadata
from idare2.errors import UsageError
from idare2.fmt import to_json

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

COMMENT_DETAIL = [
    ("C", "", "list comments"),
    ("Cj", "", "list comments as JSON"),
    ("C*", "", "list comments as radare2 commands"),
    ("C.", "", "metadata at the current address"),
    ("CC", " text [@addr]", "add or replace a comment; bare CC lists them"),
    ("CCr", " text [@addr]", "add a repeatable comment"),
    ("CC*", "", "list all comments as radare2 commands"),
    ("CC.", "", "show the comment at the current address"),
    ("CC-", "", "remove the comment at the current address"),
    ("CCu", " text [@addr]", "add a comment only if there is none"),
    ("C-", " [len]", "remove comments in a range"),
    ("Cd", " [size] [repeat]", "define data of the given element size"),
    ("Cd.", "", "describe the data at the current address"),
]

_SIZES = {"1": "byte", "2": "word", "4": "dword", "8": "qword"}


@command("C", usage="[Cd]", summary="comments and metadata", detail=COMMENT_DETAIL, json_suffix=True)
def metadata(session: Session, statement: Statement) -> list[str]:
    suffix = statement.cmd[1:]
    argument = statement.args.strip()

    if suffix in ("", "j", "*", "C*"):
        return _list(session, suffix)
    if suffix == ".":
        return _show_current(session)
    if suffix == "C.":
        return _show_comment(session)
    if suffix == "C":
        if not argument:
            # r2's `C[Cthsdmf]` family: bare `CC` lists the comments.  Only
            # `CC <text>` writes, so the list must not demand -w -- otherwise
            # read-only sessions get "would modify the database" and writable
            # ones get "needs comment text", and there is no path to the list.
            return _list(session, "")
        return _add_comment(
            session, argument, token="CC", repeatable=False, only_if_missing=False
        )
    if suffix == "Cr":
        return _add_comment(
            session, argument, token="CCr", repeatable=True, only_if_missing=False
        )
    if suffix == "Cu":
        return _add_comment(
            session, argument, token="CCu", repeatable=False, only_if_missing=True
        )
    if suffix == "C-":
        return _delete_comment(session)
    if suffix == "-":
        return _delete_range(session, argument)
    if suffix == "d":
        return _define_data(session, argument)
    if suffix == "d.":
        return _data_info(session)

    raise UsageError(f"unsupported metadata command 'C{suffix}' (see C?)")


def _list(session: Session, suffix: str) -> list[str]:
    if suffix in ("*", "C*"):
        return _radare_commands(session.remote.call("comments"))
    return _format_comments(session, session.remote.call("comments"), json=suffix == "j")


def _radare_commands(rows: list[dict]) -> list[str]:
    """``C*``/``CC*`` -- replayable ``CCu`` commands, base64-encoded like r2."""
    return [
        f"CCu base64:{base64.b64encode(row['comment'].encode()).decode()} "
        f"@ 0x{int(row['ea']):08x}"
        for row in rows
    ]


def _format_comments(session: Session, rows: list[dict], *, json: bool) -> list[str]:
    if json:
        return [to_json(rows)]
    width = session.addr_width
    return [f"0x{int(row['ea']):0{width}x} {row['comment']}" for row in rows]


def _show_comment(session: Session) -> list[str]:
    return _format_comments(
        session, session.remote.call("comments", ea=session.seek), json=False
    )


def _show_current(session: Session) -> list[str]:
    return describe_metadata(session)


def _add_comment(
    session: Session,
    argument: str,
    *,
    token: str,
    repeatable: bool,
    only_if_missing: bool,
) -> list[str]:
    text = _unquote(argument)
    if not text:
        raise UsageError(f"{token} needs comment text")
    cmd_module.require_write(session, f"'{token}'")
    if only_if_missing and session.remote.call("comments", ea=session.seek):
        return []
    session.remote.call(
        "set_comment", ea=session.seek, text=text, repeatable=repeatable
    )
    session.prime_comments({session.seek: text})
    return []


def _delete_comment(session: Session) -> list[str]:
    cmd_module.require_write(session, "'CC-'")
    session.remote.call("delete_comment", ea=session.seek)
    session.prime_comments({})
    return []


def _delete_range(session: Session, argument: str) -> list[str]:
    cmd_module.require_write(session, "'C-'")
    length = session.eval(argument) if argument else 1
    if length <= 0:
        raise UsageError("C- needs a positive length")
    payload = session.remote.call(
        "delete_comments_in_range", start=session.seek, end=session.seek + length
    )
    return [f"-- removed {payload['removed']} comment(s) --"]


def _define_data(session: Session, argument: str) -> list[str]:
    cmd_module.require_write(session, "'Cd'")
    words = argument.split()
    size = words[0] if words else "1"
    if size not in _SIZES:
        raise UsageError(f"Cd size must be 1, 2, 4 or 8, not {size!r}")
    count = session.eval(words[1]) if len(words) > 1 else 1
    session.remote.call(
        "set_data_type", ea=session.seek, kind=_SIZES[size], count=count
    )
    return []


def _data_info(session: Session) -> list[str]:
    payload = session.remote.call("data_info", ea=session.seek)
    return [f"size: {payload['size']}", f"type: {_describe(payload)}"]


def _describe(payload: dict) -> str:
    for key, label in (
        ("is_code", "code"),
        ("is_string", "string"),
        ("is_struct", "struct"),
        ("is_dword", "dword"),
        ("is_word", "word"),
        ("is_qword", "qword"),
        ("is_byte", "byte"),
        ("is_data", "data"),
        ("is_unknown", "unknown"),
    ):
        if payload.get(key):
            return label
    return "data"


def _unquote(text: str) -> str:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        return stripped[1:-1]
    return stripped
