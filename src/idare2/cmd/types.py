"""The ``t`` type family and ``dt``.

IDA's type system is richer than r2's, so several commands map one-to-one and a
few have no r2 equivalent (``tc`` parses real C declarations into the database).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2 import cmd as cmd_module
from idare2.cmd import command, numeric_args, with_more
from idare2.errors import UsageError
from idare2.fmt import to_json

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

TYPE_DETAIL = [
    ("t", "[pat]", "list named types"),
    ("tj", "[pat]", "list named types as JSON"),
    ("t*", "[pat]", "list named types as radare2 commands"),
    ("ts", " name", "show one type"),
    ("tp", " [addr]", "the type applied at an address"),
    ("tc", " declaration", "parse C declarations into the database"),
    ("tt", " name [@addr]", "apply a type at an address"),
    ("t-", " name", "delete a named type"),
    ("td", " name", "struct or union members"),
    ("te", " name", "enum members"),
    ("dt", " name [addr]", "read a typed value at an address"),
]


@command("t", usage="[pat]", summary="types", detail=TYPE_DETAIL)
def types(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    suffix = token[1:]
    argument = statement.args.strip()

    if suffix in ("", "*", "j"):
        return _list(session, suffix, argument, statement)

    if suffix == "s":
        return _show(session, argument)

    if suffix == "p":
        return _type_at(session, argument)

    if suffix == "c":
        return _parse(session, argument)

    if suffix == "t":
        return _apply(session, argument)

    if suffix == "-":
        return _delete(session, argument)

    if suffix == "d":
        return _members(session, argument)

    if suffix == "e":
        return _enum_members(session, argument)

    raise UsageError(f"unsupported type command '{token}' (see t?)")


def _list(session: Session, suffix: str, pattern: str, statement: Statement) -> list[str]:
    _rest, count, offset = numeric_args(session, statement)
    payload, meta = session.remote.call_with_meta(
        "types_list", pattern=pattern or None, offset=offset, count=count
    )
    if suffix == "j":
        return [to_json(payload)]
    if suffix == "*":
        return [f"tc {row['declaration']}" if "declaration" in row else
                f"td {row['name']}" for row in payload]
    if not payload:
        return []
    width = max(len(row["name"]) for row in payload)
    lines = [
        f"{row['name'].ljust(width)} {row['size']:>6} {row['category']}" for row in payload
    ]
    return with_more(lines, meta)


def _show(session: Session, argument: str) -> list[str]:
    if not argument:
        raise UsageError("ts needs a type name")
    payload = session.remote.call("type_info", name=argument)
    return [
        f"name:      {payload['name']}",
        f"size:      {payload['size']}",
        f"category:  {payload['category']}",
        f"decl:      {payload['declaration']}",
    ]


def _type_at(session: Session, argument: str) -> list[str]:
    target = session.resolve(argument) if argument else session.seek
    payload = session.remote.call("type_at", ea=target)
    return [
        f"addr:      {session.format_addr(int(payload['ea']))}",
        f"type:      {payload['declaration']}",
        f"size:      {payload['size']}",
        f"category:  {payload['category']}",
    ]


def _parse(session: Session, argument: str) -> list[str]:
    cmd_module.require_write(session, "'tc'")
    if not argument:
        raise UsageError("tc needs a C declaration")
    payload = session.remote.call("type_parse", declaration=_unquote(argument))
    created = payload.get("created") or []
    if created:
        return [f"-- defined {', '.join(created)} --"]
    return ["-- declaration parsed --"]


def _apply(session: Session, argument: str) -> list[str]:
    cmd_module.require_write(session, "'tt'")
    if not argument:
        raise UsageError("tt needs a type name")
    session.remote.call("type_apply", ea=session.seek, name=argument)
    return []


def _delete(session: Session, argument: str) -> list[str]:
    cmd_module.require_write(session, "'t-'")
    if not argument:
        raise UsageError("t- needs a type name")
    session.remote.call("type_delete", name=argument)
    return []


def _members(session: Session, argument: str) -> list[str]:
    if not argument:
        raise UsageError("td needs a struct or union name")
    payload = session.remote.call("type_members", name=argument)
    width = max((len(member["name"]) for member in payload["members"]), default=0)
    lines = [f"-- {payload['name']} (size {payload['size']}) --"]
    for member in payload["members"]:
        bit = " (bitfield)" if member["bitfield"] else ""
        lines.append(
            f"{member['offset']:>6}  {member['name'].ljust(width)}  "
            f"{member['type']}{bit}"
        )
    return lines


def _enum_members(session: Session, argument: str) -> list[str]:
    if not argument:
        raise UsageError("te needs an enum name")
    payload = session.remote.call("type_enum_members", name=argument)
    width = max((len(member["name"]) for member in payload["members"]), default=0)
    lines = [f"-- {payload['name']} --"]
    for member in payload["members"]:
        lines.append(f"{member['name'].ljust(width)} = {member['value']}")
    return lines


@command("dt", usage="name [addr]", summary="read a typed value", detail=[])
def typed_value(session: Session, statement: Statement) -> list[str]:
    words = statement.argv
    if not words:
        raise UsageError("dt needs a type name")
    name = words[0]
    target = session.resolve(words[1]) if len(words) > 1 else session.seek
    payload = session.remote.call("object_at", ea=target, name=name)
    lines = [
        f"-- {payload['name']} at {session.format_addr(int(payload['ea']))} "
        f"(size {payload['size']}) --"
    ]
    for key, value in (payload.get("fields") or {}).items():
        lines.append(f"{key} = {value}")
    return lines


def _unquote(text: str) -> str:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        return stripped[1:-1]
    return stripped
