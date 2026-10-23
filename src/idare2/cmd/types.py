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
    ("tpv", " name [addr]", "show data formatted for a named type"),
    ("tpx", " name hexpairs", "format a byte sequence as a named type"),
    ("tc", " declaration", "parse C declarations into the database"),
    ("tt", " name [@addr]", "apply a type at an address"),
    ("t-", " name", "delete a named type"),
    ("td", " name", "struct or union members"),
    ("te", " name", "enum members"),
    ("tf", " name", "function signature (func.<name>.* keys)"),
    ("tfj", " name", "function signature as JSON"),
    ("tfc", " name", "function signature as a C prototype"),
    ("tn", "[addr]", "list or set noreturn functions"),
    ("tn-", " addr", "clear a noreturn mark"),
    ("to", " header", "load types from a C header file"),
    ("dt", " name [addr]", "read a typed value at an address"),
]


@command("t", usage="[pat]", summary="types", detail=TYPE_DETAIL, json_suffix=True)
def types(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    suffix = token[1:]
    argument = statement.args.strip()

    if suffix in ("", "*", "j"):
        return _list(session, suffix, argument, statement)

    if suffix == "s":
        return _show(session, argument)

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

    if suffix in ("f", "fj", "fc"):
        return _function_signature(session, suffix, argument)

    if suffix in ("n", "n-"):
        return _noreturn(session, token, argument)

    if suffix == "o":
        return _load_header(session, argument)

    if suffix in ("p", "pv", "px"):
        return _type_value(session, suffix, argument, statement)

    raise UsageError(f"unsupported type command '{token}' (see t?)")


def _type_value(
    session: Session, suffix: str, argument: str, statement: Statement
) -> list[str]:
    """``tp``/``tpv``/``tpx`` -- format data according to a named type.

    ``tpx`` takes the bytes from its second argument; the others read memory
    at the temporary seek.  ``tpv`` only affects how scalar rows are shown in
    r2 (offsets); the row data is the same here.
    """
    words = statement.argv
    if not words:
        raise UsageError(f"t{suffix} needs a type name")
    type_name = words[0]
    rest = words[1:]
    data_hex = None
    target = session.seek
    if suffix == "px":
        if not rest:
            raise UsageError("tpx needs a hexpair value")
        data_hex = rest[0]
    elif rest:
        target = session.resolve(rest[0])
    payload = session.remote.call(
        "type_format", name=type_name, ea=target, data_hex=data_hex
    )
    lines = []
    width = session.addr_width
    for row in payload["rows"]:
        address = int(payload["base"]) + int(row["offset"])
        prefix = f"{row['name']:>2}" if payload["kind"] != "scalar" else ""
        head = f"{prefix} : 0x{address:08x} = " if prefix else f"0x{address:0{width}x} = "
        if "pointer" in row:
            value = row.get("text")
            if value:
                lines.append(f'{head}"{value}"')
            else:
                lines.append(f"{head}{row.get('text') or ''}".rstrip())
        elif "float" in row:
            number = float(row["float"])
            lines.append(f"{head}{number:g}" if number.is_integer() else f"{head}{number}")
        elif row.get("char"):
            lines.append(f"{head}'{row['char']}'")
        elif "value" in row:
            value = int(row.get("unsigned", row["value"]))
            lines.append(f"{head}0x{value & 0xFFFFFFFF:x}")
        else:
            lines.append(f"{head}{row.get('bytes', '')}")
    return lines


def _load_header(session: Session, argument: str) -> list[str]:
    """``to <header>`` -- parse a C header into the database's type library."""
    cmd_module.require_write(session, "'to'")
    if not argument:
        raise UsageError("to needs a header file path")
    payload = session.remote.call("type_load_header", path=_unquote(argument))
    created = payload.get("created") or []
    if created:
        return [f"-- loaded {', '.join(created)} from {payload['path']} --"]
    return [f"-- parsed {payload['path']} --"]


def _noreturn(session: Session, token: str, argument: str) -> list[str]:
    """``tn`` -- list noreturn functions, or mark/unmark one."""
    if token == "tn" and not argument:
        return [row["name"] for row in session.remote.call("noreturn_functions")]
    clearing = token == "tn-"
    words = argument.split()
    if not words:
        raise UsageError("tn- needs at least one function" if clearing else "tn needs an address")
    if len(words) > 1 and not clearing:
        raise UsageError("tn takes one address")
    cmd_module.require_write(session, f"'{token}'")
    marked = []
    for word in words:
        ea = session.resolve(word)
        payload = session.remote.call("set_noreturn", ea=ea, value=not clearing)
        if not clearing:
            marked.append(f"0x{int(payload['ea']):x}")
    return marked


def _function_signature(session: Session, suffix: str, argument: str) -> list[str]:
    """``tf``/``tfj``/``tfc`` -- function prototype.

    ``tf`` prints r2's ``func.<name>.ret=`` / ``.args=`` / ``.arg.<n>=`` keys
    (in r2's hash order, which puts the index digits before the name);
    ``tfj`` returns the ``tfj <name>`` object; ``tfc`` the C prototype.
    """
    target = session.resolve(argument) if argument else session.seek
    payload = session.remote.call("function_signature", ea=target)
    name = payload["name"]
    if suffix == "fj":
        return [to_json(payload)]
    if suffix == "fc":
        args = "".join(
            f"{arg['type']} {arg['name']}, " if arg["name"] else f"{arg['type']}, "
            for arg in payload["args"]
        ).rstrip(", ")
        return [f"{payload['ret']} {name} ({args});"]

    prefix = f"func.{name}"
    lines = [f"{prefix}.ret={payload['ret']}", f"{prefix}.args={len(payload['args'])}"]
    # r2 dumps these keys in sdb hash order (arg.2 can precede arg.0); we print
    # the argument index numerically, which is stable and easier to read.
    for index, arg in enumerate(payload["args"]):
        decl = f"{arg['type']},{arg['name']}" if arg["name"] else arg["type"]
        lines.append(f"{prefix}.arg.{index}={decl}")
    return lines


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
