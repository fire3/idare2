"""The ``f`` flag family."""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command, numeric_args
from idare2.errors import UsageError
from idare2.fmt import addr_width, fmt_addr

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

FLAG_DETAIL = [
    ("f", "", "list flags (seeded from the database's names)"),
    ("f", "name [sz] [@ addr]", "create a flag; writes the name into the IDB with -w"),
    ("f-", "name", "remove a flag"),
    ("f*", "", "list flags as radare2 commands"),
    ("f,", "", "list flags as a table"),
    ("f?", "name", "print the address of a flag"),
]


@command("f", usage="[name] [sz] [addr]", summary="manage flags", detail=FLAG_DETAIL)
def flags(session: Session, statement: Statement) -> list[str]:
    session._ensure_flags()
    suffix = statement.cmd[1:]
    rest, count, _offset = numeric_args(session, statement)

    if suffix == "-":
        return _remove(session, rest)

    if not rest and suffix in ("", "*", ","):
        return _list(session, suffix)

    return _create(session, rest, count, suffix)


def _list(session: Session, suffix: str) -> list[str]:
    width = addr_width(session.info.get("bits"))
    rows = list(session.flags.all())
    if suffix == "*":
        return [f"f {flag.name} {flag.size} @ 0x{flag.ea:x}" for flag in rows]
    if suffix == ",":
        from idare2.fmt.listing import table

        return table(
            ("addr", "size", "name"),
            [[fmt_addr(flag.ea, width), str(flag.size), flag.name] for flag in rows],
        )
    return [f"{fmt_addr(flag.ea, width)} {flag.size:>5} {flag.name}" for flag in rows]


def _create(session: Session, rest: list[str], count: int | None, suffix: str) -> list[str]:
    name = rest[0]
    size = count if count is not None else 1
    if len(rest) > 1:
        address = session.resolve(rest[1])
    elif suffix == "?":
        found = session.flags.lookup(name)
        if found is None:
            return []
        return [fmt_addr(found, addr_width(session.info.get("bits")))]
    else:
        address = session.seek
    session.write_flag(name, address, size)
    return []


def _remove(session: Session, rest: list[str]) -> list[str]:
    from idare2 import cmd as cmd_module

    cmd_module.require_write(session, "'f-'")
    if not rest:
        raise UsageError("f- needs a flag name")
    name = rest[0]
    flag = session.flags.remove(name)
    if flag is not None:
        session.remote.call("delete_name", ea=flag.ea)
    return []
