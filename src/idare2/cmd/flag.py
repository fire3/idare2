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
    ("f", "name [sz] [addr]", "create a flag at seek or addr; size defaults to 1"),
    ("f", "name [sz] @ addr", "same, via a temporary seek (writes into the IDB with -w)"),
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
    """``f name [sz] [addr]`` -- r2's order is size first, address second.

    ``numeric_args`` cannot do this split: it only recognises a count in the
    *first* positional slot, and for ``f`` that slot is the flag name, so
    ``f x 16`` used to fall through with ``count is None`` and then parse
    ``16`` as the address -- the flag landed at 0x10 and the IDB write failed
    with ``InvalidEAError``.  Verified against r2: ``f zz6 0x40000`` creates a
    flag of size 0x40000 at the seek, not a flag at 0x40000.
    """
    name = rest[0]
    if suffix == "?":
        found = session.flags.lookup(name)
        if found is None:
            return []
        return [fmt_addr(found, addr_width(session.info.get("bits")))]

    words = rest[1:]
    size = count if count is not None else 1
    if words and count is None:
        size = session.eval(words.pop(0))
    address = session.seek
    if words:
        address = session.resolve(words.pop(0))
    if words:
        raise UsageError(f"f: unexpected argument {words[0]!r} (see f?)")

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
