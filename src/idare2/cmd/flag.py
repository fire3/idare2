"""The ``f`` flag family."""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command, not_supported, numeric_args
from idare2.errors import UsageError
from idare2.fmt import addr_width, fmt_addr, to_json
from idare2.fmt import memory as fmt_memory

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
    ("fq", "", "list flag names only"),
    ("fn", "", "list flags with their real (demangled) names"),
    ("fnj", "", "same as fn, as JSON"),
    ("fN", "", "real name of the flag at the current address"),
    ("fr", "[old] [new]", "rename a flag (the flag at the seek when old is omitted)"),
    ("fx", "flag", "hexdump the bytes covered by a flag"),
]


@command(
    "f",
    usage="[name] [sz] [addr]",
    summary="manage flags",
    detail=FLAG_DETAIL,
    query_suffix=True,
)
def flags(session: Session, statement: Statement) -> list[str]:
    session._ensure_flags()
    suffix = statement.cmd[1:]
    words = statement.argv

    if suffix.startswith("?"):
        # r2 writes the query without a space: `f?name`.
        name = suffix[1:]
        return _query(session, ([name] if name else []) + words)
    if statement.help:
        # The spaced form, `f? name`.  `invoke` only got us here because the
        # command declared `query_suffix`; a bare `f?` printed the table already.
        return _query(session, words)

    if suffix == "-":
        return _remove(session, words)

    if suffix in ("", "*", ","):
        if not words:
            return _list(session, suffix)
        if suffix:
            raise UsageError(f"f{suffix} takes no arguments")
        rest, count, _offset = numeric_args(session, statement)
        return _create(session, rest, count)

    # Every other suffix is dispatched explicitly.  Falling through to
    # `_create` used to turn `fn foo` into a flag named "foo" and made `fx`
    # crash with an IndexError.
    if suffix in ("n", "nj"):
        return _names(session, words, as_json=suffix == "nj")
    if suffix == "N":
        return _real_name(session, words)
    if suffix == "q":
        return _quiet(session, words)
    if suffix == "r":
        return _rename(session, words)
    if suffix == "x":
        return _hexdump(session, words)

    raise UsageError(f"unsupported flag command 'f{suffix}' (see f?)")


def _query(session: Session, rest: list[str]) -> list[str]:
    """``f? name`` / ``f?name`` -- where a flag lives, or nothing if it does not.

    r2 documents `f?flagname` as an existence check and (in 5.5.0) prints
    neither 1 nor 0, so there is no output to match.  idare2's own help promises
    the address, which also answers existence: absent == no output.
    """
    if not rest:
        raise UsageError("f? needs a flag name")
    found = session.flags.lookup(rest[0])
    if found is None:
        return []
    return [fmt_addr(found, addr_width(session.info.get("bits")))]


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


def _demangled_names(session: Session) -> dict[int, str]:
    """``{ea: realname}`` for the names IDA can demangle (one round trip)."""
    rows = session.remote.call("demangled_names") or []
    return {
        int(row["ea"]): str(row["realname"])
        for row in rows
        if row.get("realname")
    }


def _quiet(session: Session, words: list[str]) -> list[str]:
    """``fq`` -- flag names only."""
    if words:
        raise UsageError("fq takes no arguments")
    return [flag.name for flag in session.flags.all()]


def _names(session: Session, words: list[str], *, as_json: bool) -> list[str]:
    """``fn``/``fnj`` -- flags with their real (demangled) names."""
    if words:
        raise UsageError("fn takes no arguments")
    realnames = _demangled_names(session)
    rows: list[dict[str, object]] = []
    lines: list[str] = []
    for flag in session.flags.all():
        name = realnames.get(flag.ea) or flag.name
        if as_json:
            row: dict[str, object] = {"name": flag.name}
            if name != flag.name:
                row["realname"] = name
            row["size"] = flag.size
            row["addr"] = flag.ea
            rows.append(row)
        else:
            lines.append(f"0x{flag.ea:08x} {flag.size} {name}")
    return [to_json(rows)] if as_json else lines


def _real_name(session: Session, words: list[str]) -> list[str]:
    """``fN`` -- the real name of the flag at the current address.

    r2 can also *set* a real name, but IDA derives the demangled name from the
    symbol and has no separate field, so that form is refused.
    """
    if words:
        not_supported(
            "fN <name> <realname>",
            "IDA derives the demangled name from the symbol and has no "
            "separate real-name field to set",
        )
    candidates = session.flags.at(session.seek)
    if not candidates:
        return []
    flag = candidates[0]
    return [_demangled_names(session).get(flag.ea) or flag.name]


def _rename(session: Session, words: list[str]) -> list[str]:
    """``fr [old] [new]`` -- rename a flag.

    With one argument the flag at the current address is renamed; with two the
    named flag is.  The size is preserved, and the new name is written through
    to the IDB under the same rules as `f name`.
    """
    if not words:
        raise UsageError("fr needs a new name")
    if len(words) > 2:
        raise UsageError("fr takes at most [old] and [new]")
    if len(words) == 2:
        old_name, new_name = words
        flag = session.flags.get(old_name)
        if flag is None:
            raise UsageError(f"fr: no flag named {old_name!r}")
    else:
        candidates = session.flags.at(session.seek)
        if not candidates:
            raise UsageError("fr: no flag at the current address")
        flag = candidates[0]
        new_name = words[0]

    if new_name == flag.name:
        return []
    session.write_flag(new_name, flag.ea, flag.size)
    session.flags.remove(flag.name)
    return []


def _hexdump(session: Session, words: list[str]) -> list[str]:
    """``fx <flag>`` -- the flag's address, then its bytes as a hexdump."""
    if len(words) != 1:
        raise UsageError("fx needs a flag name")
    target = session.resolve(words[0])
    candidates = session.flags.at(target)
    if not candidates:
        return []
    flag = candidates[0]
    payload = session.remote.call("read_bytes", ea=flag.ea, count=flag.size)
    return [f"0x{flag.ea:08x}", *fmt_memory.format_hexdump(payload, session)]


def _create(session: Session, rest: list[str], count: int | None) -> list[str]:
    """``f name [sz] [addr]`` -- r2's order is size first, address second.

    ``numeric_args`` cannot do this split: it only recognises a count in the
    *first* positional slot, and for ``f`` that slot is the flag name, so
    ``f x 16`` used to fall through with ``count is None`` and then parse
    ``16`` as the address -- the flag landed at 0x10 and the IDB write failed
    with ``InvalidEAError``.  Verified against r2: ``f zz6 0x40000`` creates a
    flag of size 0x40000 at the seek, not a flag at 0x40000.
    """
    if not rest:
        raise UsageError("f needs a flag name")
    name = rest[0]
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


def _remove(session: Session, words: list[str]) -> list[str]:
    from idare2 import cmd as cmd_module

    cmd_module.require_write(session, "'f-'")
    if not words:
        raise UsageError("f- needs a flag name")
    name = words[0]
    flag = session.flags.remove(name)
    if flag is not None:
        session.remote.call("delete_name", ea=flag.ea)
    return []
