"""The ``s`` seek family.

Seek is client-side state.  r2 has no notion of a remote database, but IDA does
have ``db.current_ea`` -- which is the *analyst's cursor* in a GUI.  idare2 never
touches it, so attaching to somebody's live IDA session cannot yank their view.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command
from idare2.errors import UsageError
from idare2.fmt import addr_width, fmt_addr

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

DETAIL = [
    ("s", "", "print the current address"),
    ("s", "addr", "seek to address"),
    ("s+", "", "redo seek"),
    ("s-", "", "undo seek"),
    ("s+", "n", "seek n bytes forward"),
    ("s-", "n", "seek n bytes backward"),
    ("s++", "[n]", "seek blocksize bytes forward (/=n)"),
    ("s--", "[n]", "seek blocksize bytes backward (/=n)"),
    ("s*", "", "list the seek history as commands"),
    ("sb", "", "seek to the start of the basic block"),
    ("sf", "[addr]", "seek to the function start"),
    ("sF", "[addr]", "seek to the function end"),
    ("sn", "[n]", "seek to the next instruction"),
    ("so", "[n]", "seek to the next instruction (skipping calls)"),
    ("sp", "[n]", "seek to the previous instruction"),
    ("s=", "", "list the undo seek history (oldest first)"),
    ("s==", "", "list the history with names or addresses"),
    ("s=*", "", "list the history as radare2 commands"),
    ("s=!", "", "alias of s= (r2 ignores the !)"),
    ("s=j", "", "alias of s= (r2 ignores the j)"),
    ("s:", "", "print the current address, zero padded"),
]


@command("s", usage="[addr]", summary="seek to address", detail=DETAIL)
def seek(session: Session, statement: Statement) -> list[str]:
    suffix = statement.cmd[1:]
    argument = statement.args.strip()
    width = addr_width(session.info.get("bits"))

    if suffix == "":
        if not argument:
            return [fmt_addr(session.seek, width)]
        session.seek_to(session.resolve(argument))
        return []

    # `s+4` glues the amount to the command; `s+` alone is redo.
    if suffix.startswith("+") or suffix.startswith("-"):
        glued = suffix[1:]
        amount = glued or argument
        if not amount:
            return _redo(session) if suffix.startswith("+") else _undo(session)
        if suffix[1:2] in ("+", "-"):
            # s++ / s-- : multiples of the block size.
            repeats = session.eval(argument) if argument else 1
            step = repeats * session.blocksize
            session.seek_to(
                session.seek + step if suffix[0] == "+" else max(session.seek - step, 0)
            )
            return []
        distance = session.resolve(amount)
        session.seek_to(
            session.seek + distance if suffix[0] == "+" else session.seek - distance
        )
        return []

    if suffix == "++":
        step = session.resolve(argument) if argument else 1
        session.seek_to(session.seek + step * session.blocksize)
        return []

    if suffix == "--":
        step = session.resolve(argument) if argument else 1
        session.seek_to(session.seek - step * session.blocksize)
        return []

    if suffix == "*":
        return [f"s 0x{ea:x}" for ea in [*session.seek_history, session.seek]]

    if suffix == ":":
        digits = session.eval(argument) if argument else width
        return [f"0x{session.seek:0{int(digits)}x}"]

    if suffix.startswith("="):
        return _history(session, suffix)


    if suffix == "b":
        payload = session.remote.call("block_info", ea=session.resolve(argument or None))
        session.seek_to(int(payload["start"]))
        return []

    if suffix in ("f", "F"):
        target = session.resolve(argument or None)
        payload = session.remote.call("function_info", ea=target)
        session.seek_to(int(payload["ea"]) if suffix == "f" else int(payload["end"]))
        return []

    if suffix in ("n", "o", "p"):
        target = session.resolve(argument or None)
        if suffix == "n":
            payload = session.remote.call("disasm", ea=target, count=2, mode="count")
            lines = payload.get("lines") or []
            if len(lines) > 1:
                session.seek_to(int(lines[1]["ea"]))
            return []
        if suffix == "o":
            payload = session.remote.call("disasm", ea=target, count=32, mode="count")
            for line in payload.get("lines") or []:
                if line.get("is_call"):
                    continue
                if int(line["ea"]) > target:
                    session.seek_to(int(line["ea"]))
                    return []
            return []
        payload = session.remote.call("disasm", ea=target, count=1, mode="count")
        lines = payload.get("lines") or []
        if lines:
            session.seek_to(max(int(lines[0]["ea"]) - 4, 0))
        return []

    raise UsageError(f"unsupported seek modifier '{suffix}' (see s?)")


#: r2 6.2.5 only special-cases the second ``=`` (explicit list) and ``*``
#: (radare commands); ``s=!`` and ``s=j`` fall through to the plain chain.
_HISTORY_MODIFIERS = {
    "==": "the explicit list form",
    "=*": "the history as radare2 commands",
}


def _history(session: Session, suffix: str) -> list[str]:
    """``s=`` and friends -- the undo seek history.

    ``s=`` is the chain of past seeks (oldest first, current excluded), ``s==``
    labels each entry with its nearest name or address, and ``s=*`` prints the
    radare2 commands r2 uses to replay the history.  ``s=!``/``s=j`` are
    aliases of ``s=`` because r2 ignores those modifiers.
    """
    if suffix in ("=!", "=j"):
        suffix = "="
    past = list(session.seek_history)
    future = list(reversed(session.seek_future))

    if suffix == "=":
        return [" > ".join(session.format_addr(ea) for ea in past)]
    if suffix == "==":
        chain = [*past, session.seek, *future]
        return [" > ".join(_history_label(session, ea) for ea in chain)]
    if suffix == "=*":
        lines = []
        total = len(past)
        for index, ea in enumerate(past):
            lines.append(
                f"0x{ea:08x} ; {total - index}s- # {_name_delta(session, ea) or ''}"
            )
        if session.seek:
            lines.append(
                f"0x{session.seek:08x} ; # CUR {_name_delta(session, session.seek) or ''}"
            )
        for index, ea in enumerate(future):
            lines.append(
                f"0x{ea:08x} ; {index + 1}s+ # {_name_delta(session, ea) or ''}"
            )
        return lines
    raise UsageError(
        f"s{suffix} ({_HISTORY_MODIFIERS.get(suffix, 'unknown modifier')}) "
        "is not implemented yet; use s= for the plain history"
    )


def _history_label(session: Session, ea: int) -> str:
    return _name_delta(session, ea) or f"0x{ea:x}"


def _name_delta(session: Session, ea: int) -> str | None:
    """Nearest flag name at or before ``ea``, with an ``+ N`` delta."""
    session._ensure_flags()
    best = None
    for flag in session.flags.all():
        if flag.ea > ea:
            break
        best = flag
    if best is None:
        return None
    delta = int(ea) - best.ea
    return best.name if delta == 0 else f"{best.name} + {delta}"


def _undo(session: Session) -> list[str]:
    if not session.seek_history:
        session.warn_once("seek-history", "no previous seek to undo")
        return []
    session.seek_future.append(session.seek)
    session.seek = session.seek_history.pop()
    return []


def _redo(session: Session) -> list[str]:
    if not session.seek_future:
        session.warn_once("seek-history", "no seek to redo")
        return []
    session.seek_history.append(session.seek)
    session.seek = session.seek_future.pop()
    return []
