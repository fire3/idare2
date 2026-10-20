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


#: r2 documents ``s[j*=!]``; 5.5.0 accepts all of them and prints the same
#: chain, so idare2 says plainly which ones it has not implemented rather than
#: inventing output for them.
_HISTORY_MODIFIERS = {
    "==": "the explicit list form",
    "=*": "the history as radare2 commands",
    "=!": "the history as flag names",
    "=j": "the history as JSON",
}


def _history(session: Session, suffix: str) -> list[str]:
    """``s=`` -- the undo seek history, oldest first, `` > ``-joined.

    Matches r2 5.5.0 exactly: the *current* seek is not part of the chain, and
    an empty history prints an empty line.  ``s`` already seeks to a flag or
    symbol by name, so this does not double as a lookup.
    """
    if suffix != "=":
        raise UsageError(
            f"s{suffix} ({_HISTORY_MODIFIERS[suffix]}) is not implemented yet; "
            "use s= for the plain history"
        )
    return [" > ".join(session.format_addr(ea) for ea in session.seek_history)]


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
