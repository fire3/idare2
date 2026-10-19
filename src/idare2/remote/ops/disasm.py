"""Disassembly operations backing ``pd`` / ``pD`` / ``pdf`` / ``pdb``."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

#: Guard against a runaway walk on a corrupt database.
HARD_CAP = 100_000


def _targets(db: Any, insn: Any) -> list[int]:
    """Resolved branch/call destinations, as plain ints."""
    out: list[int] = []
    for getter in (db.instructions.call_targets, db.instructions.jump_targets):
        try:
            for target in getter(insn):
                value = int(target)
                if value not in out:
                    out.append(value)
        except Exception:
            # Not every instruction type has targets; that is not an error.
            continue
    return out


def _record(db: Any, insn: Any) -> dict[str, Any]:
    ea = int(insn.ea)
    size = int(insn.size)
    raw = db.bytes.get_bytes_at(ea, size)
    comment = _comment(db, ea)
    text = helpers.clean_disasm(
        helpers.strip_comment(
            db.instructions.get_disassembly(insn) or "", comment
        )
    )
    return {
        "ea": ea,
        "size": size,
        "bytes": bytes(raw) if raw else b"",
        "text": text,
        "comment": comment,
        "is_call": bool(db.instructions.is_call_instruction(insn)),
        "is_jump": bool(db.instructions.is_jump(insn)),
        "targets": _targets(db, insn),
    }


def _comment(db: Any, ea: int) -> str:
    """IDA's comment text at ``ea``.

    ``db.comments.get_at`` returns a ``CommentInfo`` dataclass, not a string;
    returning it directly fails at Nexus's JSON boundary with a confusing
    "CommentInfo is not JSON serializable".
    """
    try:
        info = db.comments.get_at(ea)
    except Exception:
        return ""
    return info.comment if info is not None else ""


def _walk(db: Any, start: int, limit: int, max_count: int | None) -> Iterator[Any]:
    """Yield instructions from ``start`` upward, stopping at ``limit``.

    A negative ``max_count`` means "no limit", which is what the ``@@i``
    iterator asks for.

    ``limit`` is an *inclusive* last valid address: ``db.maximum_ea`` is
    exclusive, and passing it to ``get_next_head`` raises because IDA validates
    the bound.
    """
    from ida_idaapi import BADADDR

    if max_count is not None and max_count < 0:
        max_count = None
    cur: int | None = start
    emitted = 0
    while cur is not None and cur != BADADDR and cur <= limit:
        if max_count is not None and emitted >= max_count:
            return
        if emitted >= HARD_CAP:
            return
        insn = db.instructions.get_at(cur)
        if insn is None:
            return
        yield insn
        emitted += 1
        nxt = db.bytes.get_next_head(cur, limit)
        if nxt is None or int(nxt) <= cur:
            return
        cur = int(nxt)


def _signature(db: Any, func: Any) -> str | None:
    """The function's C signature, when IDA has one."""
    try:
        return db.functions.get_signature(func) or None
    except Exception:
        return None


def _limit(db: Any) -> int:
    """The last valid address (``maximum_ea`` is one past it and is rejected)."""
    maximum = db.maximum_ea
    if maximum is None:
        return 0
    return max(int(maximum) - 1, 0)


@op("disasm")
def disasm(
    db: Any,
    ea: int,
    count: int | None = None,
    offset: int = 0,
    mode: str = "count",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Disassemble around ``ea``.

    ``mode`` is one of:

    ``count``
        ``count`` instructions starting at ``ea`` (``pd``).
    ``bytes``
        instructions covering ``count`` bytes (``pD``).
    ``function``
        the whole containing function (``pdf``).
    ``block``
        the basic block containing ``ea`` (``pdb``).
    """
    func = db.functions.get_at(ea)
    header = None
    if func is not None:
        header = {
            "name": db.functions.get_name(func),
            "start": int(func.start_ea),
            "end": int(func.end_ea),
            "signature": _signature(db, func),
        }

    if mode == "function":
        if func is None:
            helpers.fail(protocol.NOT_FUNC, f"no function at 0x{ea:x}")
        source: Iterator[Any] = iter(db.functions.get_instructions(func))
        cap = helpers.FUNC_CAP
    elif mode == "block":
        block = _block_at(db, ea)
        if block is None:
            helpers.fail(protocol.NOT_FUNC, f"no basic block at 0x{ea:x}")
        source = iter(db.instructions.get_between(block.start_ea, block.end_ea))
        cap = helpers.FUNC_CAP
    elif mode == "bytes":
        span = count if count else helpers.DISASM_DEFAULT
        source = _walk_until_bytes(db, ea, span)
        cap = helpers.FUNC_CAP
    else:
        cap = helpers.FUNC_CAP
        limit = helpers.DISASM_DEFAULT if count is None else count
        source = _walk(db, ea, _limit(db), limit)

    records, next_offset = helpers.paginate(source, offset, cap)
    lines = [_record(db, insn) for insn in records]
    result = {"mode": mode, "ea": ea, "func": header, "lines": lines}
    return result, helpers.page_meta(lines, next_offset)


def _walk_until_bytes(db: Any, start: int, span: int) -> Iterator[Any]:
    limit = _limit(db)
    covered = 0
    for insn in _walk(db, start, limit, None):
        if covered >= span:
            return
        yield insn
        covered += int(insn.size)


def _block_at(db: Any, ea: int) -> Any | None:
    func = db.functions.get_at(ea)
    if func is None:
        return None
    chart = db.functions.get_flowchart(func)
    if chart is None:
        return None
    for block in chart:
        if int(block.start_ea) <= ea < int(block.end_ea):
            return block
    return None


@op("block_info")
def block_info(db: Any, ea: int) -> dict[str, Any]:
    """Basic block boundaries and neighbours at ``ea`` (``ab``)."""
    func = db.functions.get_at(ea)
    if func is None:
        helpers.fail(protocol.NOT_FUNC, f"no function at 0x{ea:x}")
    chart = db.functions.get_flowchart(func)
    if chart is None:
        helpers.fail(protocol.NOT_FUNC, f"no control flow graph for 0x{ea:x}")
    blocks = list(chart)
    for index, block in enumerate(blocks):
        if int(block.start_ea) <= ea < int(block.end_ea):
            return {
                "index": index,
                "start": int(block.start_ea),
                "end": int(block.end_ea),
                "size": int(block.end_ea) - int(block.start_ea),
                "count": len(blocks),
            }
    helpers.fail(protocol.NOT_FUNC, f"0x{ea:x} is not inside a basic block")
    raise AssertionError("unreachable")  # pragma: no cover
