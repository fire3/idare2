"""Function and cross-reference operations backing the ``a`` command family."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

#: IDA xref types -> the token idare2 prints in ``axt``/``axf``.
_XREF_KIND = {
    "CALL_NEAR": "CALL",
    "CALL_FAR": "CALL",
    "JUMP_NEAR": "JUMP",
    "JUMP_FAR": "JUMP",
    "ORDINARY_FLOW": "FLOW",
    "USER_SPECIFIED": "USER",
    "OFFSET": "DATA",
    "READ": "DATA",
    "WRITE": "DATA",
    "TEXT": "DATA",
    "INFORMATIONAL": "DATA",
    "SYMBOLIC": "DATA",
}


def _xref_perm(kind: str) -> str:
    """A ``rwx``-shaped permission column, mirroring r2's ``[DATA:r--]``."""
    if kind == "WRITE":
        return "-w-"
    if kind == "READ":
        return "r--"
    if kind in ("CALL_NEAR", "CALL_FAR", "JUMP_NEAR", "JUMP_FAR", "ORDINARY_FLOW"):
        return "r-x"
    return "r--"


def _kind_name(xref: Any) -> str:
    raw = getattr(xref.type, "name", None) or str(xref.type)
    return _XREF_KIND.get(raw, raw)


@op("functions")
def functions(
    db: Any,
    pattern: str | None = None,
    offset: int = 0,
    count: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Function table (``afl``).

    Basic-block counts come from a flow chart per function, which is not free,
    so they are computed only for the functions actually being returned.
    """
    predicate = helpers.name_filter(pattern)

    def make() -> Iterator[Any]:
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if predicate(name):
                yield func

    # Like r2, an unfiltered `afl` lists everything; capping it would make
    # `afl~name` silently miss functions beyond the page size.
    funcs, next_offset = helpers.paginate(make(), offset, count)
    out = []
    for func in funcs:
        out.append(
            {
                "ea": int(func.start_ea),
                "end": int(func.end_ea),
                "size": int(func.end_ea) - int(func.start_ea),
                "name": db.functions.get_name(func),
                "nbbs": _block_count(db, func),
            }
        )
    return out, helpers.page_meta(out, next_offset)


def _block_count(db: Any, func: Any) -> int:
    try:
        chart = db.functions.get_flowchart(func)
        return len(chart) if chart is not None else 0
    except Exception:
        return 0


@op("function_info")
def function_info(db: Any, ea: int) -> dict[str, Any]:
    """Function detail (``afi``)."""
    func = helpers.require_func(db, ea)
    chart = db.functions.get_flowchart(func)
    blocks = list(chart) if chart is not None else []
    instruction_count = sum(1 for _ in db.functions.get_instructions(func))
    callers = list(db.functions.get_callers(func))
    callees = list(db.functions.get_callees(func))
    locals_count = _local_count(db, func)

    return {
        "ea": int(func.start_ea),
        "end": int(func.end_ea),
        "name": db.functions.get_name(func),
        "size": int(func.end_ea) - int(func.start_ea),
        "nbbs": len(blocks),
        "ninstrs": instruction_count,
        "callers": len(callers),
        "callees": len(callees),
        "locals": locals_count,
        "is_far": bool(db.functions.is_far(func)),
        "does_return": bool(db.functions.does_return(func)),
        "noreturn": not bool(db.functions.does_return(func)),
        "signature": _signature(db, func),
        "flags": helpers.flag_value(db.functions.get_flags(func)),
    }


def _local_count(db: Any, func: Any) -> int:
    """Hex-Rays local count, or 0 when the decompiler is unavailable."""
    try:
        variables = db.functions.get_local_variables(func)
        return len(list(variables)) if variables is not None else 0
    except Exception:
        return 0


def _signature(db: Any, func: Any) -> str | None:
    try:
        return db.functions.get_signature(func)
    except Exception:
        return None


@op("xrefs")
def xrefs(db: Any, ea: int, direction: str = "to") -> list[dict[str, Any]]:
    """Cross-references (``axt``, ``axf``).

    Uses ``db.xrefs.to_ea``/``from_ea`` rather than the ``code_refs_*`` helpers
    because those yield bare addresses and lose the reference kind, which
    ``axt`` needs for its type column.
    """
    if direction not in ("to", "from", "both"):
        helpers.fail(protocol.BAD_ARGS, f"direction must be to, from or both, not {direction}")

    out: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str]] = set()

    def emit(xref: Any, kind_direction: str) -> None:
        source = int(xref.from_ea)
        target = int(xref.to_ea)
        kind = _kind_name(xref)
        key = (source, target, kind)
        if key in seen:
            return
        seen.add(key)
        insn = db.instructions.get_at(source)
        comment = ""
        text = ""
        if insn is not None:
            try:
                info = db.comments.get_at(source)
                comment = info.comment if info is not None else ""
            except Exception:
                comment = ""
            text = helpers.clean_disasm(
                helpers.strip_comment(
                    db.instructions.get_disassembly(insn) or "", comment
                )
            )
        out.append(
            {
                "from": source,
                "to": target,
                "type": kind,
                "perm": _xref_perm(kind),
                "code": bool(xref.is_code),
                "user": bool(getattr(xref, "user", False)),
                "func": helpers.func_name(db, source),
                "text": text,
                "direction": kind_direction,
            }
        )

    if direction in ("to", "both"):
        for xref in db.xrefs.to_ea(ea):
            emit(xref, "to")
    if direction in ("from", "both"):
        for xref in db.xrefs.from_ea(ea):
            emit(xref, "from")
    return out


@op("callers")
def callers(db: Any, ea: int) -> list[dict[str, Any]]:
    """Callers of the function at ``ea`` (``afc``, ``ac``)."""
    func = helpers.require_func(db, ea)
    return [
        {"ea": int(caller.start_ea), "name": db.functions.get_name(caller)}
        for caller in db.functions.get_callers(func)
    ]


@op("callees")
def callees(db: Any, ea: int) -> list[dict[str, Any]]:
    """Callees of the function at ``ea`` (``afC``, ``ac``)."""
    func = helpers.require_func(db, ea)
    return [
        {"ea": int(callee.start_ea), "name": db.functions.get_name(callee)}
        for callee in db.functions.get_callees(func)
    ]


@op("blocks")
def blocks(db: Any, ea: int) -> list[dict[str, Any]]:
    """Basic blocks of the function at ``ea`` (``afb``)."""
    func = helpers.require_func(db, ea)
    chart = db.functions.get_flowchart(func)
    if chart is None:
        return []
    out = []
    for index, block in enumerate(chart):
        start = int(block.start_ea)
        end = int(block.end_ea)
        out.append(
            {
                "index": index,
                "start": start,
                "end": end,
                "size": end - start,
                "successors": _block_successors(db, block),
            }
        )
    return out


def _block_successors(db: Any, block: Any) -> list[int]:
    try:
        return [int(target.start_ea) for target in block.get_successors()]
    except Exception:
        return []


@op("reanalyze", writes=True)
def reanalyze(db: Any, ea: int) -> dict[str, Any]:
    """Re-run IDA's analysis over the function at ``ea`` (``afr``)."""
    func = helpers.require_func(db, ea)
    db.functions.reanalyze(func)
    return {"ea": int(func.start_ea), "reanalyzed": True}


@op("create_function", writes=True)
def create_function(db: Any, ea: int) -> dict[str, Any]:
    """Force a function at ``ea`` (``af``).

    ``ida_funcs.add_func`` refuses addresses that are already inside a function
    or that are not code; both are legitimate answers, so the error says which
    one instead of a bare "IDA refused".
    """
    existing = db.functions.get_at(ea)
    if existing is not None:
        helpers.fail(
            protocol.IDA_ERROR,
            f"0x{ea:x} already belongs to {db.functions.get_name(existing)}",
        )
    if not db.bytes.is_code_at(ea):
        helpers.fail(
            protocol.IDA_ERROR,
            f"0x{ea:x} is not code; define code there first (C, a8)",
        )
    if not db.functions.create(ea):
        helpers.fail(protocol.IDA_ERROR, f"IDA refused to create a function at 0x{ea:x}")
    func = db.functions.get_at(ea)
    return {"ea": ea, "name": db.functions.get_name(func) if func else None}
