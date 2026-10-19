"""Decompiler operations backing ``pdc`` / ``afv`` (Hex-Rays)."""

from __future__ import annotations

from typing import Any

from idare2.remote import helpers
from idare2.remote.dispatch import op


@op("decompile")
def decompile(
    db: Any, ea: int, offset: int = 0, count: int | None = None
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Pseudocode for the function at ``ea`` (``pdc``)."""
    helpers.require_hexrays()
    func = helpers.require_func(db, ea)
    pseudocode = db.functions.get_pseudocode(func)
    lines = pseudocode.to_text(remove_tags=True)
    items, next_offset = helpers.paginate(
        iter(lines), offset, count if count else helpers.DECOMPILE_DEFAULT
    )
    result = {
        "ea": int(func.start_ea),
        "name": db.functions.get_name(func),
        "header_lines": int(getattr(pseudocode, "header_lines", 0)),
        "lines": items,
    }
    return result, helpers.page_meta(items, next_offset, len(lines))


@op("locals")
def locals_(db: Any, ea: int) -> dict[str, Any]:
    """Hex-Rays local variables of the function at ``ea`` (``afv``)."""
    helpers.require_hexrays()
    func = helpers.require_func(db, ea)
    variables = db.functions.get_local_variables(func)
    out = []
    for variable in variables or []:
        out.append(
            {
                "name": str(getattr(variable, "name", "")),
                "type": str(getattr(variable, "type", "")),
                "is_arg": bool(getattr(variable, "is_arg", False)),
                "width": int(getattr(variable, "width", 0) or 0),
                "comment": str(getattr(variable, "comment", "") or ""),
            }
        )
    return {"ea": int(func.start_ea), "name": db.functions.get_name(func), "locals": out}
