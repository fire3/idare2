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


@op("var_accesses")
def var_accesses(db: Any, ea: int, name: str | None = None) -> list[dict[str, Any]]:
    """Read/write addresses per local variable (``afvR``/``afvW``).

    One decompilation and one ctree walk for the whole function: references
    carry the variable index and the binary address, so grouping is free.
    Address-taken references count as reads, like r2's ``R_PERM_R``.
    """
    helpers.require_hexrays()
    func = helpers.require_func(db, ea)
    pcfunc = db.pseudocode.decompile(func)
    raw = pcfunc.raw_cfunc
    names = [str(getattr(raw.lvars[i], "name", "") or "") for i in range(raw.lvars.size())]
    rows: dict[int, dict[str, Any]] = {}
    for index, lvar_name in enumerate(names):
        if not lvar_name:
            continue
        if name is not None and lvar_name != name:
            continue
        rows[index] = {"name": lvar_name, "read": [], "write": []}

    for ref in pcfunc.find_variable_references():
        expr = getattr(ref, "expr", None)
        index = getattr(expr, "variable_index", None) if expr is not None else None
        if index is None or index not in rows:
            continue
        address = getattr(ref, "ea", None)
        if address is None:
            continue
        access = str(getattr(getattr(ref, "access_type", None), "name", "") or "")
        key = "write" if access == "WRITE" else "read"
        rows[index][key].append(int(address))
    return list(rows.values())


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


#: Stack-pointer register per IDA processor, for the ``sp`` ref base.
_SP_REGISTER = {
    "metapc": ("rsp", "esp"),
    "arm": ("sp", "sp"),
    "arm64": ("sp", "sp"),
    "aarch64": ("sp", "sp"),
    "mips": ("sp", "sp"),
    "ppc": ("r1", "r1"),
    "riscv": ("sp", "sp"),
}


@op("function_locals")
def function_locals(db: Any, ea: int) -> dict[str, Any]:
    """Hex-Rays variables in r2's ``afvj`` shape (``afv``/``afvj``).

    ``reg`` holds the arguments (r2 classifies by storage class, so register
    temporaries are not listed), ``sp`` the stack variables.  IDA's
    ``stkoff()`` is relative to the stack pointer and matched r2's
    ``rsp+0xNN`` refs exactly on x86-64.  IDA does not expose frame-pointer
    relative variables, so ``bp`` is always empty; ``afvd`` (which needs the
    live values per class) is still unsupported.
    """
    import ida_hexrays
    import ida_ida
    import ida_idp

    helpers.require_hexrays()
    func = helpers.require_func(db, ea)
    pcfunc = db.pseudocode.decompile(func)
    raw = pcfunc.raw_cfunc

    proc = str(ida_ida.inf_get_procname() or "").lower()
    reg64, reg32 = _SP_REGISTER.get(proc, ("sp", "sp"))
    sp_base = reg64 if int(getattr(db, "bitness", 0) or 0) == 64 else reg32
    reg_width = 8 if int(getattr(db, "bitness", 0) or 0) == 64 else 4

    reg: list[dict[str, Any]] = []
    sp: list[dict[str, Any]] = []
    for index in range(raw.lvars.size()):
        variable = raw.lvars[index]
        name = str(getattr(variable, "name", "") or "")
        if not name:
            # IDA's unnamed compiler temporaries have no r2 counterpart.
            continue
        tif = getattr(variable, "tif", None)
        type_name = tif.dstr() if tif is not None else ""
        location = variable.location
        if variable.is_arg_var and location.is_reg1():
            mreg = int(location.reg1())
            register = ida_hexrays.mreg2reg(mreg, reg_width)
            ref = ida_idp.get_reg_name(register, reg_width) if register >= 0 else None
            if not ref:
                ref = ida_hexrays.get_mreg_name(mreg, int(getattr(variable, "width", 8) or 8))
            if ref:
                reg.append({"name": name, "kind": "reg", "type": type_name, "ref": ref})
        elif location.is_stkoff():
            sp.append(
                {
                    "name": name,
                    "kind": "var",
                    "type": type_name,
                    "ref": {"base": sp_base, "offset": int(location.stkoff())},
                }
            )
    return {"reg": reg, "sp": sp, "bp": []}
