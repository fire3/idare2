"""Type operations backing ``t*`` and ``dt``.

Described through ``tinfo_t``'s own methods rather than ``TypeDetails``: the
latter is a dataclass whose shape follows ida-domain's version, while the
``tinfo_t`` predicates are IDA's stable SDK surface.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op


def _text(tinfo: Any) -> str:
    try:
        return tinfo.dstr()
    except Exception:
        return str(tinfo)


def _describe(tinfo: Any) -> dict[str, Any]:
    """Name, size, declaration and category for one type."""
    def flag(name: str) -> bool:
        try:
            return bool(getattr(tinfo, name)())
        except Exception:
            return False

    with contextlib.suppress(Exception):
        size = int(tinfo.get_size())

    category = "other"
    for name, label in (
        ("is_struct", "struct"),
        ("is_union", "union"),
        ("is_enum", "enum"),
        ("is_func", "func"),
        ("is_ptr", "ptr"),
        ("is_array", "array"),
        ("is_bitfield", "bitfield"),
        ("is_scalar", "scalar"),
    ):
        if flag(name):
            category = label
            break

    return {
        "name": _text(tinfo),
        "size": size,
        "category": category,
        "declaration": _text(tinfo),
        "is_const": flag("is_const"),
        "is_volatile": flag("is_volatile"),
    }


#: IDA's calling conventions -> r2's names (``get_cc`` returns an int).
_CC_NAMES = {
    48: "cdecl",       # CM_CC_CDECL
    64: "cdecl",       # CM_CC_ELLIPSIS (vararg cdecl)
    80: "stdcall",     # CM_CC_STDCALL
    96: "pascal",      # CM_CC_PASCAL
    112: "fastcall",   # CM_CC_FASTCALL
    128: "thiscall",   # CM_CC_THISCALL
    144: "swift",      # CM_CC_SWIFT
    160: "spoiled",    # CM_CC_SPOILED
    176: "golang",     # CM_CC_GOLANG
    208: "special",    # CM_CC_SPECIALE
    224: "special",    # CM_CC_SPECIALP
    240: "special",    # CM_CC_SPECIAL
    256: "gostk",      # CM_CC_GOSTK
    257: "rust",       # CM_CC_RUST
}


def _cc_name(cc: int) -> str | None:
    return _CC_NAMES.get(cc)


@op("function_signature")
def function_signature(db: Any, ea: int) -> dict[str, Any]:
    """One function prototype in r2's ``tfj`` shape (``tf``).

    IDA stores the return and argument types plus their storage locations, so
    r2's ret/cc/ret_reg/args/size keys all have an equivalent.  r2's
    ``*aligned_alloc`` style leading-star names are not reproduced.
    """
    import ida_nalt
    import ida_typeinf

    func = helpers.require_func(db, ea)
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, func.start_ea) or not tif.is_func():
        helpers.fail(protocol.NOT_FOUND, f"no function type at 0x{int(func.start_ea):x}")
    details = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(details):
        helpers.fail(protocol.IDA_ERROR, f"cannot read the prototype at 0x{int(func.start_ea):x}")

    cc = int(details.get_cc())
    ret = details.rettype
    ret_type = ret.dstr() if ret is not None else "void"
    ret_loc = getattr(details, "retloc", None)
    ret_reg = None
    if ret_loc is not None:
        try:
            if ret_loc.is_reg1():
                ret_reg = _reg_name(int(ret_loc.reg1()))
        except Exception:
            ret_reg = None

    offset = 0
    args = []
    for index in range(len(details)):
        arg = details[index]
        type_name = arg.type.dstr() if arg.type is not None else ""
        size = int(arg.type.get_size()) if arg.type is not None else 0
        loc = arg.argloc
        loc_text = _argloc_text(loc)
        args.append(
            {
                "type": type_name,
                "name": str(arg.name or ""),
                "size": size,
                "offset": offset,
                "loc": loc_text,
            }
        )
        offset += size

    return {
        "name": db.functions.get_name(func),
        "ret": ret_type,
        "cc": _cc_name(cc),
        "ret_reg": ret_reg,
        "args": args,
        "size": offset,
    }


def _reg_name(reg: int) -> str | None:
    try:
        import ida_idp

        return ida_idp.get_reg_name(reg, 8) or None
    except Exception:
        return None


def _argloc_text(loc: Any) -> str:
    try:
        if loc.is_reg1():
            return _reg_name(int(loc.reg1())) or ""
        if loc.is_stkoff():
            return f"stack+0x{int(loc.stkoff()):x}"
    except Exception:
        pass
    return ""


@op("types_list")
def types_list(
    db: Any,
    pattern: str | None = None,
    offset: int = 0,
    count: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Named types in the database (``t``)."""
    predicate = helpers.name_filter(pattern)

    def make() -> Iterator[dict[str, Any]]:
        for tinfo in db.types.get_all():
            text = _text(tinfo)
            if predicate(text):
                yield {
                    "name": text,
                    "size": _size(tinfo),
                    "category": _describe(tinfo)["category"],
                }

    return helpers.paged(make, offset, count)


def _size(tinfo: Any) -> int:
    try:
        return int(tinfo.get_size())
    except Exception:
        return 0


@op("type_info")
def type_info(db: Any, name: str) -> dict[str, Any]:
    """One named type (``ts``)."""
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type named {name!r}")
    return _describe(tinfo)


@op("type_at")
def type_at(db: Any, ea: int) -> dict[str, Any]:
    """The type applied at ``ea`` (``tp``)."""
    tinfo = db.types.get_at(ea)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type at 0x{ea:x}")
    return {"ea": ea, **_describe(tinfo)}


def _scalar_row(
    db: Any, name: str, tinfo: Any, offset: int, base: int, data: bytes | None
) -> dict[str, Any]:
    """One typed value: read it from memory (or ``data``) and describe it."""
    import struct

    size = _size(tinfo)
    if data is not None:
        raw = data[offset : offset + size]
    else:
        raw = db.bytes.get_bytes_at(base + offset, size) if size else None
    raw = bytes(raw) if raw else b""
    big = False
    try:
        import ida_ida

        big = bool(ida_ida.inf_is_be())
    except Exception:
        big = False
    kind = _describe(tinfo)["category"]
    row: dict[str, Any] = {
        "name": name,
        "offset": offset,
        "size": size,
        "kind": kind,
        "type": _text(tinfo),
    }
    if kind == "ptr" and len(raw) >= 4:
        width = 8 if len(raw) >= 8 else 4
        pointer = int.from_bytes(raw[:width], "big" if big else "little")
        row["pointer"] = pointer
        row["text"] = ""
        try:
            target = db.bytes.get_bytes_at(pointer, 24)
        except Exception:
            target = None
        if target:
            text = bytes(target).split(b"\0", 1)[0]
            row["text"] = "".join(
                chr(byte) if 0x20 <= byte < 0x7F else f"\\x{byte:02x}" for byte in text
            )
        return row
    if not raw:
        row["value"] = 0
        return row
    if _is_float(tinfo):
        import struct

        fmt = (">f" if big else "<f") if len(raw) == 4 else (">d" if big else "<d")
        row["float"] = struct.unpack(fmt, raw[: 4 if len(raw) == 4 else 8])[0]
        return row
    if kind in ("scalar", "enum", "bitfield"):
        unsigned = int.from_bytes(raw, "big" if big else "little")
        signed = unsigned
        if _is_signed(tinfo):
            bits = len(raw) * 8
            if unsigned >= 1 << (bits - 1):
                signed = unsigned - (1 << bits)
        row["value"] = signed
        row["unsigned"] = unsigned
        row["signed"] = signed != unsigned
        if _is_char(tinfo) and len(raw) == 1 and 0x20 <= raw[0] < 0x7F:
            row["char"] = chr(raw[0])
        return row
    row["bytes"] = raw.hex()
    return row


def _is_float(tinfo: Any) -> bool:
    try:
        return bool(tinfo.is_floating_point())
    except Exception:
        return str(tinfo) in ("float", "double", "long double")


def _is_signed(tinfo: Any) -> bool:
    try:
        return bool(tinfo.is_signed())
    except Exception:
        return False


def _is_char(tinfo: Any) -> bool:
    try:
        return bool(tinfo.is_char())
    except Exception:
        return False


@op("type_format")
def type_format(
    db: Any, name: str, ea: int | None = None, data_hex: str | None = None
) -> dict[str, Any]:
    """Typed values for ``tp``/``tpv``/``tpx``.

    Structs/unions yield one row per member (in declaration order, with their
    byte offsets); scalars yield a single row at offset 0.  ``data_hex`` reads
    the values from the given bytes (``tpx``) instead of memory.
    """
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        # ``tp int`` and friends name IDA's builtin scalar types, which are
        # not in the database's named-type list; parse them on the fly.
        import ida_typeinf

        tinfo = ida_typeinf.tinfo_t()
        parsed = ida_typeinf.parse_decl(
            tinfo, None, f"{name} __ire2_tmp;", ida_typeinf.PT_VAR | ida_typeinf.PT_SIL
        )
        if parsed is None:
            helpers.fail(protocol.NOT_FOUND, f"Cannot find {name!r} type")
    base = int(ea) if ea is not None else int(db.minimum_ea or 0)
    data = None
    if data_hex is not None:
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            helpers.fail(protocol.BAD_ARGS, f"not a hexpair string: {data_hex!r}")
    describe = _describe(tinfo)
    if describe["category"] in ("struct", "union"):
        import ida_typeinf

        udt = ida_typeinf.udt_type_data_t()
        if not tinfo.get_udt_details(udt):
            helpers.fail(protocol.IDA_ERROR, f"cannot read the layout of {name!r}")
        rows = [
            _scalar_row(db, str(member.name), member.type, int(member.offset) // 8, base, data)
            for member in udt
        ]
        return {"name": name, "base": base, "kind": describe["category"], "rows": rows}
    return {
        "name": name,
        "base": base,
        "kind": describe["category"],
        "rows": [_scalar_row(db, name, tinfo, 0, base, data)],
    }


@op("type_load_header", writes=True)
def type_load_header(db: Any, path: str) -> dict[str, Any]:
    """Parse a C header file into the local type library (``to``)."""
    from pathlib import Path

    import ida_typeinf

    header = Path(path).expanduser()
    if not header.is_file():
        helpers.fail(protocol.NOT_FOUND, f"no such header file: {path}")
    try:
        text = header.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        helpers.fail(protocol.BAD_ARGS, f"cannot read {path}: {exc}")
    til = ida_typeinf.get_idati()
    errors = int(db.types.parse_declarations(til, text))
    created = _declared_names(text)
    return {
        "path": str(header),
        "errors": errors,
        "created": [name for name in created if db.types.get_by_name(name) is not None],
    }


@op("type_typedefs")
def type_typedefs(db: Any) -> list[str]:
    """Names declared with ``typedef`` (``tt``)."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    out: list[str] = []
    seen: set[str] = set()
    for index in range(1, 1 << 16):
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_numbered_type(til, index):
            continue
        if not tinfo.is_typedef():
            continue
        name = str(tinfo.get_type_name() or "")
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


@op("type_parse", writes=True)
def type_parse(db: Any, declaration: str) -> dict[str, Any]:
    """Parse C declarations into the database (``tc``).

    ``parse_declarations`` returns the number of **parse errors**, so zero
    means success -- the opposite of the "truthy means it worked" convention,
    which is worth stating because getting it backwards rejects every valid
    declaration.
    """
    import ida_typeinf

    if not declaration.strip():
        helpers.fail(protocol.BAD_ARGS, "tc needs a C declaration")
    til = ida_typeinf.get_idati()
    errors = int(db.types.parse_declarations(til, declaration))
    if errors:
        helpers.fail(
            protocol.BAD_ARGS,
            f"C parser reported {errors} error(s) in {declaration.strip()!r}",
        )
    created = _declared_names(declaration)
    missing = [name for name in created if db.types.get_by_name(name) is None]
    if created and len(missing) == len(created):
        helpers.fail(
            protocol.BAD_ARGS,
            f"C parser accepted {declaration.strip()!r} but defined no named type",
        )
    return {"errors": errors, "created": [n for n in created if n not in missing]}


def _declared_names(declaration: str) -> list[str]:
    """Best-effort list of the type names a declaration block defines."""
    import re

    names = re.findall(
        r"\b(?:struct|union|enum|typedef)\s+([A-Za-z_]\w*)", declaration
    )
    return [name for name in dict.fromkeys(names) if name]


@op("type_apply", writes=True)
def type_apply(db: Any, ea: int, name: str) -> dict[str, Any]:
    """Apply a named type at ``ea`` (``tt``)."""
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type named {name!r}")
    if not db.types.apply_at(tinfo, ea):
        # IDA refuses to lay a struct over code, among other things; say what
        # the address currently is so the message is actionable.
        kind = "code" if db.bytes.is_code_at(ea) else "data"
        helpers.fail(
            protocol.IDA_ERROR,
            f"IDA refused to apply {name!r} at 0x{ea:x} (the address is {kind})",
        )
    return {"ea": ea, "name": name}


@op("type_delete", writes=True)
def type_delete(db: Any, name: str) -> dict[str, Any]:
    """Delete a named type (``t-``).

    ida-domain has no delete API, so this reaches for ``ida_typeinf``.
    """
    import ida_typeinf

    til = ida_typeinf.get_idati()
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type named {name!r}")
    ordinal = tinfo.get_ordinal()
    if not ordinal:
        helpers.fail(protocol.IDA_ERROR, f"{name!r} has no ordinal to delete")
    if not ida_typeinf.del_numbered_type(til, ordinal):
        helpers.fail(protocol.IDA_ERROR, f"IDA refused to delete {name!r}")
    return {"name": name}


@op("type_members")
def type_members(db: Any, name: str) -> dict[str, Any]:
    """Struct/union members (``td``)."""
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type named {name!r}")
    members = [
        {
            "name": member.name,
            "type": _text(member.type),
            "offset": int(member.offset),
            "size": int(member.size),
            "bitfield": bool(member.is_bitfield),
        }
        for member in db.types.get_udt_members(tinfo)
    ]
    if not members:
        helpers.fail(protocol.BAD_ARGS, f"{name!r} is not a struct or union with members")
    return {"name": name, "size": _size(tinfo), "members": members}


@op("type_enum_members")
def type_enum_members(db: Any, name: str) -> dict[str, Any]:
    """Enum members (``te``)."""
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type named {name!r}")
    members = [
        {"name": member.name, "value": int(member.value)}
        for member in db.types.get_enum_members(tinfo)
    ]
    if not members:
        helpers.fail(protocol.BAD_ARGS, f"{name!r} is not an enum")
    return {"name": name, "members": members}


@op("object_at")
def object_at(db: Any, ea: int, name: str) -> dict[str, Any]:
    """Read a typed value at ``ea`` (``dt``).

    ``parse_object_at`` returns an ``object_t`` whose ``__dict__`` holds one
    entry per struct member (plus ``__at__`` for the address).  That dict is the
    portable representation; the object itself is not JSON-serialisable.
    """
    tinfo = db.types.get_by_name(name)
    if tinfo is None:
        helpers.fail(protocol.NOT_FOUND, f"no type named {name!r}")
    obj = db.types.parse_object_at(ea, tinfo)
    if obj is None:
        helpers.fail(protocol.IDA_ERROR, f"cannot read a {name} at 0x{ea:x}")
    fields = {
        key: value
        for key, value in getattr(obj, "__dict__", {}).items()
        if not key.startswith("__")
    }
    return {
        "ea": ea,
        "name": name,
        "size": _size(tinfo),
        "fields": fields,
    }
