"""Memory and data operations backing ``px`` / ``ps`` / ``pv`` / ``p8``."""

from __future__ import annotations

from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

#: Refuse absurd reads rather than have IDA allocate them.
MAX_READ = 1 << 24

_WIDTHS = {1: "byte", 2: "word", 4: "dword", 8: "qword"}


@op("read_bytes")
def read_bytes(db: Any, ea: int, count: int) -> dict[str, Any]:
    """Raw memory read (``px``, ``p8``, ``pr``)."""
    if count > MAX_READ:
        helpers.fail(protocol.BAD_ARGS, f"refusing to read {count} bytes at once")
    return {"ea": ea, "count": count, "data": helpers.read_bytes(db, ea, count)}


@op("read_values")
def read_values(db: Any, ea: int, count: int, width: int = 4) -> dict[str, Any]:
    """``count`` little/big-endian integers of ``width`` bytes (``pxw``, ``pxq``)."""
    if width not in _WIDTHS:
        helpers.fail(protocol.BAD_ARGS, f"width must be 1, 2, 4 or 8, not {width}")
    import ida_ida

    big = bool(ida_ida.inf_is_be())
    getters = {
        1: db.bytes.get_byte_at,
        2: db.bytes.get_word_at,
        4: db.bytes.get_dword_at,
        8: db.bytes.get_qword_at,
    }
    getter = getters[width]
    values: list[int] = []
    for index in range(count):
        address = ea + index * width
        value = getter(address)
        if value is None:
            break
        values.append(int(value))
    return {"ea": ea, "width": width, "count": len(values), "big_endian": big, "values": values}


@op("read_value")
def read_value(db: Any, ea: int, width: int = 4) -> dict[str, Any]:
    """A single value at ``ea`` (``pv``)."""
    if width not in _WIDTHS:
        helpers.fail(protocol.BAD_ARGS, f"width must be 1, 2, 4 or 8, not {width}")
    import ida_ida

    getters = {
        1: db.bytes.get_byte_at,
        2: db.bytes.get_word_at,
        4: db.bytes.get_dword_at,
        8: db.bytes.get_qword_at,
    }
    value = getters[width](ea)
    if value is None:
        helpers.fail(protocol.BAD_ADDRESS, f"cannot read {_WIDTHS[width]} at 0x{ea:x}")
    raw = db.bytes.get_bytes_at(ea, width) or b""
    return {
        "ea": ea,
        "width": width,
        "value": int(value),
        "bytes": bytes(raw),
        "big_endian": bool(ida_ida.inf_is_be()),
    }


@op("read_string")
def read_string(
    db: Any, ea: int, max_length: int = 4096, encoding: str = "auto"
) -> dict[str, Any]:
    """String read (``ps``, ``psw``).

    ``encoding="auto"`` asks IDA first, which picks up the string type it already
    inferred; ``"ascii"`` and ``"utf16"`` force a decoding of the raw bytes.
    """
    if encoding == "auto":
        text = db.bytes.get_string_at(ea, max_length)
        if text is not None:
            return {"ea": ea, "text": text, "length": len(text), "encoding": "auto"}
        text = db.bytes.get_cstring_at(ea, max_length)
        if text is not None:
            return {"ea": ea, "text": text, "length": len(text), "encoding": "cstring"}
        helpers.fail(protocol.NOT_FOUND, f"no string at 0x{ea:x}")

    raw = helpers.read_bytes(db, ea, max_length)
    if encoding == "utf16":
        cut = _terminator(raw, 2)
        text = raw[:cut].decode("utf-16-le", errors="replace")
    else:
        cut = _terminator(raw, 1)
        text = raw[:cut].decode("utf-8", errors="replace")
    return {"ea": ea, "text": text, "length": len(text), "encoding": encoding}


def _terminator(raw: bytes, unit: int) -> int:
    for index in range(0, len(raw) - unit + 1, unit):
        if raw[index : index + unit] == b"\x00" * unit:
            return index
    return len(raw)


@op("data_info")
def data_info(db: Any, ea: int) -> dict[str, Any]:
    """Size and kind of the item at ``ea`` (``Cd.``, ``pA``)."""
    size = db.bytes.get_data_size_at(ea)
    flags = helpers.item_flags(db, ea)
    return {
        "ea": ea,
        "size": int(size) if size else 0,
        "is_code": bool(db.bytes.is_code_at(ea)),
        "is_data": bool(db.bytes.is_data_at(ea)),
        "is_unknown": bool(db.bytes.is_unknown_at(ea)),
        "is_string": bool(db.bytes.is_string_literal_at(ea)),
        "flags": flags,
    }
