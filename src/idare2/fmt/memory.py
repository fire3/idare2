"""Hexdump and value rendering, matching radare2's ``px`` layout.

Measured against r2 6.2.5::

    - offset -  1011 1213 1415 1617 1819 1A1B 1C1D 1E1F  0123456789ABCDEF
    0x00008d10  9e00 0000 0000 0000 0000 0000 3000 0000  ............0...

The header is not decorative: the first block is the **low byte** of each
byte's offset in uppercase hex, two bytes per group, and the second block is
the uppercase hex digit of each byte's **low nibble**.  Both wrap at 0xFF, which
is why ``px @ 0x8d1b`` labels its first group ``1B1C``.
"""

from __future__ import annotations

from typing import Any

from idare2.fmt import addr_width, fmt_addr

PRINTABLE = set(range(0x20, 0x7F))


def format_hexdump(payload: dict[str, Any], session: Any) -> list[str]:
    """Render a ``read_bytes`` result (``px`` and friends)."""
    ea = int(payload["ea"])
    raw = bytes(payload.get("data") or b"")
    cols = session.config.get_int("hex.cols")
    width = addr_width(session.info.get("bits"))
    pairs = session.config.get_bool("hex.pairs")
    show_offset = session.config.get_bool("hex.offset")
    show_ascii = session.config.get_bool("hex.ascii")

    rows: list[str] = []
    if session.config.get_bool("hex.header") and raw:
        rows.append(_header(ea, cols, width, pairs, show_offset, show_ascii))

    for offset in range(0, len(raw), cols):
        chunk = raw[offset : offset + cols]
        rows.append(
            _row(ea + offset, chunk, cols, width, pairs, show_offset, show_ascii)
        )
    return rows


def _data_width(cols: int, pairs: bool) -> int:
    """Characters the hex block occupies for ``cols`` bytes."""
    if pairs and cols % 2 == 0:
        groups = cols // 2
        return groups * 4 + (groups - 1)
    return cols * 2 + (cols - 1)


def _header(
    ea: int, cols: int, width: int, pairs: bool, show_offset: bool, show_ascii: bool
) -> str:
    # r2 puts two spaces after "- offset -" and after the hex block; without
    # them the header is one column narrower than the rows and misaligns.
    out = ("- offset -  ") if show_offset else ""
    if pairs and cols % 2 == 0:
        groups = [
            f"{(ea + i) & 0xFF:02X}{(ea + i + 1) & 0xFF:02X}" for i in range(0, cols, 2)
        ]
    else:
        groups = [f"{(ea + i) & 0xFF:02X}" for i in range(cols)]
    out += " ".join(groups)
    if show_ascii:
        out += "  " + "".join(f"{(ea + i) & 0xF:X}" for i in range(cols))
    return out


def _row(
    ea: int,
    chunk: bytes,
    cols: int,
    width: int,
    pairs: bool,
    show_offset: bool,
    show_ascii: bool,
) -> str:
    out = (fmt_addr(ea, width) + "  ") if show_offset else ""
    if pairs:
        cells = [
            chunk[i : i + 2].hex()
            for i in range(0, len(chunk), 2)
        ]
    else:
        cells = [f"{byte:02x}" for byte in chunk]
    block = " ".join(cells)
    out += block.ljust(_data_width(cols, pairs))
    if show_ascii:
        text = "".join(chr(byte) if byte in PRINTABLE else "." for byte in chunk)
        out += "  " + text
    return out.rstrip()


_VALUE_DECIMAL_WIDTH = {1: 4, 2: 7, 4: 13, 8: 23}


def format_values(payload: dict[str, Any], session: Any, *, fmt: str = "hex") -> list[str]:
    """Render a ``read_values`` result like r2's value dumps.

    r2 does not print one value per line: it prints ``hex.cols`` bytes per row,
    pads the value block when a row is short, and starts the ASCII column at a
    fixed offset.  The padding rules are copied from ``r_print_hexdump`` in
    radare2's ``libr/util/print.c``.
    """
    step = int(payload.get("width") or 0)
    if step not in _VALUE_DECIMAL_WIDTH:
        raise ValueError(f"unsupported value width {step}")
    values = [int(value) for value in payload.get("values") or []]
    if not values:
        return []
    mask = (1 << (step * 8)) - 1
    order = "big" if payload.get("big_endian") else "little"
    raw = b"".join((value & mask).to_bytes(step, order) for value in values)

    cols = session.config.get_int("hex.cols")
    cols = max(step, (cols // step) * step)
    address_width = addr_width(session.info.get("bits"))
    show_header = session.config.get_bool("hex.header")
    show_offset = session.config.get_bool("hex.offset")
    show_ascii = session.config.get_bool("hex.ascii")
    ea = int(payload["ea"])

    rows: list[str] = []
    if fmt != "hex" and show_header:
        rows.append(_value_header(ea, cols, address_width, show_offset, show_ascii))

    for offset in range(0, len(raw), cols):
        chunk = raw[offset : offset + cols]
        row_values = values[offset // step : (offset + len(chunk)) // step]
        rows.append(
            _value_row(
                ea + offset,
                chunk,
                row_values,
                step,
                cols,
                fmt,
                address_width,
                show_offset,
                show_ascii,
            )
        )
    return rows


def _value_header(
    ea: int, cols: int, address_width: int, show_offset: bool, show_ascii: bool
) -> str:
    out = "- offset -".ljust(address_width + 6) if show_offset else ""
    for index in range(cols):
        if index:
            out += "  " if index % 2 else "   "
        out += f"{(ea + index) & 0xF:X}"
    if show_ascii:
        out += "  " + "".join(f"{(ea + index) & 0xF:X}" for index in range(cols))
    return out.rstrip()


def _value_row(
    ea: int,
    chunk: bytes,
    values: list[int],
    step: int,
    cols: int,
    fmt: str,
    address_width: int,
    show_offset: bool,
    show_ascii: bool,
) -> str:
    out = (fmt_addr(ea, address_width) + " ") if show_offset else ""
    out += " "
    for value in values:
        if fmt == "hex":
            out += f"0x{value:0{step * 2}x}" + ("  " if step == 8 else " ")
        else:
            number = _signed(value, step) if fmt == "signed" else value
            out += f"{number:>{_VALUE_DECIMAL_WIDTH[step]}} "
    for index in range(len(chunk), cols):
        out += _value_padding(fmt, step, index)
    if show_ascii:
        out += " "
        out += "".join(chr(byte) if byte in PRINTABLE else "." for byte in chunk)
    return out.rstrip()


def _value_padding(fmt: str, step: int, index: int) -> str:
    """Whitespace r2 emits for a byte missing from a short row."""
    if fmt == "hex" and step == 4:
        return "  " if index % 4 == 0 else "   "
    if fmt == "hex":
        return "  " if index % 2 == 0 else "   "
    if fmt == "signed":
        return "  " if index % 2 == 0 else "     "
    return "  " if index % 2 == 0 else "   "


def _signed(value: int, width: int) -> int:
    limit = 1 << (width * 8)
    return value - limit if value >= limit >> 1 else value


def format_value(payload: dict[str, Any], session: Any) -> list[str]:
    """Render a ``read_value`` result (``pv``)."""
    raw = bytes(payload.get("bytes") or b"")
    value = int(payload["value"])
    width = int(payload["width"])
    lines = [
        f"hex     0x{value:0{width * 2}x}",
        f"uint    {value}",
        f"int     {_signed(value, width)}",
    ]
    if raw:
        lines.append(f"bytes   {raw.hex()}")
    if width == 4:
        lines.append(f"float   {_as_float(raw, 4, payload.get('big_endian'))}")
    if width == 8:
        lines.append(f"double  {_as_float(raw, 8, payload.get('big_endian'))}")
    return lines


def _as_float(raw: bytes, size: int, big_endian: Any) -> str:
    import struct

    if len(raw) < size:
        return "-"
    fmt = (">" if big_endian else "<") + ("f" if size == 4 else "d")
    try:
        return repr(struct.unpack(fmt, raw[:size])[0])
    except struct.error:
        return "-"


def format_string(payload: dict[str, Any], session: Any) -> list[str]:
    """Render a ``read_string`` result (``ps``, ``psw``)."""
    return [str(payload.get("text") or "")]


def format_bytes(payload: dict[str, Any], session: Any) -> list[str]:
    """Render a raw read as a hexpair list (``p8``)."""
    raw = bytes(payload.get("data") or b"")
    return [raw.hex()]
