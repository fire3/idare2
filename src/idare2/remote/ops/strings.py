"""File-wide string scanner backing ``izz``.

radare2's ``izz`` scans the raw file, not just the sections the loader mapped,
and guesses ASCII/UTF-8/UTF-16LE/UTF-32LE per run.  IDA's string list only
covers database bytes (and this firmware's ``.debug_*`` sections are not
mapped), so the scanner is implemented here over the input file.

This is an independent implementation of the behaviour, not a port of
radare2's C code.
"""

from __future__ import annotations

from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

#: Bytes r2 renders as escape sequences rather than ``\xNN``.
_ESCAPES = {
    0x07: "\\a",
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0B: "\\v",
    0x0C: "\\f",
    0x0D: "\\r",
    0x1B: "\\e",
    0x5C: "\\\\",
}


def _render_codepoint(value: int, out: list[str]) -> bool:
    """Append one code point the way ``r_print_string`` does."""
    if value == 0:
        return False
    if value < 0x100 and value in _ESCAPES:
        out.append(_ESCAPES[value])
        return True
    if 0x20 <= value <= 0x7E:
        out.append(chr(value))
        return True
    if value > 0x10FFFF:
        return False
    char = chr(value)
    if char.isprintable():
        out.append(char)
        return True
    if value < 0x100:
        # r2 stops the string on an unprintable byte without an escape.
        return False
    out.append(f"\\u{value:04x}")
    return True


def _scan_ascii(data: bytes, start: int) -> tuple[int, str, int, str]:
    """UTF-8/ASCII run; returns ``(end, text, runes, type)``."""
    out: list[str] = []
    index = start
    runes = 0
    kind = "ascii"
    while index < len(data):
        byte = data[index]
        if byte < 0x80:
            value = byte
            width = 1
        else:
            width = _utf8_width(byte, data, index)
            if not width:
                break
            try:
                value = ord(data[index : index + width].decode("utf-8"))
            except UnicodeDecodeError:
                break
            kind = "utf8"
        if not _render_codepoint(value, out):
            break
        index += width
        runes += 1
    return index, "".join(out), runes, kind


def _utf8_width(byte: int, data: bytes, index: int) -> int:
    if 0xC2 <= byte <= 0xDF:
        width = 2
    elif 0xE0 <= byte <= 0xEF:
        width = 3
    elif 0xF0 <= byte <= 0xF4:
        width = 4
    else:
        return 0
    if index + width > len(data):
        return 0
    return width


def _scan_wide(data: bytes, start: int, unit: int) -> tuple[int, str, int]:
    """UTF-16LE/UTF-32LE run; returns ``(end, text, runes)``."""
    out: list[str] = []
    index = start
    runes = 0
    while index + unit <= len(data):
        value = int.from_bytes(data[index : index + unit], "little")
        if unit == 4 and (value & 0xFF) == 0xFF:
            value = 0
        if not _render_codepoint(value, out):
            break
        index += unit
        runes += 1
    return index, "".join(out), runes


def _valid_utf8_start(data: bytes, index: int) -> bool:
    """Whether a complete UTF-8 sequence starts at ``index``.

    r2's wide-string detection only happens after ``r_utf8_decode`` succeeds;
    a byte like 0xDF followed by 0x00 is not a valid sequence, so a table of
    UTF-32LE integers with a high low-byte is *not* detected as a wide string.
    """
    byte = data[index]
    if byte < 0x80:
        return True
    width = _utf8_width(byte, data, index)
    if not width:
        return False
    try:
        data[index : index + width].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _looks_wide16(data: bytes, index: int) -> bool:
    if index % 2 or index + 6 > len(data) or not _valid_utf8_start(data, index):
        return False
    return (
        data[index + 1] == 0
        and data[index + 2] != 0
        and data[index + 3] == 0
        and data[index + 4] != 0
        and data[index + 5] == 0
    )


def _looks_wide32(data: bytes, index: int) -> bool:
    if index % 4 or index + 10 > len(data) or not _valid_utf8_start(data, index):
        return False
    if not (
        data[index + 1] == 0
        and data[index + 2] == 0
        and data[index + 3] == 0
        and data[index + 4] != 0
        and data[index + 5] == 0
    ):
        return False
    return not (
        data[index + 6] == 0
        and data[index + 7] == 0
        and data[index + 8] != 0
        and data[index + 9] == 0
    )


def _locate(elf: Any, offset: int) -> tuple[int, int, str]:
    """``(paddr, vaddr, section)`` for a file offset."""
    if elf is not None:
        for section in elf.sections:
            if section.type == 8 or section.size <= 0:
                continue
            if section.offset <= offset < section.offset + section.size:
                vaddr = (
                    section.addr + (offset - section.offset)
                    if section.flags & 0x2
                    else 0
                )
                return offset, vaddr, section.r2_name()
    return offset, offset, ""


def scan_file(
    data: bytes,
    *,
    elf: Any = None,
    min_length: int = 4,
    max_length: int = 512,
    alignment: int = 0,
    encoding: str = "guess",
) -> list[dict[str, Any]]:
    """Scan ``data`` for r2-shaped string rows."""
    rows: list[dict[str, Any]] = []
    index = 0
    length = len(data)
    while index < length:
        if index + 4 <= length and data[index : index + 4] == b"\0\0\0\0":
            index += 4
            continue
        if encoding == "wide":
            kind = "utf16le"
        elif encoding in ("ascii", "utf8"):
            kind = "ascii"
        elif _looks_wide32(data, index):
            kind = "utf32le"
        elif _looks_wide16(data, index):
            kind = "utf16le"
        else:
            kind = "ascii"

        start = index
        if kind == "utf32le":
            index, text, runes = _scan_wide(data, start, 4)
            terminator = 4
        elif kind == "utf16le":
            index, text, runes = _scan_wide(data, start, 2)
            terminator = 2
        else:
            index, text, runes, scanned_kind = _scan_ascii(data, start)
            if scanned_kind == "utf8" and encoding in ("guess", "utf8"):
                kind = "utf8"
            terminator = 1

        stripped = text.rstrip(" \t\r\n")
        runes -= len(text) - len(stripped)
        text = stripped
        if runes >= min_length and (not alignment or start % alignment == 0):
            if runes > max_length:
                runes = max_length
            paddr, vaddr, section = _locate(elf, start)
            rows.append(
                {
                    "vaddr": vaddr,
                    "paddr": paddr,
                    "ordinal": len(rows),
                    "size": index - start + terminator,
                    "length": runes,
                    "section": section,
                    "type": kind,
                    "string": text,
                }
            )
        if index <= start:
            index = start + 1
    return rows


@op("all_strings")
def all_strings(
    db: Any,
    pattern: str | None = None,
    offset: int = 0,
    count: int | None = None,
    min_length: int = 4,
    max_length: int = 512,
    alignment: int = 0,
    encoding: str = "guess",
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """``izz``: strings over the whole original input file."""
    import ida_nalt

    from idare2.remote.ops.info import _elf_for

    if encoding not in ("guess", "ascii", "utf8", "wide"):
        helpers.fail(protocol.BAD_ARGS, f"unsupported string encoding {encoding!r}")
    try:
        path = ida_nalt.get_input_file_path()
    except Exception:
        path = ""
    if not path:
        helpers.fail(protocol.NOT_FOUND, "izz needs the original input file")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        helpers.fail(protocol.NOT_FOUND, f"cannot read {path}: {exc}")
    rows = scan_file(
        data,
        elf=_elf_for(db),
        min_length=max(min_length, 1),
        max_length=max(max_length, 1),
        alignment=max(alignment, 0),
        encoding=encoding,
    )
    predicate = helpers.name_filter(pattern)

    def make():
        for row in rows:
            if predicate(row["string"]):
                yield row

    return helpers.paged(make, offset, count)
