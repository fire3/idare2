"""A practical subset of radare2's ``pf`` format language.

The parser is pure client-side code: the command reads one block and every
field is decoded from that buffer.  The supported alphabet mirrors r2's help
for the scalar formats, offset controls and inline arrays; unsupported format
characters fail loudly instead of silently printing the wrong bytes.
"""

from __future__ import annotations

import re
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from idare2.errors import UsageError

_FIXED = {
    "b": 1,
    "c": 1,
    "C": 1,
    "w": 2,
    "d": 4,
    "i": 4,
    "x": 4,
    "o": 4,
    "f": 4,
    "g": 2,
    "q": 8,
    "F": 8,
    "t": 4,
    "Q": 16,
    "s": 4,
    "S": 8,
}

_SKIP = {
    ".": 1,
    ":": 4,
    ",": -1,
    ";": -4,
}

_UNSUPPORTED = {
    "B": "enum bitfields",
    "D": "embedded disassembly",
    "E": "enum names",
    "G": "long double",
    "T": "buffer previews",
    "X": "formatted hexpairs",
    "r": "CPU registers",
    "u": "uleb128",
}

ReadString = Callable[[int, int], str | None] | None


@dataclass(frozen=True)
class Field:
    code: str
    size: int
    count: int = 1
    inline: bool = False
    name: str | None = None


@dataclass(frozen=True)
class Format:
    fields: tuple[Field, ...]
    repeat: int = 1
    union: bool = False


@dataclass
class Rendered:
    lines: list[str]
    rows: list[dict[str, Any]]


def parse_format(
    text: str,
    *,
    pointer_size: int = 4,
    names: list[str] | tuple[str, ...] = (),
    repeat: int = 1,
    union: bool = False,
) -> Format:
    """Parse one r2 format string, assigning optional field labels."""
    if not text:
        raise UsageError("pf needs a format string")

    prefix = re.match(r"(\d+)(.*)", text)
    if prefix:
        count = int(prefix.group(1))
        text = prefix.group(2)
        if not text:
            raise UsageError("pf: a repeat count needs a format character")
        if count == 0:
            union = True
        else:
            repeat = count

    fields: list[Field] = []
    index = 0
    inline = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            break
        if char == "[":
            end = text.find("]", index + 1)
            if end < 0:
                raise UsageError("pf: unterminated array count")
            digits = text[index + 1 : end]
            if not digits.isdigit():
                raise UsageError(f"pf: bad array count {digits!r}")
            inline = int(digits)
            index = end + 1
            continue
        if char == "+":
            index += 1
            continue
        if char in _SKIP:
            fields.append(Field(char, _SKIP[char]))
            inline = 0
            index += 1
            continue
        if char == "e":
            fields.append(Field("e", 0))
            inline = 0
            index += 1
            continue
        if char in ("n", "N"):
            if index + 1 >= len(text) or text[index + 1] not in "1248":
                raise UsageError(f"pf: {char} needs a size of 1, 2, 4 or 8")
            size = int(text[index + 1])
            fields.append(
                Field(char, size, count=inline or 1, inline=bool(inline))
            )
            inline = 0
            index += 2
            continue
        if char == "p":
            fields.append(
                Field("p", pointer_size, count=inline or 1, inline=bool(inline))
            )
            inline = 0
            index += 1
            continue
        if char in ("z", "Z"):
            fields.append(Field(char, 0, count=inline or 1, inline=bool(inline)))
            inline = 0
            index += 1
            continue
        if char in _FIXED:
            fields.append(
                Field(char, _FIXED[char], count=inline or 1, inline=bool(inline))
            )
            inline = 0
            index += 1
            continue
        if char in _UNSUPPORTED:
            raise UsageError(f"pf: {char} ({_UNSUPPORTED[char]}) is not supported yet")
        raise UsageError(f"pf: unknown format character {char!r}")

    if inline:
        raise UsageError("pf: an array count needs a following format character")

    value_fields = [
        field
        for field in fields
        if field.code not in _SKIP and field.code not in ("e", "+")
    ]
    names = tuple(names[: len(value_fields)])
    named_fields: list[Field] = []
    value_index = 0
    for field in fields:
        if field.code not in _SKIP and field.code not in ("e", "+"):
            if value_index < len(names):
                field = replace(field, name=names[value_index])
            value_index += 1
        named_fields.append(field)
    fields = named_fields
    return Format(tuple(fields), repeat=repeat, union=union)


def format_size(fmt: Format, *, include_repeat: bool = True) -> int:
    """Bytes consumed by one format, rounded to r2's minimum for strings."""
    cursor = 0
    union_end = 0
    for field in fmt.fields:
        if field.code in _SKIP:
            cursor = max(0, cursor + field.size)
            union_end = max(union_end, cursor)
            continue
        if field.code == "e":
            continue
        if fmt.union:
            union_end = max(union_end, _field_size(field))
            continue
        cursor += _field_size(field)
        union_end = max(union_end, cursor)
    one = union_end if fmt.union else cursor
    return one * max(fmt.repeat, 1) if include_repeat else one


def render(
    data: bytes,
    ea: int,
    fmt: Format,
    *,
    endian: str = "little",
    format_addr: Callable[[int], str] | None = None,
    read_string: ReadString = None,
) -> Rendered:
    """Decode ``fmt`` over ``data``, producing r2-style lines and JSON rows."""
    addr_fmt = format_addr or (lambda value: f"0x{value:08x}")
    lines: list[str] = []
    rows: list[dict[str, Any]] = []
    cursor = 0
    big = endian == "big"
    for iteration in range(max(fmt.repeat, 1)):
        start = cursor
        grouped = fmt.repeat > 1
        if grouped:
            lines.append(f"{addr_fmt(ea + start)} [{iteration}] {{")

        iteration_end = start
        for field in fmt.fields:
            if field.code in _SKIP:
                cursor = max(0, cursor + field.size)
                iteration_end = max(iteration_end, cursor)
                continue
            if field.code == "e":
                big = not big
                continue

            at = start if fmt.union else cursor
            value, display = _read_field(
                data, at, field, big=big, addr_fmt=addr_fmt, read_string=read_string
            )
            line = _line(field, addr_fmt(ea + at), display)
            lines.append(f"  {line}" if grouped else line)
            rows.append(
                {
                    "name": field.name or "",
                    "type": field.code,
                    "offset": ea + at,
                    "value": value,
                }
            )
            if not fmt.union:
                cursor += _field_advance(field, data, at)
            iteration_end = max(iteration_end, cursor)

        if grouped:
            lines.append("}")
        if fmt.union:
            sizes = [_field_size(field) for field in _value_fields(fmt)]
            if sizes:
                cursor = start + max(sizes)
        else:
            cursor = max(cursor, iteration_end)
    return Rendered(lines, rows)


def _value_fields(fmt: Format) -> list[Field]:
    return [
        field for field in fmt.fields if field.code not in _SKIP and field.code != "e"
    ]


def _field_size(field: Field) -> int:
    if field.code in ("z", "Z"):
        unit = 2 if field.code == "Z" else 1
        return (field.count * unit) if field.inline else unit
    return field.size * field.count


def _field_advance(field: Field, data: bytes, offset: int) -> int:
    if field.inline:
        return _field_size(field)
    if field.code == "z":
        end = data.find(b"\x00", offset)
        return len(data) - offset if end < 0 else end - offset + 1
    if field.code == "Z":
        for index in range(offset, len(data) - 1, 2):
            if data[index : index + 2] == b"\x00\x00":
                return index - offset + 2
        return len(data) - offset
    return field.size


def _read_field(
    data: bytes,
    offset: int,
    field: Field,
    *,
    big: bool,
    addr_fmt: Callable[[int], str],
    read_string: ReadString,
) -> tuple[Any, str]:
    if field.code in ("z", "Z"):
        return _read_string_field(data, offset, field, big=big)
    if field.inline:
        values = []
        displays = []
        for index in range(field.count):
            value, display = _scalar(
                data, offset + index * field.size, field, big=big, addr_fmt=addr_fmt,
                read_string=read_string,
            )
            values.append(value)
            displays.append(display)
        return values, f"[ {', '.join(displays)} ]"
    return _scalar(data, offset, field, big=big, addr_fmt=addr_fmt, read_string=read_string)


def _read_string_field(
    data: bytes, offset: int, field: Field, *, big: bool
) -> tuple[Any, str]:
    if field.code == "Z":
        if field.inline:
            raw = data[offset : offset + field.count * 2]
        else:
            end = _wide_terminator(data[offset:])
            raw = data[offset : offset + end]
        text = raw.decode("utf-16-be" if big else "utf-16-le", errors="replace")
        return text, _quote_text(text)

    if field.inline:
        raw = data[offset : offset + field.count]
    else:
        end = data.find(b"\x00", offset)
        raw = data[offset:] if end < 0 else data[offset:end]
    text = raw.decode("latin-1")
    return text, _quote_text(text)


def _wide_terminator(raw: bytes) -> int:
    for index in range(0, len(raw) - 1, 2):
        if raw[index : index + 2] == b"\x00\x00":
            return index
    return len(raw)


def _scalar(
    data: bytes,
    offset: int,
    field: Field,
    *,
    big: bool,
    addr_fmt: Callable[[int], str],
    read_string: ReadString,
) -> tuple[Any, str]:
    size = field.size
    raw = data[offset : offset + size]
    if len(raw) < size:
        return None, "<unreadable>"
    byteorder = "big" if big else "little"
    if field.code in ("f", "F", "g"):
        code = {"f": "f", "F": "d", "g": "e"}[field.code]
        value = struct.unpack((">" if big else "<") + code, raw)[0]
        precision = {"f": ".8g", "F": ".17g", "g": ".5g"}[field.code]
        return value, format(value, precision)

    value = int.from_bytes(raw, byteorder, signed=field.code in ("c", "i", "n"))
    if field.code == "c":
        return value, _char(value)
    if field.code == "b":
        return value & 0xFF, f"0x{value & 0xFF:02x}"
    if field.code == "C":
        return value, str(value)
    if field.code == "w":
        return value, f"0x{value:04x}"
    if field.code in ("d", "x"):
        return value, f"0x{value:08x}"
    if field.code in ("i", "n"):
        return value, str(value)
    if field.code == "N":
        return value, str(value)
    if field.code == "o":
        return value, f"(octal)  0{value:o}"
    if field.code == "q":
        return value, f"(qword)0x{value:016x}"
    if field.code == "Q":
        return value, f"0x{value:032x}"
    if field.code == "t":
        try:
            return value, time.ctime(value)
        except (OverflowError, OSError, ValueError):
            return value, "<invalid time>"
    if field.code == "p":
        prefix = "(qword)" if size == 8 else ""
        return value, f"{prefix}0x{value:0{size * 2}x}"
    if field.code in ("s", "S"):
        pointer = f"0x{value:0{size * 2}x}"
        if read_string is None:
            return value, pointer
        text = read_string(value, 256)
        if text is None:
            return value, f"{pointer} -> <invalid>"
        return value, f"{pointer} -> {_quote_text(text)}"
    return value, str(value)


def _char(value: int) -> str:
    byte = value & 0xFF
    if 0x20 <= byte < 0x7F:
        if byte == 0x27:
            return "\"'\""
        return f"'{chr(byte)}'"
    return "'.'"


def _quote_text(text: str) -> str:
    out = []
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif 0x20 <= code < 0x7F:
            out.append(char)
        elif code <= 0xFF:
            out.append(f"\\x{code:02x}")
        else:
            out.append(f"\\u{code:04x}")
    return '"' + "".join(out) + '"'


def _line(field: Field, address: str, display: str) -> str:
    if field.name:
        return f" {field.name} : {address} = {display}"
    return f"{address} = {display}"
