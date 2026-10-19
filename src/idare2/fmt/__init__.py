"""Output formatting: structured data in, r2-shaped text out.

Nothing in this subpackage talks to IDA or to Nexus -- the formatters take the
plain dicts that the remote operations return.  That is what lets ``~``, ``|``,
``>`` and the ``j``/``*`` suffixes apply uniformly to every command.
"""

from __future__ import annotations

from typing import Any

#: r2 prints 32-bit addresses with 8 hex digits and 64-bit with 16.
WIDTH32 = 8
WIDTH64 = 16


def addr_width(bits: int | None) -> int:
    return WIDTH64 if bits == 64 else WIDTH32


def fmt_addr(ea: int, width: int = WIDTH32) -> str:
    """``0x00015e50`` -- r2's zero-padded address form."""
    return f"0x{ea & ((1 << (width * 4)) - 1):0{width}x}"


def fmt_hex_bytes(raw: bytes, *, group: bool = True) -> str:
    """Instruction bytes as r2 prints them: ``b4379fe5`` / ``b4 37 9f e5``."""
    text = raw.hex()
    if group and len(raw) > 4:
        return " ".join(text[i : i + 8] for i in range(0, len(text), 8))
    return text


def fmt_int(value: int, width: int = 0) -> str:
    """Signed and unsigned decimal plus hex, the way ``?v`` shows a value."""
    mask = (1 << (width * 8)) - 1 if width else None
    unsigned = value & mask if mask else value
    signed = unsigned
    if mask and unsigned > mask >> 1:
        signed = unsigned - mask - 1
    return f"0x{unsigned:x} {unsigned} {signed}"


def column(text: str, width: int) -> str:
    return text.ljust(width)


def indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def human_size(count: int) -> str:
    """r2's ``humansz`` formatting: 1.7M, 512K, 3.4G."""
    step = 1024.0
    value = float(count)
    for suffix in ("", "K", "M", "G", "T"):
        if abs(value) < step or suffix == "T":
            if not suffix:
                return str(int(value))
            return f"{value:.1f}{suffix}"
        value /= step
    return str(count)  # pragma: no cover


def truth(value: Any) -> str:
    return "true" if value else "false"


def jsonable(value: Any) -> Any:
    """Recursively convert a remote result into JSON-native values.

    ``bytes`` become hex strings, matching r2's JSON (``"bytes": "10482de9"``).
    Without this, ``json.dumps(default=str)`` would emit ``b'\\x10H-\\xe9'``.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def to_json(value: Any, *, indent: int = 2) -> str:
    """Serialise a remote result the way r2's ``j`` suffix does."""
    import json

    return json.dumps(jsonable(value), indent=indent, default=str)
