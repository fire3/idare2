"""The ``p`` print family: disassembly, memory, values, strings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from idare2.cmd import command, numeric_args, with_more
from idare2.errors import UsageError
from idare2.fmt import disasm as fmt_disasm
from idare2.fmt import memory as fmt_memory
from idare2.fmt import to_json

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

DISASM_DETAIL = [
    ("pd", "[n]", "disassemble N instructions"),
    ("pD", "[n]", "disassemble N bytes"),
    ("pdj", "[n]", "disassemble to json"),
    ("pdf", "", "disassemble the whole function"),
    ("pdfj", "", "disassemble the whole function to json"),
    ("pdb", "", "disassemble the current basic block"),
    ("pdr", "", "recursive disassembly across the function graph"),
    ("pi", "[n]", "print N instructions without the address and byte columns"),
    ("pdl", "[n]", "instruction sizes"),
    ("pdc", "[n]", "pseudo-C decompilation (Hex-Rays)"),
    ("pdq", "[n]", "disassemble N instructions, address and text only"),
]

MEMORY_DETAIL = [
    ("px", "[n]", "hexdump of N bytes"),
    ("pxw", "[n]", "hexdump as 32-bit words"),
    ("pxq", "[n]", "hexdump as 64-bit words"),
    ("pxd", "[n]", "signed decimal dump"),
    ("pxu", "[n]", "unsigned decimal dump"),
    ("p8", "[n]", "hexpair list of bytes"),
    ("pr", "[n]", "raw bytes"),
    ("pc", "[n]", "C array of bytes"),
    ("ps", "[n]", "string at the current offset"),
    ("psw", "[n]", "wide (UTF-16) string"),
    ("pv", "[n]", "value of the given size (1, 2, 4, 8)"),
    ("ph", "[algo]", "hash of a block"),
]


def _json_mode(token: str) -> bool:
    return token.endswith("j")


@command("p[dDiI]", usage="[n]", summary="print disassembly", detail=DISASM_DETAIL)
def print_disasm(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    rest, count, offset = numeric_args(session, statement)
    target = session.resolve(rest[0]) if rest else session.seek

    if token.startswith("pd") and token.endswith("c"):
        return _decompile(session, target, count, offset)

    mode = "count"
    if token in ("pdf", "pdfj", "pdr"):
        mode = "function"
    elif token == "pdb":
        mode = "block"
    elif token == "pD":
        mode = "bytes"

    payload, meta = session.remote.call_with_meta(
        "disasm", ea=target, count=count, offset=offset, mode=mode
    )
    session.prime_comments(
        {int(line["ea"]): line.get("comment") or "" for line in payload.get("lines", [])}
    )

    if _json_mode(token):
        return [to_json(payload)]

    if token == "pi":
        return [line["text"] for line in payload.get("lines", [])]
    if token == "pdl":
        return [str(line["size"]) for line in payload.get("lines", [])]
    if token == "pdq":
        return [
            f"{session.format_addr(int(line['ea']))} {line['text']}"
            for line in payload.get("lines", [])
        ]

    lines = fmt_disasm.format_disasm(payload, session)
    return with_more(lines, meta)


def _decompile(session: Session, target: int, count: int | None, offset: int) -> list[str]:
    payload, meta = session.remote.call_with_meta(
        "decompile", ea=target, count=count, offset=offset
    )
    return with_more(list(payload.get("lines") or []), meta)


@command("p[x8ruvscw]", usage="[n]", summary="print memory and values", detail=MEMORY_DETAIL)
def print_memory(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    rest, count, _offset = numeric_args(session, statement)
    target = session.resolve(rest[0]) if rest else session.seek
    width = session.info.get("bits") or 32

    if token == "pwd":
        import os

        return [os.getcwd()]

    if token.startswith("ps"):
        encoding = "utf16" if token == "psw" else "auto"
        payload = session.remote.call(
            "read_string", ea=target, max_length=count or 4096, encoding=encoding
        )
        return fmt_memory.format_string(payload, session)

    if token.startswith("pv"):
        size = _value_width(token, width)
        payload = session.remote.call("read_value", ea=target, width=size)
        return fmt_memory.format_value(payload, session)

    if token == "ph":
        return _hash(session, target, count or 256, rest)

    if token.startswith("px") and token not in ("px", "pxw", "pxq", "pxd", "pxu"):
        raise UsageError(f"unsupported print modifier '{token[2:]}' (see px?)")

    if token in ("pxd", "pxu"):
        size = _value_width(token, width)
        cells = count or 16
        payload = session.remote.call(
            "read_values", ea=target, count=cells, width=size
        )
        return fmt_memory.format_values(
            payload, session, fmt="signed" if token == "pxd" else "unsigned"
        )

    if token in ("pxw", "pxq"):
        size = 4 if token == "pxw" else 8
        cells = count or (16 if size == 4 else 8)
        payload = session.remote.call("read_values", ea=target, count=cells, width=size)
        return fmt_memory.format_values(payload, session)

    size = count or (session.blocksize if token == "pr" else 64)
    payload = session.remote.call("read_bytes", ea=target, count=size)

    if token == "p8":
        return fmt_memory.format_bytes(payload, session)
    if token == "pr":
        return payload.get("data", b"").decode("utf-8", errors="replace").splitlines()
    if token == "pc":
        raw = bytes(payload.get("data") or b"")
        body = ", ".join(f"0x{byte:02x}" for byte in raw)
        return [f"unsigned char block[{len(raw)}] = {{{body}}};"]
    if token == "px":
        return fmt_memory.format_hexdump(payload, session)
    raise UsageError(f"unsupported print modifier '{token[1:]}' (see p?)")


def _value_width(token: str, bits: Any) -> int:
    suffix = token[-1] if token[-1].isdigit() else ""
    if suffix:
        return int(suffix)
    return 8 if bits == 64 else 4


def _hash(session: Session, target: int, size: int, rest: list[str]) -> list[str]:
    import hashlib

    algorithm = rest[1] if len(rest) > 1 else "sha256"
    try:
        digest = hashlib.new(algorithm)
    except ValueError:
        raise UsageError(f"unknown hash algorithm {algorithm!r}") from None
    payload = session.remote.call("read_bytes", ea=target, count=size)
    digest.update(bytes(payload.get("data") or b""))
    return [f"{algorithm} {digest.hexdigest()}"]
