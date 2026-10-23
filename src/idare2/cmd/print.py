"""The ``p`` print family: disassembly, memory, values, strings."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from idare2 import assembler
from idare2 import pf as pf_format
from idare2.cmd import _NUMERIC, command, numeric_args, with_more
from idare2.errors import Idare2Error, UsageError
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

ASSEMBLY_DETAIL = [
    ("pa", "[asm]", "assemble an instruction and print its hexpairs"),
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
    ("pcj", "[n]", "C array of bytes as JSON"),
    ("pc*", "[n]", "C array of bytes as r2 `wx` commands"),
    ("pcq", "[n]", "quiet C array of bytes"),
    ("pcp", "[n]", "C array of bytes as a Python struct.pack"),
    ("pcP", "[n]", "C array of bytes as a Python struct.pack"),
    ("ps", "[n]", "string at the current offset"),
    ("psw", "[n]", "wide (UTF-16) string"),
    ("pv", "[n]", "value of the given size (1, 2, 4, 8)"),
    ("ph", "[algo] [n]", "hash of a block; bare `ph` lists the algorithms"),
]

PF_DETAIL = [
    ("pf", "<fmt> [name ...]", "print formatted data (pf.<name> applies a saved format)"),
    ("pfj", "<fmt> [name ...]", "print formatted data as JSON"),
    ("pfs", "<fmt>", "size in bytes consumed by a pf format"),
    ("pf.", "[name]", "list or apply named pf formats"),
    ("pf.<name>", "[fmt [name ...]]", "define or apply a named pf format"),
]


def _json_mode(token: str) -> bool:
    return token.endswith("j")


@command(
    "p[dDiI]",
    usage="[n]",
    summary="print disassembly",
    detail=DISASM_DETAIL,
    json_suffix=True,
)
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


@command(
    "pa",
    usage="[asm]",
    summary="assemble an instruction",
    detail=ASSEMBLY_DETAIL,
)
def print_assembly(session: Session, statement: Statement) -> list[str]:
    """``pa`` -- the reverse of ``pd``, matching r2's hexpair output."""
    if statement.cmd != "pa":
        raise UsageError(f"unsupported print modifier '{statement.cmd[1:]}' (see p?)")
    return [assembler.assemble(session, statement.args).hex()]


@command("p[x8hruvscw]", usage="[n]", summary="print memory and values", detail=MEMORY_DETAIL)
def print_memory(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    rest, count, _offset = numeric_args(session, statement)

    if token == "ph":
        # r2 gives `ph`'s positional slot to the *length*, never an address, so
        # this has to run before `rest[0]` is resolved as one -- otherwise
        # `ph md5` tries to seek to a symbol called "md5".  `@ addr` still
        # works because the temporary seek wraps the whole statement.
        return _hash(session, session.seek, rest, count)

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
        lines = _c_array(raw)
        return lines
    if token == "px":
        return fmt_memory.format_hexdump(payload, session)
    raise UsageError(f"unsupported print modifier '{token[1:]}' (see p?)")


X_DETAIL = [
    ("x", "[n]", "hexdump N bytes (same as px)"),
    ("x8", "[n]", "8-bit hexpair dump (same as px)"),
    ("xw", "[n]", "32-bit word dump (same as pxw)"),
    ("xq", "[n]", "64-bit word dump (same as pxq)"),
    ("xj", "[n]", "byte values as a JSON array"),
]

_X_ALIASES = {"x": "px", "x8": "px", "xw": "pxw", "xq": "pxq"}


@command("x", usage="[n]", summary="print memory (alias of px)", detail=X_DETAIL, json_suffix=True)
def print_x(session: Session, statement: Statement) -> list[str]:
    """The r2 ``x`` family: ``x``/``x8`` = ``px``, ``xw``/``xq`` = ``pxw``/``pxq``.

    ``xh`` and the gdb-style ``x/`` forms are not implemented; they fail with
    the usual usage error instead of printing a different dump.
    """
    token = statement.cmd
    if token == "xj":
        rest, count, _offset = numeric_args(session, statement)
        target = session.resolve(rest[0]) if rest else session.seek
        size = count or 64
        payload = session.remote.call("read_bytes", ea=target, count=size)
        return [to_json(list(payload.get("data") or b""))]

    alias = _X_ALIASES.get(token)
    if alias is None:
        raise UsageError(f"unsupported print modifier '{token[1:]}' (see px?)")
    return print_memory(session, replace(statement, cmd=alias))


P6_DETAIL = [
    ("p6e", "[len]", "base64-encode the block at the seek"),
    ("p6es", " text", "base64-encode the given text"),
    ("p6ez", "", "base64-encode the zero-terminated string at the seek"),
    ("p6d", "[len]", "base64-decode the block at the seek"),
    ("p6ds", " text", "base64-decode the given text"),
    ("p6dz", "", "base64-decode the zero-terminated string at the seek"),
]


@command("p6", usage="[de][sz] [arg]", summary="base64 encode/decode", detail=P6_DETAIL)
def print_base64(session: Session, statement: Statement) -> list[str]:
    """``p6e``/``p6d`` -- r2's base64 helpers.

    ``s`` takes the data from the argument, ``z`` stops at a NUL byte in the
    block; otherwise ``[len]`` bytes are read at the seek (blocksize default).
    """
    import base64 as b64

    token = statement.cmd[2:]
    if not token:
        raise UsageError("p6 needs e (encode) or d (decode); see p6?")
    action, flags = token[0], token[1:]
    if action not in ("e", "d") or flags not in ("", "s", "z"):
        raise UsageError(f"unsupported print modifier 'p6{token}' (see p6?)")

    rest, count, _offset = numeric_args(session, statement)
    zero_terminated = flags == "z"
    from_argument = flags == "s"

    if from_argument:
        text = " ".join(rest)
        if not text:
            raise UsageError(f"p6{token} needs an argument")
        data = text.encode("utf-8")
    else:
        length = count or session.blocksize
        payload = session.remote.call("read_bytes", ea=session.seek, count=length)
        data = bytes(payload.get("data") or b"")
        if zero_terminated:
            data = data.split(b"\0", 1)[0]

    if action == "e":
        return [b64.b64encode(data).decode("ascii")]

    try:
        decoded = b64.b64decode(data, validate=True)
    except Exception:
        raise UsageError("p6d: invalid base64 stream") from None
    return [decoded.decode("latin-1")]


@command("pc[*jqPp]", usage="[n]", summary="C array formats", detail=MEMORY_DETAIL)
def print_c_array(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    rest, count, _offset = numeric_args(session, statement)
    target = session.resolve(rest[0]) if rest else session.seek
    payload = session.remote.call(
        "read_bytes", ea=target, count=count or session.blocksize
    )
    raw = bytes(payload.get("data") or b"")
    if not raw:
        return []
    if token == "pcj":
        return [json.dumps(list(raw), separators=(",", ":"))]
    if token == "pc*":
        lines = [
            f"wx+{raw[offset:offset + 32].hex()};"
            for offset in range(0, len(raw), 32)
        ]
        lines.append(f"s-{len(raw)}")
        return lines
    if token == "pcq":
        return list(_c_array(raw)[2:-1])
    if token in ("pcp", "pcP"):
        return _python_pack(raw)
    raise UsageError(f"unsupported print modifier '{token[1:]}' (see p?)")


def _c_array(raw: bytes) -> list[str]:
    """r2's ``pc`` layout: 10 bytes per row, trailing commas inside the block."""
    if not raw:
        return []
    lines = [f"#define _BUFFER_SIZE {len(raw)}", "const uint8_t buffer[_BUFFER_SIZE] = {"]
    for offset in range(0, len(raw), 10):
        chunk = raw[offset : offset + 10]
        body = ", ".join(f"0x{byte:02x}" for byte in chunk)
        if offset + 10 < len(raw):
            body += ","
        lines.append(f"  {body}")
    lines.append("};")
    return lines


def _python_pack(raw: bytes) -> list[str]:
    """r2's ``pcp``/``pcP`` layout: 11 bytes per row."""
    lines = ["import struct", f'buf = struct.pack ("{len(raw)}B", *[']
    for offset in range(0, len(raw), 11):
        chunk = raw[offset : offset + 11]
        body = ",".join(f"0x{byte:02x}" for byte in chunk)
        if offset + 11 < len(raw):
            body += ","
        else:
            body += "])"
        lines.append(body)
    return lines


def _value_width(token: str, bits: Any) -> int:
    suffix = token[-1] if token[-1].isdigit() else ""
    if suffix:
        return int(suffix)
    return 8 if bits == 64 else 4


#: What bare ``ph`` advertises.  Deliberately the CPython-guaranteed set rather
#: than r2's full list (crc32, xxhash, ...): idare2 delegates to ``hashlib``,
#: and promising a hash it cannot compute would be worse than a short list.
_HASH_ALGORITHMS = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
)


def _hash(
    session: Session, ea: int, rest: list[str], count: int | None
) -> list[str]:
    """``ph [algo] [n]`` over the block at the seek.

    Matches r2 where it matters: the digest is **bare hex** (no algorithm
    prefix), the default length is the block size, and a bare ``ph`` prints the
    algorithm list.  An unknown algorithm is an explicit error rather than r2's
    empty output, which reads as "no data here".
    """
    import hashlib

    words = list(rest)
    if not words and count is None:
        return [" ".join(_HASH_ALGORITHMS)]

    algorithm = "sha256"
    if words and not _NUMERIC.match(words[0]):
        algorithm = words.pop(0)
    size = count
    if words:
        size = session.eval(words.pop(0))
    if words:
        raise UsageError(f"ph: unexpected argument {words[0]!r} (see ph?)")

    try:
        digest = hashlib.new(algorithm)
    except ValueError:
        known = " ".join(_HASH_ALGORITHMS)
        raise UsageError(
            f"unknown hash algorithm {algorithm!r}; algorithms: {known}"
        ) from None

    payload = session.remote.call(
        "read_bytes", ea=ea, count=session.blocksize if size is None else size
    )
    digest.update(bytes(payload.get("data") or b""))
    return [digest.hexdigest()]


@command(
    "pf",
    usage="<fmt> [name ...]",
    summary="print formatted data",
    detail=PF_DETAIL,
    query_suffix=True,
)
def print_format(session: Session, statement: Statement) -> list[str]:
    """``pf`` -- decode fields according to an r2 format string.

    Definitions live in the session, like r2's: ``pf.foo xxd a b`` defines a
    format.  ``pf.foo``, ``pfj.foo`` and ``pfs.foo`` then use it.
    """
    token = statement.cmd
    mode, dotted, named = _pf_mode(token)
    if mode is None:
        raise UsageError(f"unsupported print modifier '{token[2:]}' (see pf?)")

    if statement.help:
        words = statement.argv
        if not words:
            raise UsageError("pf? needs a format name")
        return _pf_show(session, words[0])

    words = statement.argv
    if dotted:
        if named is None:
            if not words:
                return _pf_list(session)
            named, words = words[0], words[1:]
        if words:
            return _pf_define(session, named, words)
        definition = session.pf_formats.get(named)
        if definition is None:
            raise UsageError(f"pf: no named format {named!r}")
        text, names = definition
        fmt = pf_format.parse_format(
            text,
            pointer_size=_pointer_size(session),
            names=names,
            repeat=statement.repeat,
            union=statement.repeat == 0,
        )
    else:
        if not words:
            return []
        fmt = pf_format.parse_format(
            words[0],
            pointer_size=_pointer_size(session),
            names=words[1:],
            repeat=statement.repeat,
            union=statement.repeat == 0,
        )

    if mode == "s":
        return [str(pf_format.format_size(fmt, include_repeat=False))]
    return _pf_render(session, statement, fmt, json_mode=mode == "j")


def _pf_mode(token: str) -> tuple[str | None, bool, str | None]:
    """Return ``(mode, dotted, inline_name)`` for the pf token variants."""
    if token == "pf":
        return "", False, None
    if token == "pfj":
        return "j", False, None
    if token == "pfs":
        return "s", False, None
    if token.startswith("pf."):
        rest = token[3:]
        return "", True, rest or None
    if token.startswith("pfj."):
        return "j", True, token[4:] or None
    if token.startswith("pfs."):
        return "s", True, token[4:] or None
    return None, False, None


def _pf_define(session: Session, name: str, words: list[str]) -> list[str]:
    if not words:
        raise UsageError(f"pf.{name} needs a format string")
    text, names = words[0], tuple(words[1:])
    pf_format.parse_format(
        text, pointer_size=_pointer_size(session), names=names
    )
    session.pf_formats[name] = (text, names)
    return []


def _pf_list(session: Session) -> list[str]:
    lines = []
    for name in sorted(session.pf_formats):
        text, names = session.pf_formats[name]
        suffix = (" " + " ".join(names)) if names else ""
        lines.append(f"pf.{name} {text}{suffix}")
    return lines


def _pf_show(session: Session, name: str) -> list[str]:
    definition = session.pf_formats.get(name)
    if definition is None:
        raise UsageError(f"pf: no named format {name!r}")
    text, names = definition
    suffix = (" " + " ".join(names)) if names else ""
    return [f"pf.{name} {text}{suffix}"]


def _pf_render(
    session: Session,
    statement: Statement,
    fmt: pf_format.Format,
    *,
    json_mode: bool,
) -> list[str]:
    count = max(pf_format.format_size(fmt) + 64, session.blocksize)
    payload = session.remote.call("read_bytes", ea=session.seek, count=count)
    data = bytes(payload.get("data") or b"")

    def read_string(address: int, size: int) -> str | None:
        try:
            result = session.remote.call(
                "read_string", ea=address, max_length=size, encoding="auto"
            )
        except Idare2Error:
            return None
        return result.get("text")

    rendered = pf_format.render(
        data,
        session.seek,
        fmt,
        endian=str(session.info.get("endian") or "little"),
        format_addr=session.format_addr,
        read_string=read_string,
    )
    if json_mode:
        return [to_json(rendered.rows)]
    return rendered.lines


def _pointer_size(session: Session) -> int:
    bits = int(session.info.get("bits") or session.info.get("bitness") or 32)
    return 8 if bits == 64 else 4
