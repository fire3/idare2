"""The ``w`` write family and ``u``/``U`` undo.

idare2 is read-only unless ``-w`` is passed.  Beyond that, ``e io.cache=true``
buffers patches client-side the way r2 does, and ``wc+`` commits them all under
a single IDA undo point -- so a multi-address edit is one reversible action
rather than N.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from idare2 import assembler
from idare2 import cmd as cmd_module
from idare2.cmd import command
from idare2.errors import UsageError

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

WRITE_DETAIL = [
    ("w", "", "save the database"),
    ("wq", "", "save the database and quit"),
    ("w", " text", "write a string at the current offset"),
    ("wx", " hexpairs", "write bytes"),
    ("wa", " asm", "assemble an instruction and write it"),
    ("wa*", " asm", "print the `wx` command for an assembled instruction"),
    ("wa+", " asm", "assemble, write and seek past the instruction"),
    ("waf", " file", "assemble a source file and write it"),
    ("waF", " file", "assemble a source file, write it and print `wx`"),
    ("w0", " [len]", "write zero bytes"),
    ("wd", " off len", "copy len bytes from off to the current offset"),
    ("wf", " file", "write the contents of a file"),
    ("wi", "[1248][+-]n", "increment or decrement a value in place"),
    ("w6", "[d|e|x] data", "write base64-decoded, base64-encoded or hex-encoded bytes"),
    ("wc", "", "list buffered writes (io.cache)"),
    ("wc+", "", "commit buffered writes as one undoable patch"),
    ("wc-", "", "discard buffered writes"),
    ("u", "", "undo the last database change"),
    ("U", "", "redo the last undone change"),
]


@command("w", usage="[text]", summary="write / save", detail=WRITE_DETAIL, writes=True)
def write(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    suffix = token[1:]
    argument = statement.args.strip()

    # `w` alone saves the IDB (idare2's meaning, documented in DIVERGENCES);
    # `w text` is r2's "write a string".
    if suffix == "q":
        return _save(session, quit_after=True)
    if suffix == "" and not argument:
        return _save(session, quit_after=False)

    cmd_module.require_write(session, f"'{token}'")

    if suffix in ("c", "c+", "c-"):
        return _cache(session, suffix)

    if suffix == "":
        return _patch(session, argument.encode("utf-8"))

    if suffix == "x":
        return _patch(session, _hexpairs(argument, "wx"))

    if suffix == "0":
        length = session.eval(argument) if argument else session.blocksize
        return _patch(session, b"\x00" * max(int(length), 0))

    if suffix.startswith("a"):
        return _assemble(session, argument, modifier=suffix[1:])

    if suffix == "d":
        return _copy(session, argument)

    if suffix == "f":
        return _write_file(session, argument)

    if suffix.startswith("i"):
        return _increment(session, suffix, argument)

    if suffix.startswith("6"):
        return _base64(session, suffix[1:], argument)

    raise UsageError(f"unsupported write modifier '{suffix}' (see w?)")


@command(
    "wa[*]",
    usage=" asm",
    summary="print the wx command for an assembled instruction",
    detail=[("wa*", " asm", "print `wx <hexpairs>` without writing")],
)
def assembly_preview(session: Session, statement: Statement) -> list[str]:
    """``wa*`` -- read-only preview of the bytes ``wa`` would write."""
    return _assemble(session, statement.args, modifier="*")


@command(
    "waF*",
    usage=" file",
    summary="print the wx command for an assembled file",
    detail=[("waF*", " file", "assemble a file and print `wx <hexpairs>` without writing")],
)
def assembly_file_preview(session: Session, statement: Statement) -> list[str]:
    """``waF*`` -- read-only file form of ``wa*``."""
    return _assemble(session, statement.args, modifier="F*")


def _save(session: Session, *, quit_after: bool) -> list[str]:
    cmd_module.require_write(session, "'w'")
    session.remote.call("save")
    if quit_after:
        from idare2.errors import QuitRequested

        raise QuitRequested(0)
    return []


def _hexpairs(text: str, what: str) -> bytes:
    compact = text.replace(" ", "")
    if not compact:
        raise UsageError(f"{what} needs hexpairs")
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise UsageError(f"{what}: not a hexpair string: {text!r}") from None


def _patch(session: Session, data: bytes) -> list[str]:
    """Write now, or buffer when ``e io.cache=true``."""
    if not data:
        return []
    if session.config.get_bool("io.cache"):
        session.write_cache.append((session.seek, data))
        return []
    session.remote.call("patch_bytes", ea=session.seek, data=data.hex())
    session.invalidate_segments()
    return []


def _cache(session: Session, suffix: str) -> list[str]:
    if suffix == "c":
        if not session.write_cache:
            return ["write cache is empty"]
        return [
            f"0x{ea:0{session.addr_width}x} {raw.hex()}" for ea, raw in session.write_cache
        ]
    if suffix == "c-":
        count = len(session.write_cache)
        session.write_cache.clear()
        return [f"-- discarded {count} buffered write(s) --"]
    if not session.write_cache:
        return ["write cache is empty"]
    patches = [{"ea": ea, "data": raw.hex()} for ea, raw in session.write_cache]
    session.remote.call("patch_many", patches=patches)
    count = len(session.write_cache)
    session.write_cache.clear()
    session.invalidate_segments()
    return [f"-- committed {count} buffered write(s) --"]


def _assemble(session: Session, argument: str, *, modifier: str = "") -> list[str]:
    """``wa``: assemble, then patch (or buffer) -- the op itself never writes.

    The modifiers mirror r2's useful subset: ``*`` prints the equivalent ``wx``
    command, ``+`` seeks past the written instruction, and the file forms read
    the assembly from disk.
    """
    allowed = {"", "*", "+", "f", "F", "F*"}
    if modifier not in allowed:
        raise UsageError(f"unsupported wa modifier '{modifier}' (see w?)")

    from_file = modifier.startswith("f") or modifier.startswith("F")
    if from_file:
        if not argument:
            raise UsageError("wa" + modifier + " needs a file name")
        path = Path(_unquote(argument)).expanduser()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise UsageError(f"cannot read {path}: {exc}") from exc
    else:
        text = _unquote(argument)
    if not text.strip():
        raise UsageError("wa needs an instruction")

    start = session.seek
    raw = assembler.assemble(session, text, ea=start)
    emit_only = modifier in ("*", "F*")
    emit_hex = modifier in ("F", "F*")
    if emit_only:
        return [f"wx {raw.hex()}"]

    _patch(session, raw)
    if modifier == "+":
        session.seek_to(start + len(raw))
    if emit_hex:
        return [f"wx {raw.hex()}"]
    if session.config.get_bool("io.cache"):
        return []
    return [f"-- wrote {len(raw)} bytes of {text.strip()} at {session.format_addr(start)} --"]


def _unquote(text: str) -> str:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        return stripped[1:-1]
    return stripped


def _copy(session: Session, argument: str) -> list[str]:
    words = argument.split()
    if len(words) != 2:
        raise UsageError("wd needs a source offset and a length")
    source = session.resolve(words[0])
    length = session.eval(words[1])
    payload = session.remote.call("read_bytes", ea=source, count=length)
    return _patch(session, bytes(payload.get("data") or b""))


def _write_file(session: Session, argument: str) -> list[str]:
    if not argument:
        raise UsageError("wf needs a file name")
    path = Path(argument).expanduser()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    return _patch(session, data)


def _increment(session: Session, suffix: str, argument: str) -> list[str]:
    body = suffix[1:]  # strip the leading "i" in "wi..."
    if not body or body[0] not in "1248":
        raise UsageError("wi needs a width: wi1, wi2, wi4 or wi8 (for example wi1+1)")

    width = int(body[0])
    body = body[1:]
    if not body:
        # r2's `wi1` is a no-op, not an implicit increment.
        return []
    if body[0] not in "+-":
        raise UsageError(f"wi{width} needs '+' or '-', not {body[0]!r}")

    sign = body[0]
    glued = body[1:].strip()
    if glued and argument:
        raise UsageError(f"wi{width}{sign}: give the amount either glued or separated, not both")
    amount = glued or argument
    delta = session.eval(amount) if amount else 1
    if sign == "-":
        delta = -delta

    payload = session.remote.call("read_value", ea=session.seek, width=width)
    value = (int(payload["value"]) + delta) & ((1 << (width * 8)) - 1)
    return _patch(session, value.to_bytes(width, "big" if payload.get("big_endian") else "little"))


def _base64(session: Session, modifier: str, argument: str) -> list[str]:
    import base64
    import binascii

    kind = modifier[:1]
    glued = modifier[1:]
    if not kind:
        raise UsageError("w6 needs d (decode), e (encode) or x (encode hexpairs)")
    if kind not in ("d", "e", "x"):
        raise UsageError(f"unsupported w6 modifier {kind!r} (use d, e or x)")
    if glued and argument:
        raise UsageError(f"w6{kind}: give the data either glued or separated, not both")
    data = argument or glued
    if not data:
        raise UsageError(f"w6{kind} needs data")

    if kind == "d":
        try:
            decoded = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UsageError(f"w6d: bad base64: {exc}") from None
        if not decoded:
            raise UsageError("w6d: base64 payload is empty")
        return _patch(session, decoded)

    raw = _hexpairs(data, "w6x") if kind == "x" else data.encode("utf-8")
    return _patch(session, base64.b64encode(raw))


# --------------------------------------------------------------------------
# undo / redo
# --------------------------------------------------------------------------


@command("u", usage="", summary="undo the last database change", writes=True)
def undo(session: Session, statement: Statement) -> list[str]:
    cmd_module.require_write(session, "'u'")
    payload = session.remote.call("undo")
    session.invalidate_segments()
    if not payload.get("undone"):
        return ["-- nothing to undo --"]
    return []


@command("U", usage="", summary="redo the last undone change", writes=True)
def redo(session: Session, statement: Statement) -> list[str]:
    cmd_module.require_write(session, "'U'")
    payload = session.remote.call("redo")
    session.invalidate_segments()
    if not payload.get("redone"):
        return ["-- nothing to redo --"]
    return []
