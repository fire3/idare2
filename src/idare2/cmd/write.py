"""The ``w`` write family and ``u``/``U`` undo.

idare2 is read-only unless ``-w`` is passed.  Beyond that, ``e io.cache=true``
buffers patches client-side the way r2 does, and ``wc+`` commits them all under
a single IDA undo point -- so a multi-address edit is one reversible action
rather than N.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

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
    ("w0", " [len]", "write zero bytes"),
    ("wd", " off len", "copy len bytes from off to the current offset"),
    ("wf", " file", "write the contents of a file"),
    ("wi", "[1248][+-]n", "increment or decrement a value in place"),
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

    if suffix == "a":
        return _assemble(session, argument)

    if suffix == "d":
        return _copy(session, argument)

    if suffix == "f":
        return _write_file(session, argument)

    if suffix.startswith("i"):
        return _increment(session, suffix, argument)

    if suffix == "6":
        return _base64(session, argument)

    raise UsageError(f"unsupported write modifier '{suffix}' (see w?)")


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


def _assemble(session: Session, argument: str) -> list[str]:
    """``wa``: assemble, then patch (or buffer) -- the op itself never writes."""
    text = _unquote(argument)
    if not text:
        raise UsageError("wa needs an instruction")
    payload = session.remote.call("assemble", ea=session.seek, text=text)
    raw = bytes(payload.get("data") or b"")
    if not raw:
        raise UsageError(f"assembler produced nothing for {text!r}")
    _patch(session, raw)
    if session.config.get_bool("io.cache"):
        return []
    return [f"-- wrote {len(raw)} bytes of {text} at {session.format_addr(session.seek)} --"]


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
    width = 1
    for candidate in (8, 4, 2, 1):
        if suffix.startswith(f"i{candidate}"):
            width = candidate
            break
    op = suffix[len(f"i{width}") :]
    delta = session.eval(argument) if argument else 1
    if op == "-":
        delta = -delta
    elif op not in ("", "+"):
        raise UsageError(f"unsupported increment form 'w{suffix}'")

    payload = session.remote.call("read_value", ea=session.seek, width=width)
    value = (int(payload["value"]) + delta) & ((1 << (width * 8)) - 1)
    return _patch(session, value.to_bytes(width, "big" if payload.get("big_endian") else "little"))


def _base64(session: Session, argument: str) -> list[str]:
    import base64

    if not argument:
        raise UsageError("w6 needs data")
    if argument.startswith("d"):
        try:
            data = base64.b64decode(argument[1:])
        except Exception as exc:  # noqa: BLE001
            raise UsageError(f"w6d: bad base64: {exc}") from None
        return _patch(session, data)
    if argument.startswith("e"):
        return _patch(session, argument[1:].encode("utf-8"))
    return _patch(session, base64.b64decode(argument))


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
