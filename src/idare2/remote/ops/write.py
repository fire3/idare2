"""Database mutations backing ``w*`` and ``u``/``U``.

Every operation here is registered with ``writes=True``, so the dispatcher
creates an IDA undo point first and a GUI analyst can revert whatever we did.

Arguments cross the wire as hex strings rather than bytes: the request payload
is JSON (the response has a bytes codec, the request does not).
"""

from __future__ import annotations

import re
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

#: Refuse absurd patches rather than have IDA allocate them.
MAX_PATCH = 1 << 20


def _decode(data: str) -> bytes:
    if not isinstance(data, str):
        helpers.fail(protocol.BAD_ARGS, "patch data must be a hex string")
    text = data.strip().replace(" ", "")
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        helpers.fail(protocol.BAD_ARGS, f"not a hexpair string: {data!r}")
    if not raw:
        helpers.fail(protocol.BAD_ARGS, "empty patch")
    if len(raw) > MAX_PATCH:
        helpers.fail(protocol.BAD_ARGS, f"refusing to patch {len(raw)} bytes at once")
    return raw


@op("patch_bytes", writes=True)
def patch_bytes(db: Any, ea: int, data: str) -> dict[str, Any]:
    """Patch ``data`` at ``ea`` (``wx``)."""
    raw = _decode(data)
    db.bytes.patch_bytes_at(ea, raw)
    return {"ea": ea, "size": len(raw), "data": raw}


@op("patch_many", writes=True)
def patch_many(db: Any, patches: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply several patches under **one** undo point (``wc`` commit).

    The client buffers ``io.cache`` writes so that a multi-address edit is a
    single undoable action rather than N separate ones.
    """
    if not isinstance(patches, list) or not patches:
        helpers.fail(protocol.BAD_ARGS, "no patches to commit")
    applied = 0
    for patch in patches:
        ea = int(patch["ea"])
        raw = _decode(str(patch["data"]))
        db.bytes.patch_bytes_at(ea, raw)
        applied += 1
    return {"patches": applied}


@op("patch_zeros", writes=True)
def patch_zeros(db: Any, ea: int, count: int) -> dict[str, Any]:
    """Zero-fill ``count`` bytes (``w0``)."""
    if count <= 0:
        helpers.fail(protocol.BAD_ARGS, "w0 needs a positive length")
    if count > MAX_PATCH:
        helpers.fail(protocol.BAD_ARGS, f"refusing to write {count} bytes at once")
    db.bytes.patch_bytes_at(ea, b"\x00" * count)
    return {"ea": ea, "size": count}


@op("assemble")
def assemble(db: Any, ea: int, text: str) -> dict[str, Any]:
    """Assemble ``text`` at ``ea`` **without writing** (``wa``).

    Returns the bytes so the client can decide whether to patch immediately or
    buffer them under ``e io.cache=true``.  Keeping assembly read-only is what
    makes the write cache work for ``wa`` at all.

    ``idautils.Assemble()`` resolves the segment selector, instruction pointer,
    and segment bitness before calling the processor module's assembler.  The
    lower-level ``ida_idp.assemble()`` writes into the database and returns a
    boolean, so it cannot support the client-side write cache.

    Not every processor module provides an assembler.  Return a clear error when
    IDA reports that assembly failed instead of writing an empty buffer.
    """
    import idautils

    if not text.strip():
        helpers.fail(protocol.BAD_ARGS, "wa needs an instruction")

    # r2 accepts several instructions in one expression.  The client passes a
    # quoted ``"nop;nop"`` through the command parser; split it here because
    # idautils.Assemble can assemble a list of lines at consecutive addresses.
    lines = [line.strip() for line in re.split(r"[;\n]", text) if line.strip()]
    if not lines:
        helpers.fail(protocol.BAD_ARGS, "wa needs an instruction")
    argument: str | list[str] = lines[0] if len(lines) == 1 else lines
    try:
        ok, value = idautils.Assemble(ea, argument)
    except Exception as exc:  # noqa: BLE001 - translated to a protocol error
        helpers.fail(protocol.IDA_ERROR, f"assembler rejected {text!r}: {exc}")
    if not ok:
        helpers.fail(
            protocol.IDA_ERROR,
            f"IDA could not assemble {text!r}; the processor module may not "
            f"provide an assembler ({value})",
        )
    if isinstance(value, list):
        chunks = []
        for item in value:
            if not isinstance(item, (bytes, bytearray)):
                helpers.fail(
                    protocol.IDA_ERROR,
                    f"assembler returned {type(item).__name__} instead of bytes",
                )
            chunks.append(bytes(item))
        raw = b"".join(chunks)
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        helpers.fail(
            protocol.IDA_ERROR,
            f"assembler returned {type(value).__name__} instead of bytes",
        )
    if not raw:
        helpers.fail(protocol.IDA_ERROR, f"assembler produced nothing for {text!r}")
    if len(raw) > MAX_PATCH:
        helpers.fail(protocol.BAD_ARGS, f"refusing to assemble {len(raw)} bytes at once")
    return {"ea": ea, "size": len(raw), "data": raw}


@op("undo")
def undo(db: Any) -> dict[str, Any]:
    """Revert the last database change (``u``)."""
    import ida_undo

    done = ida_undo.perform_undo()
    return {"undone": bool(done)}


@op("redo")
def redo(db: Any) -> dict[str, Any]:
    """Reapply the last undone change (``U``)."""
    import ida_undo

    done = ida_undo.perform_redo()
    return {"redone": bool(done)}


@op("original_bytes")
def original_bytes(db: Any, ea: int, count: int) -> dict[str, Any]:
    """The file's bytes, ignoring patches (``wo`` preview, ``wcr``)."""
    raw = db.bytes.get_original_bytes_at(ea, count)
    if raw is None:
        helpers.fail(protocol.BAD_ADDRESS, f"cannot read {count} original bytes at 0x{ea:x}")
    return {"ea": ea, "data": bytes(raw)}
