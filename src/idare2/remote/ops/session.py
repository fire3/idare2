"""Session-level operations: database summary and persistence."""

from __future__ import annotations

from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op


@op("open_summary")
def open_summary(db: Any) -> dict[str, Any]:
    """Compact database description used for the banner and ``iI``."""
    import ida_hexrays
    import ida_ida

    return {
        "path": db.path,
        "module": db.module,
        "architecture": db.architecture,
        "bitness": db.bitness,
        "format": db.format,
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "base_address": helpers.base_address(db),
        "filesize": db.filesize,
        "start_ip": helpers.start_ip(db),
        "minimum_ea": db.minimum_ea,
        "maximum_ea": db.maximum_ea,
        "execution_mode": str(db.execution_mode),
        "compiler": _compiler_name(db),
        "md5": db.md5,
        "sha256": db.sha256,
        "crc32": db.crc32,
        "hexrays": _hexrays_available(ida_hexrays),
        "function_count": _count(db.functions.get_all()),
        "segment_count": _count(db.segments.get_all()),
    }


@op("apply_import_hints", writes=True)
def apply_import_hints(
    db: Any, bits: int | None = None, entry: int | None = None
) -> dict[str, Any]:
    """Apply raw-binary import hints before autoanalysis starts.

    IDA Nexus has no ``bits`` field in ``DatabaseOpenOptions`` (IDA's own
    ``-b`` is a load address).  Changing a segment's addressing mode after the
    loader has guessed the width is supported through ida_segment, but it
    deletes instructions, so idare2 opens hinted databases with analysis paused
    and calls this operation before draining it.
    """
    import ida_auto
    import ida_ida
    import ida_segment

    if not helpers._is_binary(db):
        return {"applied": False, "reason": "not a raw binary"}
    if bits is not None and bits not in (16, 32, 64):
        helpers.fail(protocol.BAD_ARGS, f"bits must be 16, 32 or 64, not {bits}")

    segments = list(db.segments.get_all())
    if bits is not None:
        ida_ida.inf_set_app_bitness(bits)
        # ida_segment wants the encoded addressing mode (0/1/2), while
        # inf_set_app_bitness() wants the actual width (16/32/64).
        addressing = {16: 0, 32: 1, 64: 2}[bits]
        for segment in segments:
            if not ida_segment.set_segment_addressing(int(segment.start_ea), addressing):
                helpers.fail(
                    protocol.IDA_ERROR,
                    f"IDA refused to set segment 0x{int(segment.start_ea):x} to {bits}-bit",
                )

    start = entry if entry is not None else helpers.start_ip(db)
    if start is not None and not ida_ida.inf_set_start_ip(start):
        helpers.fail(protocol.IDA_ERROR, f"IDA refused entry point 0x{start:x}")
    if start is not None:
        # set_segment_addressing() deletes the instructions the loader may have
        # created. Queue the entry point again so the analysis that connect()
        # drains immediately afterwards starts from a code address.
        ida_auto.auto_mark(start, ida_auto.AU_CODE)
    return {"applied": True, "bits": bits, "start_ip": start}


def _hexrays_available(ida_hexrays: Any) -> bool:
    """Whether Hex-Rays is licensed and initialised in this IDA process."""
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


@op("file_hashes")
def file_hashes(db: Any) -> dict[str, Any]:
    """Whole-file hashes (``it``).

    radare2 hashes the opened file from byte zero, so this reads the original
    input rather than trusting whatever the loader recorded.  When the input
    is unavailable (e.g. the database outlived the binary) fall back to the
    loader's md5/sha256; sha1 has no IDA equivalent.  The IDB path is never
    hashed -- that would silently describe the database instead of the input.
    """
    import hashlib

    path = ""
    try:
        import ida_nalt

        path = ida_nalt.get_input_file_path() or ""
    except Exception:
        path = ""

    if path:
        digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    for digest in digests.values():
                        digest.update(chunk)
        except OSError:
            digests.clear()
        if digests:
            return {name: digest.hexdigest() for name, digest in digests.items()}

    def _hex(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.hex()
        return str(value)

    return {
        "md5": _hex(getattr(db, "md5", None)),
        "sha1": None,
        "sha256": _hex(getattr(db, "sha256", None)),
    }


@op("save")
def save(db: Any) -> dict[str, Any]:
    """Flush the database to disk (``w``).

    Saving the database is not an analysis mutation, so it takes no undo point.
    """
    import ida_loader

    ida_loader.save_database(None, 0)
    return {"saved": True}


@op("deep_analyze", writes=True)
def deep_analyze(db: Any) -> dict[str, Any]:
    """Run IDA's deep analysis over the whole database (``aaa``/``aaaa``).

    ``wait_autoanalysis`` only drains work IDA already queued.  ``aaa`` promises
    to look at regions the loader did not recognise, which is exactly what
    ``ida_auto.plan_and_wait`` does for the full address range.
    """
    import ida_auto
    import ida_ida
    import ida_idaapi

    start = int(ida_ida.inf_get_min_ea())
    end = int(ida_ida.inf_get_max_ea())
    if start == int(ida_idaapi.BADADDR) or end == int(ida_idaapi.BADADDR) or end <= start:
        return {"analyzed": False, "start": start, "end": end}
    ok = ida_auto.plan_and_wait(start, end)
    return {"analyzed": bool(ok), "start": start, "end": end}


def _compiler_name(db: Any) -> str | None:
    try:
        info = db.compiler_information
    except Exception:
        return None
    return getattr(info, "name", None) or None


def _count(iterator: Any) -> int:
    total = 0
    for _ in iterator:
        total += 1
    return total
