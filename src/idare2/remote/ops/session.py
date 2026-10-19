"""Session-level operations: database summary and persistence."""

from __future__ import annotations

from typing import Any

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
        "base_address": db.base_address,
        "filesize": db.filesize,
        "start_ip": db.start_ip,
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


def _hexrays_available(ida_hexrays: Any) -> bool:
    """Whether Hex-Rays is licensed and initialised in this IDA process."""
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


@op("save")
def save(db: Any) -> dict[str, Any]:
    """Flush the database to disk (``w``).

    Saving the database is not an analysis mutation, so it takes no undo point.
    """
    import ida_loader

    ida_loader.save_database(None, 0)
    return {"saved": True}


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
