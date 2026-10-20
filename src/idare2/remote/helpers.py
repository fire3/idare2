"""Shared helpers for the IDA-side handlers.

The pure helpers (``paginate``, ``name_filter``, ``page_meta``) import no
``ida_*`` so they can be unit-tested from the CLI process.  Everything that
touches IDA imports lazily inside the function.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any, TypeVar

from idare2 import protocol
from idare2.errors import Idare2Error

T = TypeVar("T")

_SENTINEL = object()

#: r2's default page size for listings.
LIST_DEFAULT = 200
#: r2's default instruction count for ``pd``.
DISASM_DEFAULT = 32
#: Hard cap for ``pdf`` so a huge function cannot flood the terminal.
FUNC_CAP = 4096
#: r2's default line count for ``pdc``.
DECOMPILE_DEFAULT = 120


class RemoteError(Idare2Error):
    """An error raised inside a handler with an explicit protocol code."""

    def __init__(self, code: str, message: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data or {}


def fail(code: str, message: str, data: dict[str, Any] | None = None) -> None:
    """Raise a handler error that the dispatcher turns into an envelope."""
    raise RemoteError(code, message, data)


# -- pagination ------------------------------------------------------------


def paginate(
    iterable: Iterable[T], offset: int = 0, count: int | None = None
) -> tuple[list[T], int | None]:
    """Apply offset/count *while* walking an iterator (never build-then-cap).

    ``count=None`` means "the caller's default"; ``count < 0`` means "no limit"
    -- used by the ``@@`` iterators and by the flag-store seed, which genuinely
    want every row.

    Returns ``(items, next_offset)``; ``next_offset`` is ``None`` once the source
    is exhausted within the page, otherwise the offset to resume from.
    """
    offset = int(offset or 0)
    it = iter(iterable)
    for _ in range(offset):
        if next(it, _SENTINEL) is _SENTINEL:
            return [], None
    if count is None or count < 0:
        return list(it), None
    items: list[T] = []
    for _ in range(int(count)):
        value = next(it, _SENTINEL)
        if value is _SENTINEL:
            return items, None
        items.append(value)
    has_more = next(it, _SENTINEL) is not _SENTINEL
    return items, (offset + len(items)) if has_more else None


def page_meta(items: list[Any], next_offset: int | None, total: int | None = None) -> dict | None:
    """Envelope meta for a paginated result, or ``None`` if nothing was cut."""
    if next_offset is None and total is None:
        return None
    meta: dict[str, Any] = {"shown": len(items)}
    if next_offset is not None:
        meta["truncated"] = True
        meta["next_offset"] = next_offset
    if total is not None:
        meta["total"] = total
    return meta


def paged(
    make_iter: Callable[[], Iterator[T]],
    offset: int,
    count: int | None,
) -> tuple[list[T], dict | None]:
    """Paginate a listing.

    ``count=None`` means **unlimited**, matching radare2: ``afl`` prints every
    function, and capping it would silently break ``afl~main`` on a database
    with more functions than the page size.  ``-n`` opts into a limit.
    """
    items, next_offset = paginate(make_iter(), offset, count)
    return items, page_meta(items, next_offset)


# -- filtering -------------------------------------------------------------


def name_filter(pattern: str | None) -> Callable[[str | None], bool]:
    """Predicate over a name.

    ``/re/`` is a regex, ``*``/``?`` is a glob, anything else is a
    case-insensitive substring.  ``None`` matches everything.
    """
    if pattern is None:
        return lambda name: True
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        rx = re.compile(pattern[1:-1], re.IGNORECASE)
        return lambda name: rx.search(name or "") is not None
    if "*" in pattern or "?" in pattern:
        lowered = pattern.lower()
        return lambda name: fnmatch.fnmatch((name or "").lower(), lowered)
    needle = pattern.lower()
    return lambda name: needle in (name or "").lower()


# -- IDA-dependent helpers -------------------------------------------------


def require_func(db: Any, ea: int) -> Any:
    """The function containing ``ea``, or a ``NOT_FUNC`` error."""
    func = db.functions.get_at(ea)
    if func is None:
        fail(protocol.NOT_FUNC, f"no function at 0x{ea:x}")
    return func


def require_hexrays() -> None:
    """Fail early when the Hex-Rays decompiler is unavailable."""
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        fail(
            protocol.NO_HEXRAYS,
            "the Hex-Rays decompiler is not available (missing or unlicensed)",
        )


def func_name(db: Any, ea: int) -> str | None:
    """Name of the function containing ``ea``, or ``None``."""
    func = db.functions.get_at(ea)
    if func is None:
        return None
    return db.functions.get_name(func)


def symbol_at(db: Any, ea: int) -> str | None:
    """The name at ``ea`` itself, if any."""
    try:
        return db.names.get_at(ea)
    except Exception:
        return None


def nearest_symbol(db: Any, ea: int) -> tuple[str | None, int]:
    """Nearest name at or before ``ea`` plus its delta."""
    import idautils

    best_name: str | None = None
    best_ea = 0
    for address, name in idautils.Names():
        if address > ea:
            break
        if address >= best_ea:
            best_ea, best_name = address, name
    if best_name is None:
        return None, 0
    return best_name, ea - best_ea


def read_bytes(db: Any, ea: int, count: int) -> bytes:
    """Read ``count`` bytes, failing with ``BAD_ADDRESS`` on a short read."""
    if count < 0:
        fail(protocol.BAD_ARGS, "count must not be negative")
    data = db.bytes.get_bytes_at(ea, count)
    if data is None:
        fail(protocol.BAD_ADDRESS, f"cannot read 0x{count:x} bytes at 0x{ea:x}")
    return bytes(data)


def flag_value(flags: Any) -> int:
    """Numeric value of an ida-domain flag set.

    ida-domain models flag sets as ``enum.Flag`` -- *not* ``IntFlag`` -- and
    Python's ``Flag`` deliberately has no ``__int__``, so ``int(flags)`` raises
    ``TypeError``.  Reading ``.value`` works for ``Flag``, ``IntFlag`` and plain
    ints alike, which makes this the one place that conversion happens: without
    it ``afi``/``sf``/``sF`` crash and ``Cd.``'s ``flags`` silently reads 0.
    """
    if flags is None:
        return 0
    value = getattr(flags, "value", flags)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def item_flags(db: Any, ea: int) -> int:
    try:
        return flag_value(db.bytes.get_flags_at(ea))
    except Exception:
        return 0


def clean_disasm(text: str | None) -> str:
    """Normalise one IDA disassembly line for r2-style rendering.

    IDA pads the mnemonic column (``MOV             R11, #0``) and appends
    ``; comment`` text.  Only the *first* whitespace run is collapsed, so
    spacing inside string literals survives.
    """
    if not text:
        return ""
    parts = text.split(None, 1)
    if not parts:
        return ""
    return parts[0] if len(parts) == 1 else f"{parts[0]} {parts[1]}"


def strip_comment(text: str, comment: str) -> str:
    """Remove the ``; comment`` IDA appends, because we render that column.

    Only the exact suffix is removed, so other IDA annotations such as
    ``; "string"`` stay in the instruction text.
    """
    if not comment or not text:
        return text
    marker = f"; {comment}"
    if text.endswith(marker):
        return text[: -len(marker)].rstrip()
    index = text.find(marker)
    if index >= 0:
        return text[:index].rstrip()
    return text
