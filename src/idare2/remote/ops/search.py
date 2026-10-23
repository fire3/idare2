"""Search operations backing the ``/`` command family."""

from __future__ import annotations

import re
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

#: How many hits one call collects before stopping.  r2 keeps searching until
#: interrupted; we return a page and let the client resume from the last hit.
DEFAULT_LIMIT = 1000


def _bounds(db: Any, start: int | None, end: int | None) -> tuple[int, int]:
    minimum = int(db.minimum_ea or 0)
    maximum = int(db.maximum_ea or 0)
    first = start if start is not None else minimum
    last = end if end is not None else maximum
    if last <= first:
        helpers.fail(
            protocol.BAD_ARGS, f"empty search range 0x{first:x}..0x{last:x}"
        )
    return first, last


def _collect(
    finder: Any, start: int, end: int, limit: int, *, inclusive: bool
) -> list[int]:
    """Repeatedly apply a ``find_*_between`` until it stops finding hits."""
    hits: list[int] = []
    cursor = start
    while len(hits) < limit and cursor < end:
        hit = finder(cursor, end)
        if hit is None:
            break
        hit = int(hit)
        if hit < 0:
            break
        hits.append(hit)
        cursor = hit + 1 if not inclusive else hit + 1
    return hits


def _wide_variants(text: str) -> list[str]:
    """Case variants of ``text`` for ``/wi`` (at most 8 ASCII letters)."""
    import itertools

    choices: list[tuple[str, ...]] = []
    combinations = 1
    for char in text:
        if char.isascii() and char.isalpha():
            choices.append((char.lower(), char.upper()))
            combinations *= 2
        else:
            choices.append((char,))
    if combinations > 256:
        helpers.fail(
            protocol.BAD_ARGS,
            "wide case-insensitive search supports at most 8 ASCII letters",
        )
    return ["".join(variant) for variant in itertools.product(*choices)]


#: Refuse pattern searches over huge ranges rather than buffering everything.
PATTERN_MAX_BYTES = 1 << 26


@op("search_patterns")
def search_patterns(
    db: Any, size: int, start: int | None = None, end: int | None = None,
    limit: int = 64,
) -> dict[str, Any]:
    """Repeated fixed-size byte patterns (``/p``).

    Mirrors r2's algorithm: starting at the range start, take ``size`` bytes and
    look for them later in the buffer; a pattern is reported when found at
    least twice.  The cursor then advances by ``size`` when something was
    found (so a repeated record is skipped as a unit) or by one byte
    otherwise.  Only the first ``limit`` distinct patterns are returned.
    """
    first, last = _bounds(db, start, end)
    if size < 2:
        helpers.fail(protocol.BAD_ARGS, "pattern size must be greater than 1")
    if last - first > PATTERN_MAX_BYTES:
        helpers.fail(
            protocol.BAD_ARGS,
            f"pattern search range is larger than {PATTERN_MAX_BYTES} bytes",
        )
    raw = db.bytes.get_bytes_at(first, last - first)
    if raw is None:
        helpers.fail(protocol.BAD_ADDRESS, f"cannot read 0x{first:x}..0x{last:x}")
    data = bytes(raw)
    if len(data) < size:
        return {"start": first, "end": last, "size": size, "groups": []}

    groups: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    cursor = 0
    while cursor + size <= len(data) and len(groups) < limit:
        needle = data[cursor : cursor + size]
        if needle in seen:
            cursor += 1
            continue
        hits = [first + cursor]
        position = cursor + size
        while position + size <= len(data):
            index = data.find(needle, position)
            if index < 0:
                break
            hits.append(first + index)
            position = index + 1
        if len(hits) > 1:
            seen.add(needle)
            groups.append({"bytes": needle.hex(), "hits": hits})
            cursor += size
        else:
            cursor += 1
    return {"start": first, "end": last, "size": size, "groups": groups}


@op("search")
def search(
    db: Any,
    pattern: str,
    kind: str = "bytes",
    start: int | None = None,
    end: int | None = None,
    limit: int = DEFAULT_LIMIT,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """Search the database.

    ``kind`` is one of ``bytes`` (hexpairs), ``text``, ``immediate`` (a number),
    ``regex`` (over the string table), ``wide`` (UTF-16LE) or ``wide-i``
    (UTF-16LE, ASCII letters case-insensitive).  Hits come back as addresses;
    the client decides how to render them.
    """
    first, last = _bounds(db, start, end)

    if kind in ("wide", "wide-i"):
        variants = _wide_variants(pattern) if kind == "wide-i" else [pattern]
        needles = [variant.encode("utf-16-le") for variant in variants]
        if not any(needles):
            helpers.fail(protocol.BAD_ARGS, "empty search pattern")

        def wide_finder(begin: int, finish: int) -> int | None:
            best: int | None = None
            for needle in needles:
                hit = db.bytes.find_bytes_between(needle, begin, finish)
                if hit is not None and int(hit) >= 0:
                    hit = int(hit)
                    if best is None or hit < best:
                        best = hit
            return best

        hits = _collect(wide_finder, first, last, limit, inclusive=True)
        return {
            "kind": kind,
            "pattern": pattern,
            "match": len(pattern.encode("utf-16-le")),
            "hits": hits,
            "start": first,
            "end": last,
        }

    if kind == "bytes":
        try:
            needle = bytes.fromhex(pattern)
        except ValueError:
            helpers.fail(protocol.BAD_ARGS, f"not a hexpair string: {pattern!r}")
        if not needle:
            helpers.fail(protocol.BAD_ARGS, "empty search pattern")
        hits = _collect(
            lambda a, b: db.bytes.find_bytes_between(needle, a, b),
            first,
            last,
            limit,
            inclusive=True,
        )
        return {"kind": kind, "pattern": pattern, "hits": hits, "start": first, "end": last}

    if kind == "text":
        # NOT `db.bytes.find_text_between`: IDA's text search scans the text
        # *displayed in the listing* (mnemonics, names, comments) and reports
        # where that text is rendered.  r2's `/ text` searches raw memory for
        # the byte sequence, so encode and do a byte search.
        needle = pattern.encode("utf-8")
        if not needle:
            helpers.fail(protocol.BAD_ARGS, "empty search pattern")
        def finder(start: int, end: int) -> int | None:
            if case_sensitive:
                return db.bytes.find_bytes_between(needle, start, end)
            return _find_raw(needle, start, end, case_insensitive=True)

        hits = _collect(finder, first, last, limit, inclusive=True)
        return {"kind": kind, "pattern": pattern, "hits": hits, "start": first, "end": last}

    if kind == "immediate":
        try:
            value = int(pattern, 0)
        except ValueError:
            helpers.fail(protocol.BAD_ARGS, f"not a number: {pattern!r}")
        hits = _collect(
            lambda a, b: db.bytes.find_immediate_between(value, a, b),
            first,
            last,
            limit,
            inclusive=True,
        )
        return {"kind": kind, "value": value, "hits": hits, "start": first, "end": last}

    if kind == "regex":
        try:
            rx = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            helpers.fail(protocol.BAD_ARGS, f"bad regex: {exc}")
        hits = []
        for item in db.strings.get_all():
            if len(hits) >= limit:
                break
            contents = item.contents
            if not contents:
                continue
            text = contents.decode("utf-8", errors="replace")
            match = rx.search(text)
            if match is None:
                continue
            # r2 reports the address of the match inside the string, not of the
            # string's first byte.
            hits.append(int(item.address) + len(text[: match.start()].encode("utf-8")))
        return {"kind": kind, "pattern": pattern, "hits": hits, "start": first, "end": last}

    helpers.fail(
        protocol.BAD_ARGS, f"kind must be bytes, text, immediate or regex, not {kind!r}"
    )
    raise AssertionError("unreachable")  # pragma: no cover


def _find_raw(needle: bytes, start: int, end: int, *, case_insensitive: bool) -> int | None:
    """Raw byte search, optionally case-insensitive.

    The ``BIN_SEARCH_*`` flags live in ``ida_bytes`` (not ``ida_search``, which
    is where the text-search flags are).
    """
    import ida_bytes
    from ida_idaapi import BADADDR

    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    if case_insensitive:
        flags |= ida_bytes.BIN_SEARCH_NOCASE
    hit = ida_bytes.find_bytes(needle, start, range_end=end, flags=flags)
    return None if hit is None or hit == BADADDR else int(hit)


@op("search_ranges")
def search_ranges(db: Any) -> list[dict[str, Any]]:
    """Segments usable as ``search.in=io.maps`` (``e search.in`` scope)."""
    out = []
    for segment in db.segments.get_all():
        out.append(
            {
                "start": int(segment.start_ea),
                "end": int(segment.end_ea),
                "name": db.segments.get_name(segment) or "",
            }
        )
    return out
