"""The ``/`` search family.

Output format measured against r2 6.2.5::

    0x00008000 hit0_0 7f454c46
    0x0000d39c hit1_0 "dosFenceListGethttpd_msg_handleform"

The ``hit<N>_<i>`` label is a flag name r2 creates for each hit -- ``N`` counts
search commands in the session, ``i`` counts hits within one search.  idare2
creates them as **session-local** flags: writing them into the IDB would let a
read-only tool mutate the database.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command
from idare2.errors import UsageError
from idare2.fmt import to_json
from idare2.session import SearchState

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

SEARCH_DETAIL = [
    ("/", " text", "search for text"),
    ("/x", " hexpairs", "search for bytes"),
    ("/v", " value", "search for an immediate value"),
    ("/r", " regex", "search the string table with a regex"),
    ("/w", " text", "search for a UTF-16LE wide string"),
    ("/wi", " text", "search for a wide string, ignoring case"),
    ("/a", " asm", "assemble an instruction and search for its bytes"),
    ("//", "", "repeat the previous search"),
    ("/+", "", "continue the previous search after its last hit"),
    ("/j", " ...", "the same searches as JSON (append j to the kind)"),
]

#: Characters of context r2 shows around a text hit.
CONTEXT = 16

_KINDS = {
    "": "text",
    "x": "bytes",
    "v": "immediate",
    "r": "regex",
    "w": "wide",
    "wi": "wide",
    "a": "bytes",
}

#: Extra characters that are fixed by the kind itself (``/wi`` ignores case).
_KIND_FIXED = {"wi": "-i"}


@command("/", usage="[xvr] [pattern]", summary="search", detail=SEARCH_DETAIL, json_suffix=True)
def search(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd

    if token in ("//", "/+", "/-"):
        return _repeat(session, token)

    suffix = token[1:]
    as_json = suffix.endswith("j")
    kind_token = suffix[:-1] if as_json else suffix
    if kind_token not in _KINDS:
        raise UsageError(f"unsupported search modifier '/{kind_token}' (see /?)")

    pattern = _pattern(statement.args)
    if not pattern:
        raise UsageError(f"/{kind_token} needs a pattern")
    if kind_token == "a":
        # r2's `/a` assembles the text, then searches the resulting bytes.
        from idare2 import assembler

        raw = assembler.assemble(session, pattern)
        return _run(session, "bytes", raw.hex(), as_json=as_json)
    return _run(
        session,
        _KINDS[kind_token] + _KIND_FIXED.get(kind_token, ""),
        pattern,
        as_json=as_json,
    )


def _pattern(raw: str) -> str:
    """Strip the quoting r2 allows around multi-word patterns."""
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _run(session: Session, kind: str, pattern: str, *, as_json: bool) -> list[str]:
    start, end = _range(session)
    counter = session.search_counter
    width = _byte_width(pattern) if kind == "bytes" else None

    payload = session.remote.call(
        "search",
        pattern=pattern,
        kind=kind,
        start=start,
        end=end,
        limit=session.config.get_int("search.limit"),
    )
    hits = [int(hit) for hit in payload.get("hits") or []]

    session.search_counter += 1
    session.last_search = SearchState(
        kind=kind,
        pattern=pattern,
        last_hit=hits[-1] if hits else None,
        match=payload.get("match"),
    )

    if as_json:
        return [to_json({**payload, "hits": hits})]

    prefix = session.config.get_str("search.prefix")
    lines = []
    for index, ea in enumerate(hits):
        label = f"{prefix}{counter}_{index}"
        session.flags.add(label, ea)
        lines.append(f"{session.format_addr(ea)} {label} {_context(session, ea, kind, width)}")
    return lines


def _repeat(session: Session, token: str) -> list[str]:
    state = session.last_search
    if state is None:
        raise UsageError("no previous search to repeat")

    if token == "/+":
        if state.last_hit is None:
            return []
        # Nudge the search window for this one call, then restore it.
        saved = session.config.get_int("search.from")
        session.config.set("search.from", state.last_hit + 1)
        try:
            return _run(session, state.kind, state.pattern, as_json=False)
        finally:
            session.config.set("search.from", saved)
    return _run(session, state.kind, state.pattern, as_json=False)


def _range(session: Session) -> tuple[int | None, int | None]:
    """Resolve ``e search.from`` / ``e search.to`` / ``e search.in``."""
    start = session.config.get_int("search.from") or None
    end = session.config.get_int("search.to") or None
    if start is not None and end is not None:
        return start, end

    if session.config.get_str("search.in") == "io.maps":
        segments = session.search_segments()
        if segments:
            low = min(int(segment["start"]) for segment in segments)
            high = max(int(segment["end"]) for segment in segments)
            start = start if start is not None else low
            end = end if end is not None else high
    return start, end


def _byte_width(pattern: str) -> int | None:
    text = pattern.strip()
    if not text or len(text) % 2:
        return None
    try:
        return len(bytes.fromhex(text))
    except ValueError:
        return None


def _context(session: Session, ea: int, kind: str, width: int | None) -> str:
    """The right-hand column: the bytes found, or a context window."""
    if kind in ("bytes", "immediate"):
        span = width or 4
        try:
            payload = session.remote.call("read_bytes", ea=ea, count=span)
        except Exception:
            return ""
        return bytes(payload.get("data") or b"").hex()

    if kind.startswith("wide"):
        match = session.last_search.match if session.last_search else None
        if not match:
            return ""
        try:
            payload = session.remote.call("read_bytes", ea=ea, count=match)
        except Exception:
            return ""
        return bytes(payload.get("data") or b"").hex()

    start = max(ea - CONTEXT, 0)
    end = ea + CONTEXT
    for segment in session.search_segments():
        segment_start = int(segment["start"])
        segment_end = int(segment["end"])
        if segment_start <= ea < segment_end:
            # Reading a fixed ea-16 window crosses the preceding segment for a
            # hit near its start.  IDA correctly rejects that short/foreign read,
            # which used to make every such text hit render as "".
            start = max(start, segment_start)
            end = min(end, segment_end)
            break

    try:
        payload = session.remote.call("read_bytes", ea=start, count=max(end - start, 1))
    except Exception:
        return '""'
    raw = bytes(payload.get("data") or b"")
    text = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in raw)
    return f'"{text}"'
