"""Disassembly rendering, matching radare2's column layout.

Measured against r2 6.2.5 on an ARM32 firmware binary (``-e scr.color=0``)::

    │           0x00015e50      b4379fe5       ldr r3, aav.0x000b36e0      ; ...
    0x00015e50      b4379fe5       ldr r3, aav.0x000b36e0                  ; ...

The columns are fixed, and the comment column is *absolute* -- r2's
``asm.cmt.col`` defaults to 71, so a long instruction pushes its own comment
outward instead of shifting every line in the block.
"""

from __future__ import annotations

from typing import Any

from idare2.fmt import addr_width, fmt_addr, fmt_hex_bytes

#: Width of the ``│ `` flow gutter r2 prints for instructions inside a function.
GUTTER_WIDTH = 12
#: Spaces between the address column and the bytes column.
ADDR_PAD = 6
#: Spaces between the bytes column and the text.
BYTES_PAD = 7


def _gutter(session: Any, index: int, total: int) -> str:
    """``│`` with a corner marker on the first line, matching r2's box drawing."""
    if not session.config.get_bool("asm.lines"):
        return ""
    marker = "┌" if index == 0 else ("└" if index == total - 1 else "│")
    return marker + " " * (GUTTER_WIDTH - 1)


def format_disasm(result: dict[str, Any], session: Any) -> list[str]:
    """Render one ``disasm`` op result."""
    width = addr_width(session.info.get("bits"))
    show_bytes = session.config.get_bool("asm.bytes")
    show_addr = session.config.get_bool("asm.offset")
    show_comments = session.config.get_bool("asm.comments")
    comment_col = session.config.get_int("asm.cmt.col")
    lines_on = session.config.get_bool("asm.lines")

    records = result.get("lines") or []
    func = result.get("func")

    # r2 prints a function header box when the listing starts exactly at a
    # function entry, then a bare `│` gutter for every instruction.
    header = ""
    if (
        lines_on
        and func
        and records
        and int(records[0]["ea"]) == int(func.get("start", -1))
    ):
        header = _func_header(func, session)

    out: list[str] = [header] if header else []
    for index, record in enumerate(records):
        out.append(
            _line(
                record,
                session,
                width=width,
                gutter=("" if not lines_on else _gutter(index, len(records), bool(header))),
                show_addr=show_addr,
                show_bytes=show_bytes,
                show_comments=show_comments,
                comment_col=comment_col,
            )
        )
    return out


def _gutter(index: int, total: int, has_header: bool) -> str:
    """Box-drawing prefix: corner on the first/last line, pipe in between."""
    if index == 0 and not has_header:
        marker = "┌"
    elif index == total - 1:
        marker = "└"
    else:
        marker = "│"
    return marker + " " * (GUTTER_WIDTH - 1)


def _func_header(func: dict[str, Any], session: Any) -> str:
    start = int(func.get("start", 0))
    end = int(func.get("end", 0))
    signature = func.get("signature")
    label = signature or func.get("name") or "?"
    return f"┌ {end - start}: {label}"


def _line(
    record: dict[str, Any],
    session: Any,
    *,
    width: int,
    gutter: str,
    show_addr: bool,
    show_bytes: bool,
    show_comments: bool,
    comment_col: int,
) -> str:
    out = gutter

    if show_addr:
        out += fmt_addr(int(record["ea"]), width) + " " * ADDR_PAD
    if show_bytes:
        raw = record.get("bytes") or b""
        out += fmt_hex_bytes(raw) + " " * BYTES_PAD

    text = _decorate(record, session)
    comment = _comment(record, session) if show_comments else ""
    if comment:
        if len(out) + len(text) >= comment_col:
            # r2 pushes the comment out rather than truncating the instruction.
            out += text + " "
        else:
            out += text + " " * (comment_col - len(out) - len(text))
        out += comment
    else:
        out += text
    return out.rstrip() if not comment else out


def _decorate(record: dict[str, Any], session: Any) -> str:
    """Apply the ``asm.flags`` colouring hook.

    Colouring is a no-op while ``scr.color=0``, which is the default for
    non-tty output, so the text is returned untouched in the common case.
    """
    text = str(record.get("text") or "")
    if not session.config.get_bool("asm.flags"):
        return text
    return session.colors.disasm(text, record)


def _comment(record: dict[str, Any], session: Any) -> str:
    """The comment column.

    IDA's own comment comes from the op; a session-local override (``CC`` before
    it is written through) takes precedence.
    """
    local = session.comment_at(int(record["ea"]))
    if local:
        return "; " + local
    comment = str(record.get("comment") or "")
    return f"; {comment}" if comment else ""


def format_function_info(info: dict[str, Any], session: Any) -> list[str]:
    """``afi`` -- r2's ``key: value`` block."""
    width = addr_width(session.info.get("bits"))
    rows = [
        ("addr", fmt_addr(int(info["ea"]), width)),
        ("name", info.get("name") or ""),
        ("size", info.get("size")),
        ("is-pure", "false"),
        ("stackframe", info.get("stackframe", 0)),
        ("callconv", info.get("callconv", "")),
        ("nbbs", info.get("nbbs")),
        ("ninstrs", info.get("ninstrs")),
        ("callers", info.get("callers")),
        ("callees", info.get("callees")),
        ("locals", info.get("locals")),
        ("noreturn", str(bool(info.get("noreturn"))).lower()),
        ("signature", info.get("signature") or ""),
    ]
    return [f"{key}: {value}" for key, value in rows if value not in (None, "")]


def format_blocks(blocks: list[dict[str, Any]], session: Any) -> list[str]:
    """``afb`` -- one line per basic block."""
    width = addr_width(session.info.get("bits"))
    return [
        f"{fmt_addr(int(block['start']), width)} {fmt_addr(int(block['end']), width)} "
        f"{block['size']:>6} {block['index']:>4}"
        for block in blocks
    ]
