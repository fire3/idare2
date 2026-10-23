"""Cross-reference rendering, matching r2's ``axt`` / ``axf`` layout.

Measured against r2 6.2.5::

    entry0 0xf3cc [DATA:r--] ldr r0, dbg.main
    (nofunc) 0xf3e0 [NULL:r--] andeq r5, r1, r0, lsl lr

Note the address is **not** zero-padded here, unlike everywhere else in r2.
"""

from __future__ import annotations

from typing import Any


def _enclosing(xref: dict[str, Any]) -> str:
    return xref.get("func") or "(nofunc)"


def format_xrefs(xrefs: list[dict[str, Any]], session: Any) -> list[str]:
    """``axt`` / ``axf``."""
    lines = []
    for xref in xrefs:
        address = int(xref["from"] if xref.get("direction") == "to" else xref["to"])
        tag = f"[{xref['type']}:{xref['perm']}]"
        text = xref.get("text") or ""
        lines.append(f"{_enclosing(xref)} 0x{address:x} {tag} {text}".rstrip())
    return lines


def format_callers(callers: list[dict[str, Any]], session: Any) -> list[str]:
    return [f"0x{int(item['ea']):x} {item['name']}" for item in callers]


_AFX_CHAR = {"CALL": "C", "JUMP": "j", "CODE": "c", "DATA": "d", "STRN": "s"}


def format_function_xrefs(rows: list[dict[str, Any]]) -> list[str]:
    """``afx`` -- r2's ``<type> 0x<from> -> 0x<to> <instruction>`` rows."""
    lines = []
    for row in rows:
        char = _AFX_CHAR.get(str(row.get("type")), "?")
        line = (
            f"{char} 0x{int(row['from']):08x} -> 0x{int(row['to']):08x} "
            f"{row.get('text') or ''}"
        ).rstrip()
        if row.get("string"):
            line += f"  {row['string']}"
        lines.append(line)
    return lines


def format_callees(callees: list[dict[str, Any]], session: Any) -> list[str]:
    return [f"0x{int(item['ea']):x} {item['name']}" for item in callees]
