"""What ``C.`` reports about the current address.

Kept out of :mod:`idare2.cmd.meta` so that module stays a thin dispatcher; this
one assembles metadata from the comments, data and type operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from idare2.session import Session


def describe_metadata(session: Session) -> list[str]:
    ea = session.seek
    lines = [f"addr: {session.format_addr(ea)}"]

    comments = session.remote.call("comments", ea=ea)
    for row in comments:
        kind = "repeatable" if row["repeatable"] else "regular"
        lines.append(f"comment ({kind}): {row['comment']}")

    data = session.remote.call("data_info", ea=ea)
    if data["size"]:
        lines.append(f"size: {data['size']}")
    for key, label in (
        ("is_code", "code"),
        ("is_string", "string"),
        ("is_struct", "struct"),
        ("is_dword", "dword"),
        ("is_word", "word"),
        ("is_byte", "byte"),
        ("is_data", "data"),
        ("is_unknown", "unknown"),
    ):
        if data.get(key):
            lines.append(f"type: {label}")
            break

    try:
        type_at = session.remote.call("type_at", ea=ea)
    except Exception:
        type_at = None
    if type_at:
        lines.append(f"decl: {type_at['declaration']}")

    return lines
