"""Comment and metadata operations backing ``C*``."""

from __future__ import annotations

from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op


@op("comments")
def comments(db: Any, ea: int | None = None) -> list[dict[str, Any]]:
    """Comments (``C``, ``CC.``).

    ``ea=None`` lists them all.  ``db.comments.get_all`` yields ``CommentInfo``
    dataclasses, which are not JSON-serialisable, so they are flattened here.
    """
    source = db.comments.get_all() if ea is None else [db.comments.get_at(ea)]
    out = []
    for info in source:
        if info is None:
            continue
        out.append(
            {
                "ea": int(info.ea),
                "comment": info.comment,
                "repeatable": bool(info.repeatable),
            }
        )
    return out


@op("set_comment", writes=True)
def set_comment(db: Any, ea: int, text: str, repeatable: bool = False) -> dict[str, Any]:
    """Add or replace a comment (``CC``, ``CCr``)."""
    kind = _kind(repeatable, all_kinds=False)
    if not db.comments.set_at(ea, text, kind):
        helpers.fail(protocol.IDA_ERROR, f"IDA refused to comment 0x{ea:x}")
    return {"ea": ea, "comment": text, "repeatable": repeatable}


@op("delete_comment", writes=True)
def delete_comment(db: Any, ea: int, repeatable: bool = False) -> dict[str, Any]:
    """Remove a comment (``CC-``)."""
    db.comments.delete_at(ea, _kind(repeatable, all_kinds=False))
    return {"ea": ea}


@op("delete_comments_in_range", writes=True)
def delete_comments_in_range(db: Any, start: int, end: int) -> dict[str, Any]:
    """Drop every comment in ``[start, end)`` (``C- len``)."""
    removed = 0
    for info in list(db.comments.get_all()):
        if start <= int(info.ea) < end:
            db.comments.delete_at(int(info.ea), _kind(bool(info.repeatable)))
            removed += 1
    return {"removed": removed}


def _kind(repeatable: bool, *, all_kinds: bool = False) -> Any:
    from ida_domain.comments import CommentKind

    if all_kinds:
        return CommentKind.ALL
    return CommentKind.REPEATABLE if repeatable else CommentKind.REGULAR


@op("set_data_type", writes=True)
def set_data_type(db: Any, ea: int, kind: str, count: int = 1) -> dict[str, Any]:
    """Mark data at ``ea`` as a typed array (``Cd``)."""
    makers = {
        "byte": db.bytes.create_byte_at,
        "word": db.bytes.create_word_at,
        "dword": db.bytes.create_dword_at,
        "qword": db.bytes.create_qword_at,
    }
    maker = makers.get(kind)
    if maker is None:
        helpers.fail(
            protocol.BAD_ARGS, f"kind must be one of {', '.join(makers)}, not {kind!r}"
        )
    if count <= 0:
        helpers.fail(protocol.BAD_ARGS, "count must be positive")
    ok = maker(ea, count)
    return {"ea": ea, "kind": kind, "count": count, "created": bool(ok)}


@op("data_info")
def data_info(db: Any, ea: int, size: int = 0) -> dict[str, Any]:
    """What kind of item sits at ``ea`` (``Cd.``, ``Cf`` lookup)."""
    return {
        "ea": ea,
        "size": int(db.bytes.get_data_size_at(ea) or 0) or size,
        "is_code": bool(db.bytes.is_code_at(ea)),
        "is_data": bool(db.bytes.is_data_at(ea)),
        "is_unknown": bool(db.bytes.is_unknown_at(ea)),
        "is_string": bool(db.bytes.is_string_literal_at(ea)),
        "is_struct": bool(db.bytes.is_struct_at(ea)),
        "is_byte": bool(db.bytes.is_byte_at(ea)),
        "is_word": bool(db.bytes.is_word_at(ea)),
        "is_dword": bool(db.bytes.is_dword_at(ea)),
        "is_qword": bool(db.bytes.is_qword_at(ea)),
    }
