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
    from ida_domain.comments import CommentKind

    # CommentKind.ALL: the REGULAR default hides repeatable comments (CCr,
    # Cf's stored format string), which made them set-but-invisible.
    source = (
        db.comments.get_all(CommentKind.ALL)
        if ea is None
        else [db.comments.get_at(ea, CommentKind.ALL)]
    )
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


#: pf item kinds -> ida-domain ``db.bytes`` makers.  ``create_dword_at`` and
#: friends take ``(ea, count)``, so arrays ride on the same call.
_FORMAT_MAKERS = {
    "byte": "create_byte_at",
    "word": "create_word_at",
    "dword": "create_dword_at",
    "qword": "create_qword_at",
    "float": "create_float_at",
    "double": "create_double_at",
    "oword": "create_oword_at",
}


@op("set_format_meta", writes=True)
def set_format_meta(
    db: Any, ea: int, items: list[dict[str, Any]], fmt: str
) -> dict[str, Any]:
    """Create the data items a pf format describes (``Cf``).

    The client maps the format string to ``{"offset", "kind", "count"}``
    items (``pf.format_to_items``); this op materialises them sequentially
    and keeps the format string alive as a repeatable ``pf ...`` comment so
    ``C`` can list it and ``Cf-`` can undo it.  A failing item does not roll
    the earlier ones back (IDA has no such primitive); the response reports
    what was applied and what failed.
    """
    applied: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for item in items:
        kind = str(item["kind"])
        maker_name = _FORMAT_MAKERS.get(kind)
        if maker_name is None:
            helpers.fail(protocol.BAD_ARGS, f"unknown item kind {kind!r}")
        target = ea + int(item["offset"])
        count = int(item["count"])
        try:
            # force=True: Cf overrides whatever item occupies the span,
            # like r2's format metadata does.
            created = bool(getattr(db.bytes, maker_name)(target, count, True))
        except Exception as exc:  # noqa: BLE001 - reported per item
            created = False
            errors.append({"ea": target, "kind": kind, "count": count,
                           "error": str(exc)})
            continue
        if created:
            applied.append({"ea": target, "kind": kind, "count": count})
        else:
            errors.append({"ea": target, "kind": kind, "count": count,
                           "error": "IDA refused to define the item"})
    set_comment(db, ea, f"pf {fmt}", repeatable=True)
    return {"ea": ea, "fmt": fmt, "applied": applied, "errors": errors}


@op("delete_format_meta", writes=True)
def delete_format_meta(db: Any, ea: int) -> dict[str, Any]:
    """Undo ``Cf``: undefine the formatted span and drop the pf comment."""
    import ida_bytes
    from ida_domain.comments import CommentKind

    comment = db.comments.get_at(ea, CommentKind.ALL)
    text = str(comment.comment or "") if comment is not None else ""
    if not text.startswith("pf "):
        helpers.fail(protocol.NOT_FOUND, f"no format metadata at 0x{ea:x}")
    from idare2.pf import format_to_items, items_span

    try:
        items = format_to_items(text[3:], bits=int(getattr(db, "bitness", 32) or 32))
    except Exception as exc:
        helpers.fail(protocol.BAD_ARGS, f"stored format {text!r} no longer parses: {exc}")
    span = items_span(items)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, span)
    delete_comment(db, ea, repeatable=True)
    return {"ea": ea, "removed": span}


def _kind(repeatable: bool, *, all_kinds: bool = False) -> Any:
    from ida_domain.comments import CommentKind

    if all_kinds:
        return CommentKind.ALL
    return CommentKind.REPEATABLE if repeatable else CommentKind.REGULAR


@op("string_meta")
def string_meta(db: Any, ea: int) -> dict[str, Any]:
    """Whether a string literal is defined at ``ea`` and its text (``Cs.``)."""
    try:
        is_string = bool(db.bytes.is_string_literal_at(ea))
    except Exception:
        is_string = False
    text = None
    if is_string:
        try:
            text = db.bytes.get_string_at(ea)
        except Exception:
            text = None
    hidden = False
    try:
        import ida_nalt

        hidden = bool(ida_nalt.is_hidden_item(ea))
    except Exception:
        hidden = False
    return {"ea": ea, "is_string": is_string, "text": text, "hidden": hidden}


@op("set_string_meta", writes=True)
def set_string_meta(db: Any, ea: int, size: int = 0, value: bool = True) -> dict[str, Any]:
    """Create or remove an ASCII string literal at ``ea`` (``Cs``/``Cs-``).

    With ``size`` 0 the literal runs to the NUL terminator; removing it
    undefines the item so IDA no longer reports a string there.
    """
    if value:
        length = size or None
        ok = db.bytes.create_string_at(ea, length)
        return {"ea": ea, "is_string": bool(ok)}
    import ida_bytes

    ok = ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size or 1)
    return {"ea": ea, "is_string": False, "removed": bool(ok) or True}


@op("set_hidden", writes=True)
def set_hidden(db: Any, ea: int, value: bool = True) -> dict[str, Any]:
    """Hide or unhide the item at ``ea`` (``Ch``/``Ch-``)."""
    import ida_nalt

    if value:
        ida_nalt.hide_item(ea)
    else:
        ida_nalt.unhide_item(ea)
    return {"ea": ea, "hidden": bool(ida_nalt.is_hidden_item(ea))}


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
