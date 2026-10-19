"""The ``i`` file-information family."""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command, numeric_args, with_more
from idare2.fmt import listing as fmt_listing
from idare2.fmt import to_json

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

INFO_DETAIL = [
    ("i", "", "show information about the current file"),
    ("iI", "", "binary info (key: value)"),
    ("ij", "", "the same information as JSON"),
    ("iS", "", "segments with permissions"),
    ("ii", "[pat]", "imports"),
    ("is", "[pat]", "symbols"),
    ("iz", "[pat]", "strings"),
    ("ie", "", "entry points"),
    ("iE", "", "exports"),
]

LISTING_DETAIL = {
    "iS": [("iS", "", "segments with permissions"), ("iSj", "", "segments as JSON")],
    "ii": [("ii", "[pat]", "imports"), ("iij", "[pat]", "imports as JSON")],
    "is": [("is", "[pat]", "symbols"), ("isj", "[pat]", "symbols as JSON")],
    "iz": [("iz", "[pat]", "strings"), ("izj", "[pat]", "strings as JSON")],
    "ie": [("ie", "", "entry points"), ("iej", "", "entry points as JSON")],
    "iE": [("iE", "", "exports"), ("iEj", "", "exports as JSON")],
}


@command("i", usage="[j]", summary="file information", detail=INFO_DETAIL)
def file_info(session: Session, statement: Statement) -> list[str]:
    payload = session.remote.call("file_info")
    session.info.update({k: v for k, v in payload.items() if v is not None})
    if statement.cmd.endswith("j") or statement.cmd == "ij":
        return [to_json(payload)]
    return fmt_listing.format_info(payload, session)


@command("i[SsEeiz]", usage="[pat]", summary="list segments, symbols, imports, strings")
def listing(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    base = token[:2]
    as_json = token.endswith("j")
    rest, count, offset = numeric_args(session, statement)
    pattern = rest[0] if rest else None
    meta = None

    if base == "iS":
        rows = session.remote.call("segments")
    elif base == "ii":
        rows, meta = session.remote.call_with_meta(
            "imports", pattern=pattern, offset=offset, count=count
        )
    elif base == "is":
        rows, meta = session.remote.call_with_meta(
            "symbols", pattern=pattern, offset=offset, count=count
        )
    elif base == "iz":
        rows, meta = session.remote.call_with_meta(
            "strings", pattern=pattern, offset=offset, count=count
        )
    elif base in ("ie", "iE"):
        rows = session.remote.call("entries", pattern=pattern)
    else:
        raise AssertionError(f"unhandled info listing {token!r}")

    if as_json:
        return [to_json(rows)]

    formatter = {
        "iS": fmt_listing.format_segments,
        "ii": fmt_listing.format_imports,
        "is": fmt_listing.format_symbols,
        "iz": fmt_listing.format_strings,
        "ie": fmt_listing.format_entries,
        "iE": fmt_listing.format_entries,
    }[base]
    return with_more(formatter(rows, session), meta)
