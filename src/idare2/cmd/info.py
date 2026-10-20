"""The ``i`` file-information family."""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command, numeric_args, with_more
from idare2.errors import UsageError
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
    ("iM", "", "main address"),
]

FILE_TOKENS = frozenset({"i", "iI", "ij"})

LISTING_DETAIL = {
    "iS": [("iS", "", "segments with permissions"), ("iSj", "", "segments as JSON")],
    "ii": [("ii", "[pat]", "imports"), ("iij", "[pat]", "imports as JSON")],
    "is": [("is", "[pat]", "symbols"), ("isj", "[pat]", "symbols as JSON")],
    "iz": [("iz", "[pat]", "strings"), ("izj", "[pat]", "strings as JSON")],
    "ie": [("ie", "", "entry points"), ("iej", "", "entry points as JSON")],
    "iE": [("iE", "", "exports"), ("iEj", "", "exports as JSON")],
    "iM": [("iM", "", "main address")],
}

LISTING_TOKENS = frozenset(
    token for rows in LISTING_DETAIL.values() for token, _args, _description in rows
)


@command("i", usage="[j]", summary="file information", detail=INFO_DETAIL, json_suffix=True)
def file_info(session: Session, statement: Statement) -> list[str]:
    if statement.cmd not in FILE_TOKENS:
        raise UsageError(f"unsupported information command '{statement.cmd}' (see i?)")
    payload = session.remote.call("file_info")
    session.info.update({k: v for k, v in payload.items() if v is not None})
    if statement.cmd.endswith("j") or statement.cmd == "ij":
        return [to_json(payload)]
    return fmt_listing.format_info(payload, session)


@command(
    "i[SsEeizM]",
    usage="[pat]",
    summary="list segments, symbols, imports, strings",
    json_suffix=True,
)
def listing(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token not in LISTING_TOKENS:
        raise UsageError(f"unsupported information command '{token}' (see i?)")
    base = token[:2]
    as_json = token.endswith("j")

    if base == "iM":
        return _main_address(session)

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


def _main_address(session: Session) -> list[str]:
    """``iM`` -- main (or the entry point when no ``main`` symbol exists)."""
    rows, _meta = session.remote.call_with_meta(
        "symbols", pattern="main", offset=0, count=-1
    )
    target = next((int(row["ea"]) for row in rows if row["name"] == "main"), None)
    if target is None:
        target = int(session.info.get("start_ip") or 0)
        if target >= (1 << 63):
            target = 0
    if not target:
        raise UsageError("cannot locate main or an entry point")

    paddr = target
    for segment in session.remote.call("segments"):
        start = int(segment["vaddr"])
        end = start + int(segment["vsize"])
        base = segment.get("paddr")
        if base is not None and start <= target < end:
            paddr = int(base) + (target - start)
            break
    return [f"vaddr=0x{target:08x} paddr=0x{paddr:08x}"]
