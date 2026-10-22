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
    ("it", "", "file hashes"),
    ("itj", "", "file hashes as JSON"),
    ("iS", "", "segments with permissions"),
    ("ii", "[pat]", "imports"),
    ("is", "[pat]", "symbols"),
    ("iz", "[pat]", "strings"),
    ("ir", "", "relocations"),
    ("ih", "", "header fields"),
    ("iH", "", "file header"),
    ("ie", "", "entry points"),
    ("iE", "", "exports"),
    ("iM", "", "main address"),
]

HEADER_DETAIL = [
    ("ih", "[*jq]", "header fields (ELF)"),
    ("iH", "[*j]", "file header (ELF)"),
]

FILE_TOKENS = frozenset({"i", "iI", "ij", "it", "itj"})

LISTING_DETAIL = {
    "iS": [("iS", "", "segments with permissions"), ("iSj", "", "segments as JSON")],
    "ii": [("ii", "[pat]", "imports"), ("iij", "[pat]", "imports as JSON")],
    "is": [("is", "[pat]", "symbols"), ("isj", "[pat]", "symbols as JSON")],
    "iz": [("iz", "[pat]", "strings"), ("izj", "[pat]", "strings as JSON")],
    "ir": [("ir", "", "relocations"), ("irj", "", "relocations as JSON")],
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
    if statement.cmd.startswith("it"):
        return _file_hashes(session, as_json=statement.cmd == "itj")
    payload = session.remote.call("file_info")
    session.info.update({k: v for k, v in payload.items() if v is not None})
    if statement.cmd.endswith("j") or statement.cmd == "ij":
        return [to_json(payload)]
    return fmt_listing.format_info(payload, session)


def _file_hashes(session: Session, *, as_json: bool) -> list[str]:
    """``it`` -- md5/sha1/sha256 over the input file.

    ``bin.hashlimit`` mirrors r2: inputs above the limit produce no hashes (r2
    prints nothing for text and ``{}`` for JSON).  A limit of zero disables
    hashing entirely, as in r2.
    """
    limit = session.config.get_int("bin.hashlimit")
    size = int(session.info.get("filesize") or 0)
    payload: dict[str, str] = {}
    if limit > 0 and (size <= limit or not size):
        raw = session.remote.call("file_hashes") or {}
        payload = {name: value for name, value in raw.items() if value}
    if as_json:
        return [to_json(payload)]
    return [f"{name} {value}" for name, value in payload.items()]


@command(
    "i[SsEeizMr]",
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
    elif base == "ir":
        rows = session.remote.call("relocations")
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
        "ir": fmt_listing.format_relocations,
        "ie": fmt_listing.format_entries,
        "iE": fmt_listing.format_entries,
    }[base]
    return with_more(formatter(rows, session), meta)


@command(
    "i[hH]",
    usage="[*jq]",
    summary="ELF file header",
    detail=HEADER_DETAIL,
    json_suffix=True,
)
def header(session: Session, statement: Statement) -> list[str]:
    """``ih``/``iH`` -- the ELF file header, read from the original input.

    radare2 splits this in two: ``ih`` lists the header fields as
    ``vaddr paddr value name`` rows (with an embedded ``pf`` decode in JSON),
    while ``iH`` prints the plugin's fixed ``headers32``/``headers64`` table.
    Both come from the same field list, so one remote operation feeds all
    forms.
    """
    token = statement.cmd
    base, suffix = token[:2], token[2:]
    if suffix not in ("", "j", "q", "*"):
        raise UsageError(f"unsupported information command '{token}' (see ih?)")

    payload = session.remote.call("header_fields")
    bits = int(payload.get("bits") or session.info.get("bits") or 0)
    fields = payload.get("fields") or []

    if suffix == "j":
        if base == "iH":
            # r2 wraps a plugin-provided header string (trailing newline and
            # all) in an object instead of emitting an array.
            text = "\n".join(fmt_listing.format_header(fields, bits)) + "\n"
            return [to_json({"header": text})]
        return [to_json(fields)]
    if suffix == "*":
        # `iH*` falls back to the fields form in r2 as well.
        return fmt_listing.format_header_radare(fields)
    if base == "iH":
        return fmt_listing.format_header(fields, bits)
    if suffix == "q":
        return fmt_listing.format_header_quiet(fields)
    return fmt_listing.format_header_fields(fields)


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
