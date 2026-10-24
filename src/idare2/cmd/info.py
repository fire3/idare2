"""The ``i`` file-information family."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from idare2.cmd import command, numeric_args, with_more
from idare2.errors import UsageError
from idare2.fmt import addr_width, fmt_addr, human_size, to_json
from idare2.fmt import listing as fmt_listing

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

INFO_DETAIL = [
    ("i", "", "show information about the current file"),
    ("iI", "", "binary info (key: value)"),
    ("ij", "", "the same information as JSON"),
    ("it", "", "file hashes"),
    ("itj", "", "file hashes as JSON"),
    ("iD", "[lang] sym", "demangle a symbol"),
    ("ia", "", "architectures found in the file"),
    ("iaj", "", "architectures as JSON"),
    ("il", "", "needed libraries"),
    ("ilj", "", "needed libraries as JSON"),
    ("ilq", "", "needed libraries, names only"),
    ("iS", "[algo]", "ELF sections (optionally with a hash column)"),
    ("iSS", "", "memory maps (ELF program headers)"),
    ("iS.", "", "the section containing the seek"),
    ("iSh", "", "section headers"),
    ("iSm", "", "sections with the names they contain"),
    ("ii", "[pat]", "imports"),
    ("is", "[pat]", "symbols"),
    ("iz", "[pat]", "strings"),
    ("izz", "[pat]", "strings in the whole file"),
    ("ir", "", "relocations"),
    ("ih", "", "header fields"),
    ("iH", "", "file header"),
    ("ie", "", "entry points"),
    ("iee", "", "constructors and destructors"),
    ("ies", "[pat]", "entry-point symbols"),
    ("ig", "[h]", "guess the program size"),
    ("iE", "", "exports"),
    ("iM", "", "main address"),
    ("CL", "[j*.] [addr]", "source-line information"),
]

HEADER_DETAIL = [
    ("ih", "[*jq]", "header fields (ELF)"),
    ("iH", "[*j]", "file header (ELF)"),
]

#: Languages radare2 6.2.5 accepts for ``iD`` (``r_bin_demangle_type``).  IDA's
#: demangler auto-detects the scheme; the language only labels the answer.
DEMANGLE_LANGUAGES = (
    "c++",
    "dlang",
    "ibmxl",
    "java",
    "msvc",
    "objc",
    "pascal",
    "rust",
    "swift",
)

_DEMANGLE_ALIASES = {
    "cxx": "c++",
    "xlc": "ibmxl",
    "xlc++": "ibmxl",
    "freepascal": "pascal",
}

FILE_TOKENS = frozenset({"i", "iI", "ij", "it", "itj"})

LISTING_DETAIL = {
    "ii": [("ii", "[pat]", "imports"), ("iij", "[pat]", "imports as JSON")],
    "is": [("is", "[pat]", "symbols"), ("isj", "[pat]", "symbols as JSON")],
    "iz": [("iz", "[pat]", "strings"), ("izj", "[pat]", "strings as JSON")],
    "izz": [("izz", "[pat]", "strings in the whole file"),
            ("izzj", "[pat]", "whole-file strings as JSON")],
    "ir": [("ir", "", "relocations"), ("irj", "", "relocations as JSON")],
    "ie": [
        ("ie", "", "entry points"),
        ("iej", "", "entry points as JSON"),
        ("iee", "", "constructors and destructors"),
        ("ieej", "", "constructors and destructors as JSON"),
        ("ies", "[pat]", "entry-point symbols"),
        ("iesj", "[pat]", "entry-point symbols as JSON"),
    ],
    "ig": [("ig", "", "guess the program size"), ("igh", "", "same, human-readable")],
    "iE": [("iE", "", "exports"), ("iEj", "", "exports as JSON")],
    "iM": [("iM", "", "main address")],
}

SECTION_DETAIL = [    ("iS", "[algo]", "ELF sections; an algorithm name adds a hash column"),
    ("iSj", "[algo]", "sections as JSON"),
    ("iSS", "", "memory maps from the ELF program headers"),
    ("iSSj", "", "memory maps as JSON"),
    ("iS.", "", "the section containing the current seek"),
    ("iS.j", "", "the current section as JSON"),
    ("iSh", "[j]", "raw section-header table"),
    ("iSm", "", "sections with the names they contain"),
    ("iSmc", "", "section symbol counts"),
    ("iSmj", "", "section symbols as JSON"),
]

LISTING_TOKENS = frozenset(
    token for rows in LISTING_DETAIL.values() for token, _args, _description in rows
)

SECTION_TOKENS = frozenset(
    {
        "iS", "iSj", "iSh", "iShj", "iSS", "iSSj", "iS.", "iS.j",
        "iSm", "iSmc", "iSmj",
    }
)

CL_DETAIL = [
    ("CL", "", "all address/source-line mappings"),
    ("CLj", "", "the mappings as JSON"),
    ("CL*", "", "the mappings as r2 commands"),
    ("CL.", "", "the mapping at the current seek"),
    ("CLf", "[addr]", "source file name at the current seek"),
    ("CLu", "", "source files used by the debug info"),
    ("CLuj", "", "source files as JSON"),
    ("CLL", "[addr]", "source text at the current seek"),
    ("CLLb", "", "source text for the current basic block"),
    ("CLLf", "", "source text across the current function"),
]

CL_TOKENS = frozenset(
    {"CL", "CLj", "CL*", "CL.", "CLf", "CLu", "CLuj", "CLL", "CLLb", "CLLf"}
)


def _line_row(row: dict[str, Any]) -> list[str]:
    return [
        f"file: {row['file']}",
        f"line: {row['line']}",
        f"colu: {row['column']}",
        f"addr: 0x{int(row['addr']):08x}",
    ]


def _lines(session: Session, token: str, statement: Statement) -> list[str]:
    """``CL``/``CLf``/``CLu``/``CLL`` -- source-line metadata."""
    argument = statement.args.strip()
    target = session.resolve(argument) if argument else session.seek

    if token in ("CLu", "CLuj"):
        files = session.remote.call("line_units")
        return [to_json(files)] if token == "CLuj" else list(files)

    if token == "CLf":
        rows = session.remote.call("line_info", ea=target)
        return [Path(str(rows[0]["file"])).name] if rows else []

    if token == "CL.":
        rows = session.remote.call("line_info", ea=target)
        if not rows:
            return []
        lines: list[str] = []
        for row in rows:
            lines.extend(_line_row(row))
        return lines

    if token == "CLL":
        rows = session.remote.call("line_source", addrs=[target])
        return [f"0x{int(row['addr']):08x}  {row['text']}" for row in rows]
    if token == "CLLb":
        block = session.remote.call("block_info", ea=target)
        addrs = _range_instructions(
            session, int(block["start"]), int(block["end"])
        )
        rows = session.remote.call("line_source", addrs=addrs)
        return [f"0x{int(row['addr']):08x}  {row['text']}" for row in rows]
    if token == "CLLf":
        func = session.remote.call("function_info", ea=target)
        addrs = _range_instructions(session, int(func["ea"]), int(func["end"]))
        rows = session.remote.call("line_source", addrs=addrs)
        return [f"0x{int(row['addr']):08x}  {row['text']}" for row in rows]

    rows = session.remote.call("line_info")
    if token == "CLj":
        return [to_json(rows)]
    if token == "CL*":
        return [
            f"'CL 0x{int(row['addr']):08x} {row['file']}:{row['line']}"
            for row in rows
        ]
    lines = []
    for row in rows:
        lines.extend(_line_row(row))
    return lines


def _range_instructions(session: Session, start: int, end: int) -> list[int]:
    """Instruction heads in ``[start, end)`` for the CLL block/function forms."""
    payload = session.remote.call(
        "disasm", ea=start, count=max(end - start, 1), mode="bytes"
    )
    return [int(line["ea"]) for line in payload.get("lines", [])]


def _sections(
    session: Session, token: str, statement: Statement, as_json: bool
) -> list[str]:
    """``iS``/``iSS``/``iS.``/``iSh``/``iSm`` -- the ELF section family."""
    rest, _count, _offset = numeric_args(session, statement)
    if token in ("iS", "iSj"):
        algorithm = rest[0] if rest else None
        rows = session.remote.call("sections", hash_name=algorithm)
        if as_json:
            return [to_json(fmt_listing.section_json(rows))]
        return fmt_listing.format_sections(rows, session, hash_name=algorithm)

    if token in ("iSS", "iSSj"):
        rows = session.remote.call("segments_map")
        if as_json:
            return [to_json(fmt_listing.section_json(rows))]
        return fmt_listing.format_sections(rows, session)

    if token in ("iS.", "iS.j"):
        row = session.remote.call("section_at", ea=session.seek)
        if row is None:
            return []
        row = {**row, "nth": 0}
        if as_json:
            return [to_json(fmt_listing.section_json([row]))]
        return ["Current section"] + fmt_listing.format_sections([row], session)

    if token in ("iSh", "iShj"):
        rows = session.remote.call("section_headers")
        if as_json:
            return [to_json(rows)]
        headers = ("name", "type", "flags", "addr", "offset", "size",
                   "link", "info", "addralign", "entsize")
        body = [
            [
                row["name"],
                str(row["type"]),
                f"0x{row['flags']:x}",
                f"0x{row['addr']:x}",
                f"0x{row['offset']:x}",
                f"0x{row['size']:x}",
                str(row["link"]),
                str(row["info"]),
                str(row["addralign"]),
                str(row["entsize"]),
            ]
            for row in rows
        ]
        return fmt_listing.table(headers, body)

    if token == "iSmj":
        rows = session.remote.call("section_symbols")
        return [to_json(rows)]
    rows = session.remote.call("section_symbols")
    if token == "iSmc":
        return _format_section_symbols(rows, session, counts=True)
    return _format_section_symbols(rows, session, counts=False)


def _format_constructors(rows: list[dict[str, Any]], session: Session) -> list[str]:
    width = addr_width(session.info.get("bits"))
    body = [
        [
            fmt_addr(int(row["paddr"]), width),
            fmt_addr(int(row["vaddr"]), width),
            fmt_addr(int(row["phaddr"]), width),
            fmt_addr(int(row["vhaddr"]), width),
            str(row["type"]),
        ]
        for row in rows
    ]
    return fmt_listing.table(("paddr", "vaddr", "phaddr", "vhaddr", "type"), body)


def _format_section_symbols(
    rows: list[dict[str, Any]], session: Session, *, counts: bool
) -> list[str]:
    width = addr_width(session.info.get("bits"))
    lines = []
    for row in rows:
        start = fmt_addr(int(row["start"]), width)
        end = fmt_addr(int(row["end"]), width)
        label = f"{start}-{end} {human_size(int(row['vsize'])):>9} {row['name']}"
        if counts:
            lines.append(f"{label} = {len(row['symbols'])} symbols")
            continue
        lines.append(label)
        for symbol in row["symbols"]:
            lines.append(f"{'-':>9} {0:>8} {symbol['name']}")
    return lines


@command(
    "i",
    usage="[j]",
    summary="file information",
    detail=INFO_DETAIL,
    json_suffix=True,
    suffixes=frozenset({"", "I", "j", "t", "tj"}),
    suffix_label="information command",
    suffix_help="i?",
)
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
    "CL",
    usage="[j*.] [addr]",
    summary="source-line information",
    detail=CL_DETAIL,
    json_suffix=True,
    suffixes=frozenset({"", "j", "*", ".", "f", "u", "uj", "L", "Lb", "Lf"}),
    suffix_label="line-info command",
    suffix_help="CL?",
)
def line_info(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token not in CL_TOKENS:
        raise UsageError(f"unsupported line-info command '{token}' (see CL?)")
    return _lines(session, token, statement)


@command(
    "iS",
    usage="[algo]",
    summary="ELF sections, memory maps and section symbols",
    detail=SECTION_DETAIL,
    json_suffix=True,
    suffixes=frozenset({"", "j", "h", "hj", "S", "Sj", ".", ".j", "m", "mc", "mj"}),
    suffix_label="information command",
    suffix_help="iS?",
)
def section_info(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token not in SECTION_TOKENS:
        raise UsageError(f"unsupported information command '{token}' (see iS?)")
    return _sections(session, token, statement, token.endswith("j"))


@command(
    "i[EeizMrsg]",
    usage="[pat]",
    summary="list symbols, imports, entries, strings",
    json_suffix=True,
    suffixes=frozenset({"", "j", "e", "ej", "s", "sj", "h", "z", "zj"}),    suffix_label="information command",
    suffix_help="i?",
)
def listing(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token not in LISTING_TOKENS:
        raise UsageError(f"unsupported information command '{token}' (see i?)")
    base = token[:2]
    as_json = token.endswith("j")

    if token in ("iee", "ieej"):
        rows = session.remote.call("constructors")
        if as_json:
            return [to_json(rows)]
        return _format_constructors(rows, session)
    if token in ("ies", "iesj"):
        rest, _count, _offset = numeric_args(session, statement)
        rows = session.remote.call(
            "entry_symbols", pattern=rest[0] if rest else None
        )
        if as_json:
            return [to_json(rows)]
        width = addr_width(session.info.get("bits"))
        return [f"{fmt_addr(int(row['ea']), width)} {row['name']}" for row in rows]
    if token in ("ig", "igh"):
        payload = session.remote.call("guess_size")
        size = int(payload.get("size") or 0)
        return [human_size(size) if token == "igh" else f"0x{size:08x}"]

    if token in SECTION_TOKENS:
        return _sections(session, token, statement, as_json)

    if base == "iM":
        return _main_address(session)

    rest, count, offset = numeric_args(session, statement)
    pattern = rest[0] if rest else None
    meta = None

    if base == "ii":
        rows, meta = session.remote.call_with_meta(
            "imports", pattern=pattern, offset=offset, count=count
        )
    elif base == "is":
        rows, meta = session.remote.call_with_meta(
            "symbols", pattern=pattern, offset=offset, count=count
        )
    elif base == "iz" and token.startswith("izz"):
        rows, meta = session.remote.call_with_meta(
            "all_strings",
            pattern=pattern,
            offset=offset,
            count=count,
            min_length=session.config.get_int("bin.str.min"),
            max_length=session.config.get_int("bin.str.max"),
            alignment=session.config.get_int("bin.str.align"),
            encoding=session.config.get("bin.str.enc"),
        )
    elif base == "iz":
        rows, meta = session.remote.call_with_meta(
            "strings", pattern=pattern, offset=offset, count=count
        )
    elif base == "ir":
        rows = session.remote.call("relocations")
    elif base == "ie":
        rows = session.remote.call("entries", pattern=pattern)
    elif base == "iE":
        # `iE` is the export table proper: defined GLOBAL/WEAK dynsym entries.
        # IDA has no notion of "exported", so this comes from the ELF dynsym.
        rows = session.remote.call("exports", pattern=pattern)
    else:
        raise AssertionError(f"unhandled info listing {token!r}")

    if as_json:
        return [to_json(rows)]

    formatter = {
        "ii": fmt_listing.format_imports,
        "is": fmt_listing.format_symbols,
        "iz": fmt_listing.format_strings,
        "izz": fmt_listing.format_strings,
        "ir": fmt_listing.format_relocations,
        "ie": fmt_listing.format_entries,
        "iE": fmt_listing.format_symbols,
    }[base]
    return with_more(formatter(rows, session), meta)


@command(
    "i[hH]",
    usage="[*jq]",
    summary="ELF file header",
    detail=HEADER_DETAIL,
    json_suffix=True,
    suffixes=frozenset({"", "j", "q", "*"}),
    suffix_label="information command",
    suffix_help="ih?",
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


@command(
    "iD",
    usage="[lang] sym",
    summary="demangle a symbol",
    detail=[("iD", "[lang] sym", "demangle a symbol (default language from bin.lang)")],
    json_suffix=True,
    suffixes=frozenset({"", "j"}),
    suffix_label="information command",
    suffix_help="i?",
)
def demangle_symbol(session: Session, statement: Statement) -> list[str]:
    """``iD [lang] sym`` -- demangle one symbol.

    With one argument the language comes from ``e bin.lang`` (r2's default is
    ``c``, which r2 does not demangle with).  The JSON form always carries
    ``lang``/``mangled`` and either ``demangled`` or r2's ``error`` string.
    """
    words = statement.argv
    as_json = statement.cmd == "iDj"
    if not words:
        raise UsageError("iD needs a symbol (see i?)")

    if len(words) == 1:
        lang = session.config.get_str("bin.lang") or "c"
        symbol = words[0]
    else:
        lang = words[0]
        symbol = " ".join(words[1:])

    lang = _DEMANGLE_ALIASES.get(lang, lang)
    # r2's default language is "c" (the file's own language); it is not a
    # demangler plugin but is accepted, so `iD _Z3foov` still works.
    if lang != "c" and lang not in DEMANGLE_LANGUAGES:
        supported = ", ".join(DEMANGLE_LANGUAGES)
        raise UsageError(f"iD: unsupported language {lang!r}; supported: {supported}")

    payload = session.remote.call("demangle", symbol=symbol)
    demangled = payload.get("demangled")
    if as_json:
        row: dict[str, Any] = {"lang": lang, "mangled": symbol}
        if demangled:
            row["demangled"] = demangled
        else:
            row["error"] = "Cannot demangle string"
        return [to_json(row)]
    if not demangled:
        raise UsageError("Cannot demangle string")
    return [demangled]


@command(
    "ia",
    usage="[j]",
    summary="list the architectures found in the file",
    detail=[("ia", "", "architectures found in the file"), ("iaj", "", "architectures as JSON")],
    json_suffix=True,
    suffixes=frozenset({"", "j"}),
    suffix_label="information command",
    suffix_help="i?",
)
def architectures(session: Session, statement: Statement) -> list[str]:
    """``ia``/``iaj`` -- the file's arch(es).

    r2 prints a hidden-header table: ``nth  offset  size  arch_bits
    [abi=...] [machine=...]``; the JSON form nests the rows under ``bins``.
    """
    rows = session.remote.call("archs")
    if statement.cmd.endswith("j"):
        return [to_json({"bins": rows})]

    size_width = max([4, *(len(str(int(row["size"]))) for row in rows)])
    lines = []
    for index, row in enumerate(rows):
        arch = f"{row['arch']}_{int(row['bits'])}"
        if row.get("abi"):
            arch += f" abi={row['abi']}"
        if row.get("machine"):
            arch += f" machine={row['machine']}"
        size = str(int(row["size"]))
        lines.append(
            f"{index:<3} 0x{int(row['offset']):08x} {size:<{size_width}} {arch}".rstrip()
        )
    return lines


@command(
    "il",
    usage="[jq]",
    summary="list the libraries the file needs",
    detail=[
        ("il", "", "needed libraries"),
        ("ilj", "", "needed libraries as JSON"),
        ("ilq", "", "needed libraries, names only"),
    ],
    json_suffix=True,
    suffixes=frozenset({"", "j", "q"}),
    suffix_label="information command",
    suffix_help="i?",
)
def libraries(session: Session, statement: Statement) -> list[str]:
    """``il``/``ilj`` -- ``DT_NEEDED`` entries, one per line like r2."""
    rows = session.remote.call("libs")
    if statement.cmd == "ilj":
        return [to_json(rows)]
    return list(rows)


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
