"""Listing renderers: file info, segments, functions, symbols, strings.

The tables use r2's shape (header row, then a ``―`` rule, then rows) with
columns padded to their widest cell.  Exact inter-column padding differs from
r2's table printer in places; the parity tests normalise whitespace runs rather
than chase byte-identical alignment.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from idare2.fmt import addr_width, fmt_addr, human_size, truth

#: r2 underlines table headers with U+2015 HORIZONTAL BAR, not ASCII '-'.
RULE = "―"


def table(headers: Sequence[str], rows: Iterable[Sequence[str]], *, right: Sequence[int] = ()) -> list[str]:
    """Render a header + rule + rows table with padded columns."""
    materialised = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in materialised:
        for index, cell in enumerate(row[: len(widths)]):
            widths[index] = max(widths[index], len(cell))

    def render(cells: Sequence[str]) -> str:
        parts = []
        for index, cell in enumerate(cells):
            if index == len(widths) - 1:
                parts.append(cell)
                break
            parts.append(cell.rjust(widths[index]) if index in right else cell.ljust(widths[index]))
        return " ".join(parts).rstrip()

    lines = [render(list(headers)), RULE * sum(widths) + " " * (len(widths) - 1)]
    lines.extend(render(row) for row in materialised)
    return lines


def format_info(info: dict[str, Any], session: Any) -> list[str]:
    """``iI`` -- r2 prints ``key`` padded to nine columns, then the value."""
    order = (
        ("arch", lambda v: v),
        ("baddr", lambda v: fmt_addr(v, addr_width(info.get("bits"))) if v else "0x0"),
        ("binsz", lambda v: str(v)),
        ("bintype", lambda v: v),
        ("bits", lambda v: str(v)),
        ("canary", lambda v: "unknown"),
        ("class", lambda v: v),
        ("compiler", lambda v: v),
        ("endian", lambda v: v),
        ("havecode", lambda v: "true"),
        ("lang", lambda v: v),
        ("linenum", lambda v: truth(v)),
        ("lsyms", lambda v: truth(v)),
        ("machine", lambda v: v),
        ("os", lambda v: v),
        ("static", lambda v: truth(v)),
        ("stripped", lambda v: truth(v)),
        ("va", lambda v: truth(v)),
        ("humansz", lambda v: human_size(int(v)) if v else "-"),
        ("md5", lambda v: v or ""),
        ("sha256", lambda v: v or ""),
    )
    lines = []
    for key, render in order:
        value = info.get(key)
        if value is None or value == "":
            continue
        lines.append(f"{key.ljust(9)}{render(value)}")
    return lines


def format_segments(segments: list[dict[str, Any]], session: Any) -> list[str]:
    """``iS``."""
    width = addr_width(session.info.get("bits"))
    headers = ("nth", "paddr", "size", "vaddr", "vsize", "perm", "type", "name")
    rows = []
    for segment in segments:
        paddr = segment.get("paddr")
        rows.append(
            [
                str(segment["nth"]),
                fmt_addr(paddr, width) if paddr is not None else "----------",
                f"0x{int(segment['size']):x}",
                fmt_addr(int(segment["vaddr"]), width),
                f"0x{int(segment['vsize']):x}",
                segment["perm"],
                segment["type"] or segment.get("class") or "",
                segment["name"],
            ]
        )
    return table(headers, rows)


def format_sections(
    sections: list[dict[str, Any]],
    session: Any,
    *,
    hash_name: str | None = None,
) -> list[str]:
    """``iS``/``iSS``/``iSh`` -- ELF sections or memory maps."""
    width = addr_width(session.info.get("bits"))
    headers = ["nth", "paddr", "size", "vaddr", "vsize", "perm", "flags"]
    if hash_name:
        headers.append(hash_name)
    headers.extend(["type", "name"])
    rows = []
    for section in sections:
        paddr = section.get("paddr")
        perm = str(section.get("perm") or "----")
        if len(perm) == 3:  # IDA's SEGPERM form, used by the non-ELF fallback
            perm = "-" + perm
        row = [
            str(section.get("nth", "")),
            fmt_addr(int(paddr), width) if paddr is not None else "----------",
            f"0x{int(section.get('size') or 0):x}",
            fmt_addr(int(section.get("vaddr") or 0), width),
            f"0x{int(section.get('vsize') or 0):x}",
            perm,
            f"0x{int(section.get('flags') or 0):x}",
        ]
        if hash_name:
            row.append(str(section.get("hash") or ""))
        row.extend([str(section.get("type") or ""), str(section.get("name") or "")])
        rows.append(row)
    return table(headers, rows, right=(2, 4))


def section_json(sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The ``iSj`` object shape, in r2's key order."""
    keys = ("name", "size", "vsize", "type", "perm", "flags", "paddr", "vaddr")
    return [{key: section.get(key) for key in keys} for section in sections]


def format_functions(functions: list[dict[str, Any]], session: Any) -> list[str]:
    """``afl`` -- address, basic blocks, size, name."""
    width = addr_width(session.info.get("bits"))
    return [
        f"{fmt_addr(int(func['ea']), width)} {func['nbbs']:>5} {func['size']:>6} {func['name']}"
        for func in functions
    ]


def format_symbols(symbols: list[dict[str, Any]], session: Any) -> list[str]:
    """``is`` -- nth/paddr/vaddr/bind/type/size/lib/name/demangled."""
    width = addr_width(session.info.get("bits"))
    headers = ("nth", "paddr", "vaddr", "bind", "type", "size", "lib", "name", "demangled")
    rows = []
    for symbol in symbols:
        paddr = symbol.get("paddr")
        vaddr = symbol.get("vaddr", symbol.get("ea", 0))
        rows.append(
            [
                str(symbol.get("ordinal", symbol.get("ea", 0))),
                fmt_addr(int(paddr), width) if paddr is not None else "----------",
                fmt_addr(int(vaddr), width) if vaddr is not None else "----------",
                symbol.get("bind") or "NONE",
                symbol.get("type") or "NONE",
                str(symbol.get("size", 0)),
                symbol.get("lib") or "",
                symbol["name"],
                symbol.get("demangled") or "",
            ]
        )
    return table(headers, rows)


def format_imports(imports: list[dict[str, Any]], session: Any) -> list[str]:
    """``ii`` -- nth/vaddr/bind/type/lib/name."""
    width = addr_width(session.info.get("bits"))
    headers = ("nth", "vaddr", "bind", "type", "lib", "name")
    rows = []
    for item in imports:
        vaddr = item.get("vaddr", item.get("ea", 0))
        rows.append(
            [
                str(item.get("ordinal", 0)),
                fmt_addr(int(vaddr), width) if vaddr is not None else "----------",
                item.get("bind") or "NONE",
                item.get("type") or "NONE",
                item.get("lib", item.get("module", "")) or "",
                item["name"],
            ]
        )
    return table(headers, rows)


def format_entries(entries: list[dict[str, Any]], session: Any) -> list[str]:
    """``ie`` / ``iE``."""
    width = addr_width(session.info.get("bits"))
    out = []
    for item in entries:
        line = f"{item['ordinal']:>5} {fmt_addr(int(item['ea']), width)} {item['name']}"
        if item.get("forwarder"):
            line += f" -> {item['forwarder']}"
        out.append(line)
    return out


def format_relocations(relocations: list[dict[str, Any]], session: Any) -> list[str]:
    """``ir`` -- vaddr/paddr/type/ntype/name."""
    width = addr_width(session.info.get("bits"))
    headers = ("vaddr", "paddr", "type", "ntype", "name")
    rows = []
    for reloc in relocations:
        paddr = reloc.get("paddr")
        rows.append(
            [
                fmt_addr(int(reloc["vaddr"]), width),
                fmt_addr(int(paddr), width) if paddr is not None else "----------",
                reloc.get("type") or "UNKNOWN",
                str(reloc.get("ntype", 0)),
                reloc.get("name") or "",
            ]
        )
    return table(headers, rows)


def format_strings(strings: list[dict[str, Any]], session: Any) -> list[str]:
    """``iz`` -- r2's nth/paddr/vaddr/len/size/section/type/string table.

    ``paddr`` is derived from ``vaddr`` using the containing segment, because
    IDA stores the string's virtual address and the segment table already knows
    the mapping; a round trip per string would be far more expensive.
    """
    width = addr_width(session.info.get("bits"))
    headers = ("nth", "paddr", "vaddr", "len", "size", "section", "type", "string")
    rows = []
    for index, item in enumerate(strings):
        vaddr = int(item["ea"])
        rows.append(
            [
                str(index),
                fmt_addr(item.get("paddr", vaddr), width),
                fmt_addr(vaddr, width),
                str(item.get("length", 0)),
                str(item.get("size", 0)),
                item.get("section", "") or "unknown",
                "ascii",
                item["text"],
            ]
        )
    return table(headers, rows)


#: ``iH``'s value renderings.  ``Type``/``Machine`` print as 4-digit hex and
#: the sizes/counts as decimal, although the ``ih`` field table calls them all
#: ``w``; the two plugins (``headersNN`` vs ``fields``) disagree on purpose.
_HEADER_DECIMAL = frozenset(
    {"EhSize", "PhentSize", "PhNum", "ShentSize", "ShNum", "ShrStrndx"}
)
_HEADER_HALF_HEX = frozenset({"Type", "Machine"})
_HEADER_NAMES = {"ELF": None, "EntryPoint": "Entrypoint"}


def format_header(fields: list[dict[str, Any]], bits: int) -> list[str]:
    """``iH`` -- radare2's ``headersNN``: offset, field name, raw value.

    32-bit files label the magic row ``ELF MAGIC``; 64-bit files ``ELF64``.
    """
    label = "ELF64" if int(bits) == 64 else "ELF MAGIC"
    lines = []
    for field in fields:
        name = _HEADER_NAMES.get(field["name"], field["name"])
        name = label if name is None else name
        value = int(field.get("value") or 0)
        if name in _HEADER_DECIMAL:
            rendered = str(value)
        elif name in _HEADER_HALF_HEX:
            rendered = f"0x{value:04x}"
        else:
            rendered = f"0x{value:08x}"
        lines.append(f"0x{int(field['vaddr']):08x}  {name:<12}{rendered}")
    return lines


def format_header_fields(fields: list[dict[str, Any]]) -> list[str]:
    """``ih`` -- vaddr, paddr, value, field name (all values as hex)."""
    return [
        f"0x{int(field['vaddr']):08x} 0x{int(field['paddr']):08x} "
        f"0x{int(field.get('value') or 0):08x} {field['name']}"
        for field in fields
    ]


def format_header_quiet(fields: list[dict[str, Any]]) -> list[str]:
    """``ihq`` -- vaddr, value, field name."""
    return [
        f"0x{int(field['vaddr']):08x} 0x{int(field.get('value') or 0):08x} {field['name']}"
        for field in fields
    ]


def format_header_radare(fields: list[dict[str, Any]]) -> list[str]:
    """``ih*`` / ``iH*`` -- the flags radare2's ``bin_fields`` emits.

    One flag per field (``header.<name>``), plus ``header.<name>.value`` when
    the field is non-zero and a ``Cd4``/``Cd8`` data definition sized like it.
    """
    lines = ["'fs+header"]
    for field in fields:
        name = field["name"]
        vaddr = int(field["vaddr"])
        value = int(field.get("value") or 0)
        lines.append(f"'f header.{name} 1 0x{vaddr:08x}")
        if value and value != 0xFFFFFFFFFFFFFFFF:
            lines.append(f"'f header.{name}.value 1 0x{value:08x}")
        size = int(field.get("size") or 0)
        if size == 8:
            lines.append(f"'@0x{vaddr:x}'Cd8")
        elif size == 4:
            lines.append(f"'@0x{vaddr:x}'Cd4")
        fmt = field.get("format") or ""
        if fmt:
            lines.append(f"'pf.{name} {fmt}")
    lines.append("'fs-")
    return lines


def format_saved(_payload: Any, _session: Any) -> list[str]:
    return []


def format_databases(rows: list[Any], _session: Any) -> list[str]:
    """``L`` / ``--sessions``."""
    headers = ("record-id", "backend", "pid", "status", "path")
    body = [[row.record_id, row.backend, str(row.pid), row.status, row.path] for row in rows]
    if not body:
        return ["no registered Nexus databases"]
    return table(headers, body)


def format_truncation(meta: dict[str, Any] | None) -> list[str]:
    """r2's ``[+more; resume with -o N]`` hint, printed after a cut page."""
    if not meta or not meta.get("truncated"):
        return []
    return [f"[+more; resume with -o {meta['next_offset']}]"]
