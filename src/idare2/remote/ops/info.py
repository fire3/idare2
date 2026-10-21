"""File/segment/symbol listing operations backing the ``i`` command family."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op
from idare2.remote.elf import ElfFile, load_elf

#: IDA's auto-generated ("dummy") name prefixes.  A database whose names are all
#: dummy has been stripped -- which is what ``iI``'s ``stripped`` key reports.
_DUMMY_PREFIXES = (
    "sub_",
    "loc_",
    "locret_",
    "off_",
    "seg_",
    "asc_",
    "byte_",
    "word_",
    "dword_",
    "qword_",
    "oword_",
    "xmmword_",
    "ymmword_",
    "zmmword_",
    "flt_",
    "dbl_",
    "tbyte_",
    "packreal_",
    "stru_",
    "unk_",
    "algn_",
    "def_",
    "jpt_",
    "custdata_",
    "nullsub_",
    "unknown_libname_",
    "j_",
    "nullsub_",
)

_MACHINE = {
    "arm": "ARM",
    "aarch64": "ARM",
    "x86": "Intel 80386",
    "metapc": "Intel 80386",
    "mips": "MIPS",
    "mipsb": "MIPS",
    "mipsl": "MIPS",
    "ppc": "PowerPC",
    "powerpc": "PowerPC",
    "riscv": "RISC-V",
    "sh": "SuperH",
    "m68k": "Motorola 68000",
}


def _is_dummy(name: str) -> bool:
    return name.startswith(_DUMMY_PREFIXES)


@op("file_info")
def file_info(db: Any) -> dict[str, Any]:
    """Everything ``iI`` prints, plus the keys the banner needs."""
    import ida_ida
    import ida_nalt

    arch = db.architecture or "unknown"
    bits = db.bitness or 0
    fmt = (db.format or "unknown").lower()
    bintype = fmt.split()[0].rstrip(",")
    names = list(db.names.get_all())
    has_real_symbol = any(not _is_dummy(name) for _, name in names)
    import_count = sum(1 for _ in db.imports.get_all_imports())

    try:
        os_name = ida_ida.inf_get_osname() or "unknown"
    except Exception:
        os_name = "unknown"

    return {
        "path": db.path,
        "module": db.module,
        "arch": arch,
        "bits": bits,
        "baddr": helpers.base_address(db),
        "binsz": db.filesize,
        "bintype": bintype,
        "class": _elf_class(bintype, bits) or db.format,
        "compiler": _compiler_name(db),
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "machine": _MACHINE.get(arch.lower(), arch),
        "os": os_name.lower(),
        "lang": "c",
        "static": import_count == 0,
        "stripped": not has_real_symbol,
        "lsyms": has_real_symbol,
        "va": True,
        "md5": db.md5,
        "sha256": db.sha256,
        "crc32": db.crc32,
        "start_ip": helpers.start_ip(db),
        "minimum_ea": db.minimum_ea,
        "maximum_ea": db.maximum_ea,
        "execution_mode": str(db.execution_mode),
        "linenum": _has_line_info(ida_nalt),
        "function_count": _count(db.functions.get_all()),
        "symbol_count": len(names),
        "import_count": import_count,
    }


def _elf_class(bintype: str, bits: int) -> str | None:
    if bintype == "elf":
        return f"ELF{bits}" if bits else None
    if bintype.startswith("portable") or bintype == "pe":
        return "PE32+" if bits == 64 else "PE32"
    if bintype == "mach0":
        return "MACH064" if bits == 64 else "MACH0"
    return None


def _has_line_info(ida_nalt: Any) -> bool:
    try:
        return bool(ida_nalt.get_ida_hdr() is not None)
    except Exception:
        return False


def _compiler_name(db: Any) -> str | None:
    try:
        return getattr(db.compiler_information, "name", None) or None
    except Exception:
        return None


def _count(iterator: Any) -> int:
    total = 0
    for _ in iterator:
        total += 1
    return total


@op("header_fields")
def header_fields(db: Any) -> dict[str, Any]:
    """ELF file header rows (``ih``/``iH``).

    IDA keeps the parsed header in its loader structures, but the field layout
    radare2 prints (offset, size, ``pf`` format per field) belongs to the bin
    plugin.  The original input file is therefore read with :mod:`elf`, the
    same way ``is``/``ir`` recover information IDA discards.
    """
    elf = _elf_for(db)
    if elf is None:
        helpers.fail(
            protocol.NOT_FOUND,
            "the header listings need the original ELF input file, which is "
            "missing or not an ELF",
        )
    return {"bits": elf.bits, "fields": elf.header_rows()}


@op("segments")
def segments(db: Any) -> list[dict[str, Any]]:
    """Segment table (``iS``)."""
    import ida_loader

    out: list[dict[str, Any]] = []
    for index, segment in enumerate(db.segments.get_all()):
        start = int(segment.start_ea)
        end = int(segment.end_ea)
        try:
            # IDA 9.5 no longer has ida_bytes.get_filoff; the loader owns the
            # address-to-file-offset mapping.
            paddr: int | None = int(ida_loader.get_fileregion_offset(start))
        except Exception:
            paddr = None
        if paddr is not None and paddr < 0:
            paddr = None
        out.append(
            {
                "nth": index,
                "name": db.segments.get_name(segment) or "",
                "paddr": paddr,
                "vaddr": start,
                "vsize": end - start,
                "size": (end - start) if paddr is not None else 0,
                "perm": _perm(int(getattr(segment, "perm", 0))),
                "type": _seg_type(db, segment),
                "class": db.segments.get_class(segment) or "",
                "bitness": db.segments.get_bitness(segment),
            }
        )
    return out


def _perm(bits: int) -> str:
    """IDA's SEGPERM bits to r2's ``-rwx`` form."""
    read = bool(bits & 4)
    write = bool(bits & 2)
    execute = bool(bits & 1)
    return ("r" if read else "-") + ("w" if write else "-") + ("x" if execute else "-")


def _seg_type(db: Any, segment: Any) -> str:
    try:
        import ida_segment

        seg = ida_segment.getseg(segment.start_ea)
        if seg is None:
            return ""
        return "NOBITS" if seg.type == ida_segment.SEG_NOBITS else "PROGBITS"
    except Exception:
        return ""


@op("imports")
def imports(
    db: Any, pattern: str | None = None, offset: int = 0, count: int | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Import table (``ii``).

    Paginated exactly like ``symbols``/``strings``: the client passes
    ``offset``/``count`` for ``ii``/``iij``, so a handler that does not accept
    them fails the dispatcher's ``signature.bind`` before it ever runs.
    """
    predicate = helpers.name_filter(pattern)
    elf = _elf_for(db)

    def make() -> Iterator[dict[str, Any]]:
        if elf is not None:
            for row in elf.import_rows():
                if predicate(row["name"]):
                    yield row
            return
        for item in db.imports.get_all_imports():
            name = item.name or ""
            if not predicate(name):
                continue
            address = int(item.address)
            yield {
                "ordinal": int(item.ordinal),
                "ea": address,
                "vaddr": address,
                "bind": "GLOBAL",
                "type": "FUNC",
                "lib": item.module_name or "",
                "name": name,
            }

    return helpers.paged(make, offset, count)


@op("entries")
def entries(db: Any, pattern: str | None = None) -> list[dict[str, Any]]:
    """Entry points and exports (``ie``, ``iE``)."""
    predicate = helpers.name_filter(pattern)
    out = []
    for item in db.entries.get_all():
        name = item.name or ""
        if not predicate(name):
            continue
        out.append(
            {
                "ea": int(item.address),
                "name": name,
                "ordinal": int(item.ordinal),
                "forwarder": item.forwarder_name or None,
            }
        )
    return out


@op("relocations")
def relocations(db: Any) -> list[dict[str, Any]]:
    """Relocation table (``ir``)."""
    elf = _elf_for(db)
    return list(elf.reloc_rows()) if elf is not None else []


@op("symbols")
def symbols(
    db: Any, pattern: str | None = None, offset: int = 0, count: int | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Symbol table (``is``)."""
    predicate = helpers.name_filter(pattern)
    elf = _elf_for(db)

    def make() -> Iterator[dict[str, Any]]:
        if elf is not None:
            for row in elf.symbol_rows():
                if predicate(row["name"]):
                    yield row
            return
        segments = _segments_or_none(db)
        for ea, name in db.names.get_all():
            if not predicate(name):
                continue
            address = int(ea)
            paddr, _section = _locate(segments, address) if segments else (None, "unknown")
            yield {
                "ordinal": address,
                "ea": address,
                "paddr": paddr,
                "vaddr": address,
                "bind": "GLOBAL",
                "type": "FUNC",
                "size": 0,
                "lib": "",
                "name": name,
                "demangled": "",
            }

    return helpers.paged(make, offset, count)


@op("strings")
def strings(
    db: Any,
    pattern: str | None = None,
    offset: int = 0,
    count: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """String table (``iz``)."""
    predicate = helpers.name_filter(pattern)
    elf = _elf_for(db)
    segments = None if elf is not None else _segment_index(db)

    def make() -> Iterator[dict[str, Any]]:
        for item in db.strings.get_all():
            row = _string_row(item, elf, segments)
            if row is None or not predicate(row["text"]):
                continue
            yield row

    return helpers.paged(make, offset, count)


def _string_row(
    item: Any,
    elf: ElfFile | None,
    segments: list[tuple[int, int, str, int | None]] | None,
) -> dict[str, Any] | None:
    """One ``iz`` row, or ``None`` when IDA cannot render the literal."""
    contents = item.contents
    if contents is None:
        return None
    text = contents.decode("utf-8", errors="replace")
    ea = int(item.address)
    if elf is not None:
        paddr, section = elf.locate(ea)
    elif segments is not None:
        paddr, section = _locate(segments, ea)
    else:
        paddr, section = ea, "unknown"
    return {
        "ea": ea,
        "paddr": paddr,
        "section": section,
        # r2's `len` is the character count; `size` is the bytes on disk
        # including the terminator, which IDA stores in .length.
        "length": len(text),
        "size": int(item.length),
        "type": _string_type(item),
        "encoding": _string_encoding(item),
        "text": text,
    }


def _string_type(item: Any) -> str:
    """Type name of a string, tolerant of codes ida-domain's enum rejects.

    ``StringItem.type`` evaluates ``StringType(get_str_type_code(internal))``,
    and an ``IntEnum`` raises ``ValueError`` for any value outside its members
    -- ``16 is not a valid StringType``.  Decompiling with ``pdc`` can leave
    such a string behind, and without this guard one odd literal took the whole
    ``iz`` listing down with it, permanently, across sessions.
    """
    try:
        return str(item.type)
    except ValueError:
        return f"0x{int(getattr(item, 'internal_type', 0)):x}"


def _string_encoding(item: Any) -> str:
    """Encoding name; same tolerance as :func:`_string_type`."""
    try:
        return item.encoding or ""
    except (ValueError, TypeError):
        return ""


def _segment_index(db: Any) -> list[tuple[int, int, str, int | None]]:
    """(vaddr_start, vaddr_end, name, paddr_base) for every segment.

    Built once per ``iz`` call: mapping each string through a per-address IDA
    call would be thousands of round trips into the loader.
    """
    import ida_loader

    out: list[tuple[int, int, str, int | None]] = []
    for segment in db.segments.get_all():
        start = int(segment.start_ea)
        try:
            paddr = int(ida_loader.get_fileregion_offset(start))
        except Exception:
            paddr = -1
        out.append(
            (
                start,
                int(segment.end_ea),
                db.segments.get_name(segment) or "",
                paddr if paddr >= 0 else None,
            )
        )
    return out


def _segments_or_none(db: Any) -> list[tuple[int, int, str, int | None]] | None:
    """Segment index for non-ELF inputs, or ``None`` when IDA is unavailable."""
    try:
        return _segment_index(db)
    except Exception:
        return None


def _elf_for(db: Any) -> ElfFile | None:
    """The input file's ELF metadata, when the database came from ELF."""
    try:
        import ida_nalt

        path = ida_nalt.get_input_file_path()
    except Exception:
        return None
    if not path:
        return None
    return load_elf(path)


def _locate(
    segments: list[tuple[int, int, str, int | None]], ea: int
) -> tuple[int, str]:
    for start, end, name, paddr in segments:
        if start <= ea < end:
            if paddr is None:
                return ea, name
            return paddr + (ea - start), name
    return ea, "unknown"


@op("set_name", writes=True)
def set_name(db: Any, ea: int, name: str) -> dict[str, Any]:
    """Rename the location at ``ea`` (``f name @ addr``, ``afn``)."""
    if not name:
        helpers.fail(protocol.BAD_ARGS, "a name must not be empty")
    if not db.names.set_name(ea, name):
        helpers.fail(protocol.IDA_ERROR, f"IDA refused to name 0x{ea:x} {name!r}")
    return {"ea": ea, "name": name}


@op("delete_name", writes=True)
def delete_name(db: Any, ea: int) -> dict[str, Any]:
    """Remove the name at ``ea`` (``f-``)."""
    db.names.delete(ea)
    return {"ea": ea}
