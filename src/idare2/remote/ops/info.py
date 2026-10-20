"""File/segment/symbol listing operations backing the ``i`` command family."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from idare2 import protocol
from idare2.remote import helpers
from idare2.remote.dispatch import op

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
        "baddr": db.base_address,
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
        "start_ip": db.start_ip,
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

    def make() -> Iterator[dict[str, Any]]:
        for item in db.imports.get_all_imports():
            name = item.name or ""
            if not predicate(name):
                continue
            yield {
                "ea": int(item.address),
                "name": name,
                "module": item.module_name or "",
                "ordinal": int(item.ordinal),
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


@op("symbols")
def symbols(
    db: Any, pattern: str | None = None, offset: int = 0, count: int | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Symbol table (``is``)."""
    predicate = helpers.name_filter(pattern)

    def make() -> Iterator[dict[str, Any]]:
        for ea, name in db.names.get_all():
            if predicate(name):
                yield {"ea": int(ea), "name": name}

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
    segments = _segment_index(db)

    def make() -> Iterator[dict[str, Any]]:
        for item in db.strings.get_all():
            contents = item.contents
            if contents is None:
                continue
            text = contents.decode("utf-8", errors="replace")
            if not predicate(text):
                continue
            ea = int(item.address)
            paddr, section = _locate(segments, ea)
            yield {
                "ea": ea,
                "paddr": paddr,
                "section": section,
                # r2's `len` is the character count; `size` is the bytes on
                # disk including the terminator, which IDA stores in .length.
                "length": len(text),
                "size": int(item.length),
                "type": str(item.type),
                "encoding": item.encoding,
                "text": text,
            }

    return helpers.paged(make, offset, count)


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
