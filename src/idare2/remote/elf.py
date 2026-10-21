"""Minimal ELF reader for the ``iz``/``ii``/``is`` listings.

IDA's loader view has no section table and no symbol binding/type/size
metadata, while radare2 prints both.  The handlers therefore read the original
input file (``ida_nalt.get_input_file_path``) and use this module for the
fields IDA does not expose.

Only what the three listings need is parsed: the section and program headers,
and the entries of ``SHT_DYNSYM``/``SHT_SYMTAB``.  Parsing is lazy at the file
level (seek/read per table), so opening a large firmware image does not copy
the whole binary into memory.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

PT_LOAD = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHF_ALLOC = 0x2

SHN_UNDEF = 0
SHN_ABS = 0xFFF1

EM_ARM = 40
EM_AARCH64 = 183

R_ARM_JUMP_SLOT = 22

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_NUM = 3
STB_LOOS = 10
STB_HIOS = 12
STB_LOPROC = 13
STB_HIPROC = 15

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_NUM = 7
STT_LOOS = 10
STT_HIOS = 12
STT_LOPROC = 13
STT_HIPROC = 15

_BIND = {
    STB_LOCAL: "LOCAL",
    STB_GLOBAL: "GLOBAL",
    STB_WEAK: "WEAK",
    STB_NUM: "NUM",
    STB_LOOS: "LOOS",
    STB_HIOS: "HIOS",
    STB_LOPROC: "LOPROC",
    STB_HIPROC: "HIPROC",
}

_TYPE = {
    STT_NOTYPE: "NOTYPE",
    STT_OBJECT: "OBJ",
    STT_FUNC: "FUNC",
    STT_SECTION: "SECT",
    STT_FILE: "FILE",
    STT_COMMON: "COMMON",
    STT_TLS: "TLS",
    STT_NUM: "NUM",
    STT_LOOS: "LOOS",
    STT_HIOS: "HIOS",
    STT_LOPROC: "LOPROC",
    STT_HIPROC: "HIPROC",
}


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass(frozen=True)
class Program:
    type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int


@dataclass(frozen=True)
class Symbol:
    index: int
    name: str
    bind: str
    type: str
    bind_code: int
    type_code: int
    visibility: int
    shndx: int
    value: int
    size: int
    table: str


class ElfFile:
    """The section/symbol view radare2's ELF plugin exposes."""

    def __init__(
        self,
        *,
        path: str,
        bits: int,
        endian: str,
        machine: int,
        file_size: int,
        sections: list[Section],
        programs: list[Program],
        dynsyms: list[Symbol],
        symtabs: list[Symbol],
    ) -> None:
        self.path = path
        self.bits = bits
        self.endian = endian
        self.machine = machine
        self.file_size = file_size
        self.sections = sections
        self.programs = programs
        self.dynsyms = dynsyms
        self.symtabs = symtabs
        loads = [program.vaddr & ~0xFFF for program in programs if program.type == PT_LOAD]
        self.baddr = min(loads) if loads else 0
        self.import_plt: dict[int, int] = {}

    # -- construction ------------------------------------------------------

    @classmethod
    def load(cls, path: str) -> ElfFile:
        with open(path, "rb") as handle:
            ident = handle.read(16)
            if len(ident) != 16 or ident[:4] != b"\x7fELF":
                raise ValueError("not an ELF file")
            bits = {1: 32, 2: 64}.get(ident[4])
            endian = {1: "<", 2: ">"}.get(ident[5])
            if bits is None or endian is None:
                raise ValueError("unsupported ELF class or endianness")

            if bits == 64:
                header = struct.unpack(endian + "HHIQQQIHHHHHH", handle.read(48))
                ph_format = endian + "IIQQQQQQ"
                sh_format = endian + "IIQQQQIIQQ"
                sym_format = endian + "IBBHQQ"
            else:
                header = struct.unpack(endian + "HHIIIIIHHHHHH", handle.read(36))
                ph_format = endian + "IIIIIIII"
                sh_format = endian + "IIIIIIIIII"
                sym_format = endian + "IIIBBH"

            (
                _e_type,
                machine,
                _version,
                _entry,
                phoff,
                shoff,
                _flags,
                _ehsize,
                phentsize,
                phnum,
                shentsize,
                shnum,
                shstrndx,
            ) = header

            programs = cls._read_programs(handle, phoff, phnum, phentsize, ph_format)
            sections = cls._read_sections(handle, shoff, shnum, shentsize, sh_format, shstrndx)
            dynsyms, symtabs = cls._read_symbols(handle, sections, bits, sym_format, machine)
            handle.seek(0, 2)
            file_size = handle.tell()

            result = cls(
                path=str(path),
                bits=bits,
                endian=endian,
                machine=machine,
                file_size=file_size,
                sections=sections,
                programs=programs,
                dynsyms=dynsyms,
                symtabs=symtabs,
            )
            result.import_plt = cls._read_import_plt(handle, result, endian)
        return result

    @staticmethod
    def _read_programs(
        handle: Any, phoff: int, phnum: int, entsize: int, fmt: str
    ) -> list[Program]:
        if not phoff or not phnum:
            return []
        size = struct.calcsize(fmt)
        entsize = entsize or size
        out: list[Program] = []
        for index in range(phnum):
            handle.seek(phoff + index * entsize)
            raw = handle.read(size)
            if len(raw) != size:
                break
            values = struct.unpack(fmt, raw)
            if len(values) == 8 and fmt.endswith("IIQQQQQQ"):
                # 64-bit: type, flags, offset, vaddr, paddr, filesz, memsz, align
                out.append(Program(*values))
            else:
                # 32-bit: type, offset, vaddr, paddr, filesz, memsz, flags, align
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = values
                out.append(
                    Program(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
                )
        return out

    @staticmethod
    def _read_sections(
        handle: Any,
        shoff: int,
        shnum: int,
        entsize: int,
        fmt: str,
        shstrndx: int,
    ) -> list[Section]:
        if not shoff or not shnum:
            return []
        size = struct.calcsize(fmt)
        entsize = entsize or size
        raw_sections: list[tuple[int, ...]] = []
        for index in range(shnum):
            handle.seek(shoff + index * entsize)
            raw = handle.read(size)
            if len(raw) != size:
                break
            raw_sections.append(struct.unpack(fmt, raw))
        if not raw_sections:
            return []

        names = b""
        if 0 <= shstrndx < len(raw_sections):
            sh = raw_sections[shstrndx]
            offset, length = sh[4], sh[5]
            handle.seek(offset)
            names = handle.read(length)

        out: list[Section] = []
        for index, values in enumerate(raw_sections):
            name_off = values[0]
            out.append(
                Section(
                    index=index,
                    name=_cstr(names, name_off),
                    type=values[1],
                    flags=values[2],
                    addr=values[3],
                    offset=values[4],
                    size=values[5],
                    link=values[6],
                    entsize=values[9],
                )
            )
        return out

    @staticmethod
    def _read_symbols(
        handle: Any,
        sections: list[Section],
        bits: int,
        fmt: str,
        machine: int,
    ) -> tuple[list[Symbol], list[Symbol]]:
        size = struct.calcsize(fmt)
        dynsyms: list[Symbol] = []
        symtabs: list[Symbol] = []
        for section in sections:
            if section.type not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if not (0 <= section.link < len(sections)):
                continue
            strings = _read_section(handle, sections[section.link])
            raw = _read_section(handle, section)
            entsize = section.entsize or size
            count = len(raw) // entsize
            table = "dynsym" if section.type == SHT_DYNSYM else "symtab"
            target = dynsyms if section.type == SHT_DYNSYM else symtabs
            # radare2 starts at index 1: entry zero is the reserved null symbol.
            for index in range(1, count):
                entry = raw[index * entsize : index * entsize + entsize]
                if len(entry) < size:
                    break
                values = struct.unpack(fmt, entry)
                if bits == 64:
                    name_off, info, other, shndx, value, sym_size = values
                else:
                    name_off, value, sym_size, info, other, shndx = values
                bind_code = info >> 4
                type_code = info & 0xF
                name = _cstr(strings, name_off)
                if type_code == STT_SECTION and not name and 0 <= shndx < len(sections):
                    name = sections[shndx].name
                if not name:
                    continue
                type_name = _TYPE.get(type_code, "UNKNOWN")
                if _is_special_arm(machine, name, bind_code, type_code, other & 0x3):
                    type_name = "SPCL"
                target.append(
                    Symbol(
                        index=index,
                        name=name,
                        bind=_BIND.get(bind_code, "UNKNOWN"),
                        type=type_name,
                        bind_code=bind_code,
                        type_code=type_code,
                        visibility=other & 0x3,
                        shndx=shndx,
                        value=value,
                        size=sym_size,
                        table=table,
                    )
                )
        return dynsyms, symtabs

    @staticmethod
    def _read_import_plt(handle: Any, elf: ElfFile, endian: str) -> dict[int, int]:
        """PLT stubs for ARM imports whose ``st_value`` is zero.

        radare2's ELF plugin derives an import address from the relocation and
        the GOT slot (which carries the PLT header address).  IDA has no such
        field in its import list, so parse it here for the two imports in a
        typical uClibc binary whose dynsym value is still zero.
        """
        if elf.machine != EM_ARM:
            return {}
        pltgot = _dynamic_value(handle, elf.sections, endian, elf.bits, 3)
        if pltgot is None:
            return {}
        out: dict[int, int] = {}
        for section in elf.sections:
            if section.type not in (SHT_REL, SHT_RELA):
                continue
            raw = _read_section(handle, section)
            size = 12 if elf.bits == 64 else 8
            entsize = section.entsize or size
            for offset in range(0, len(raw) - size + 1, entsize):
                if elf.bits == 64:
                    rel_offset, info = struct.unpack(endian + "QQ", raw[offset : offset + 16])
                    symbol_index = info >> 32
                    rel_type = info & 0xFFFFFFFF
                else:
                    rel_offset, info = struct.unpack(endian + "II", raw[offset : offset + 8])
                    symbol_index = info >> 8
                    rel_type = info & 0xFF
                if rel_type != R_ARM_JUMP_SLOT:
                    continue
                got_file_offset = elf.vaddr_to_paddr(rel_offset)
                if got_file_offset is None:
                    continue
                handle.seek(got_file_offset)
                stub = handle.read(4)
                if len(stub) != 4:
                    continue
                plt_header = struct.unpack(endian + "I", stub)[0]
                position = (rel_offset - pltgot - 12) // 4
                if position < 0:
                    continue
                out[symbol_index] = plt_header + position * 12 + 20
        return out

    # -- address mapping ---------------------------------------------------

    def vaddr_to_paddr(self, vaddr: int) -> int | None:
        """r2's ``v2p``: PT_LOAD file ranges, else allocated sections."""
        if self.programs:
            for program in self.programs:
                if program.type != PT_LOAD:
                    continue
                if program.vaddr <= vaddr < program.vaddr + program.filesz:
                    return program.offset + (vaddr - program.vaddr)
            return None
        for section in self.sections:
            if (
                section.flags & SHF_ALLOC
                and section.size
                and section.addr <= vaddr < section.addr + section.size
            ):
                return section.offset + (vaddr - section.addr)
        return None

    def paddr_to_vaddr(self, paddr: int) -> int | None:
        if self.programs:
            for program in self.programs:
                if program.type != PT_LOAD:
                    continue
                if program.offset <= paddr < program.offset + program.filesz:
                    return program.vaddr + (paddr - program.offset)
            return None
        for section in self.sections:
            if (
                section.flags & SHF_ALLOC
                and section.type != SHT_NOBITS
                and section.size
                and section.offset <= paddr < section.offset + section.size
            ):
                return section.addr + (paddr - section.offset)
        return None

    def section_at(self, vaddr: int) -> Section | None:
        for section in self.sections:
            if section.addr <= vaddr < section.addr + section.size:
                return section
        return None

    def locate(self, vaddr: int) -> tuple[int, str]:
        """``(paddr, section)`` for a string address."""
        paddr = self.vaddr_to_paddr(vaddr)
        section = self.section_at(vaddr)
        name = section.name if section and section.name else "unknown"
        return (paddr if paddr is not None else vaddr), name

    # -- listing rows ------------------------------------------------------

    def _symbol_row(self, symbol: Symbol, *, name: str | None = None, size: int | None = None) -> dict[str, Any]:
        vaddr = symbol.value
        paddr: int | None
        if symbol.shndx == SHN_ABS:
            paddr = None
            if symbol.type in ("FUNC", "OBJ"):
                offset = self.vaddr_to_paddr(vaddr)
                if offset is not None and offset < self.file_size:
                    paddr = offset
        else:
            offset = self.vaddr_to_paddr(vaddr)
            if offset is None:
                if symbol.shndx == SHN_UNDEF and vaddr == 0:
                    plt = self.import_plt.get(symbol.index)
                    if plt is None:
                        # r2 has no PLT address to offer for this import.
                        paddr = None
                        vaddr = None
                    else:
                        vaddr = plt
                        offset = self.vaddr_to_paddr(plt)
                        paddr = offset
                elif self.baddr and vaddr and vaddr < self.baddr:
                    # Some firmware symbol tables store section-relative file
                    # offsets.  r2's fill_symbol() reinterprets those as paddr.
                    paddr = vaddr
                    mapped = self.paddr_to_vaddr(vaddr)
                    vaddr = mapped if mapped is not None else vaddr
                else:
                    paddr = None
            else:
                paddr = offset
                mapped = self.paddr_to_vaddr(offset)
                if mapped is not None:
                    vaddr = mapped
        return {
            "ordinal": symbol.index,
            "ea": vaddr if vaddr is not None else symbol.value,
            "paddr": paddr,
            "vaddr": vaddr,
            "bind": symbol.bind,
            "type": symbol.type,
            "size": symbol.size if size is None else size,
            "lib": "",
            "name": symbol.name if name is None else name,
            "demangled": "",
        }

    def symbol_rows(self) -> Iterator[dict[str, Any]]:
        """Rows in ``is`` order: dynsym, symtab, then PLT imports."""
        for table in (self.dynsyms, self.symtabs):
            for symbol in table:
                if symbol.shndx == SHN_UNDEF:
                    continue
                yield self._symbol_row(symbol)
        for symbol in self.dynsyms:
            if symbol.shndx != SHN_UNDEF:
                continue
            yield self._symbol_row(symbol, name=f"imp.{symbol.name}", size=16)

    def import_rows(self) -> Iterator[dict[str, Any]]:
        """Rows in ``ii`` order: undefined entries of ``.dynsym``."""
        for symbol in self.dynsyms:
            if symbol.shndx != SHN_UNDEF:
                continue
            vaddr: int | None = symbol.value or self.import_plt.get(symbol.index)
            yield {
                "ordinal": symbol.index,
                "ea": symbol.value,
                "vaddr": vaddr,
                "bind": symbol.bind,
                "type": symbol.type,
                "lib": "",
                "name": symbol.name,
            }


def _read_section(handle: Any, section: Section) -> bytes:
    if section.type == SHT_NOBITS or section.size <= 0:
        return b""
    handle.seek(section.offset)
    return handle.read(section.size)


def _dynamic_value(
    handle: Any, sections: list[Section], endian: str, bits: int, tag: int
) -> int | None:
    """Read one ``DT_*`` value from ``SHT_DYNAMIC``."""
    fmt = endian + ("QQ" if bits == 64 else "II")
    size = struct.calcsize(fmt)
    for section in sections:
        if section.type != SHT_DYNAMIC:
            continue
        raw = _read_section(handle, section)
        entsize = section.entsize or size
        for offset in range(0, len(raw) - size + 1, entsize):
            entry_tag, value = struct.unpack(fmt, raw[offset : offset + size])
            if entry_tag == tag:
                return value
    return None


def _cstr(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _is_special_arm(machine: int, name: str, bind: int, typ: int, visibility: int) -> bool:
    if machine not in (EM_ARM, EM_AARCH64):
        return False
    if not name.startswith("$") or len(name) < 2:
        return False
    if name[1] not in "atdx":
        return False
    if len(name) > 2 and name[2] != ".":
        return False
    return typ == STT_NOTYPE and bind == STB_LOCAL and visibility == 0


@lru_cache(maxsize=4)
def _load_cached(path: str, _mtime_ns: int, _size: int) -> ElfFile:
    return ElfFile.load(path)


def load_elf(path: str | None) -> ElfFile | None:
    """Parse ``path`` as ELF, returning ``None`` for other formats/errors."""
    if not path:
        return None
    try:
        stat = Path(path).stat()
        return _load_cached(str(path), stat.st_mtime_ns, stat.st_size)
    except (OSError, ValueError, struct.error):
        return None
