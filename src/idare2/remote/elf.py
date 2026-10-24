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
PT_DYNAMIC = 2
PT_INTERP = 3
PT_PHDR = 6
PT_ARM_EXIDX = 0x70000001
PT_GNU_STACK = 0x6474E551
DT_NEEDED = 1
DT_STRTAB = 5
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

#: ``sh_type`` -> radare2's section type column.
SECTION_TYPES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFD: "VERDEF",
    0x6FFFFFFE: "VERNEED",
    0x6FFFFFFF: "VERSYM",
    # r2 leaves these processor-specific ARM types unnamed.
    0x70000001: "----",
    0x70000003: "----",
}

#: ``sh_type``/``p_type`` -> the fallback name when the section has none.
SECTION_NAMES_BY_TYPE = {
    11: ".dynsym",
    14: ".init_array",
    15: ".fini_array",
    0x70000001: ".ARM.exidx",
    0x6FFFFFF6: ".gnu.hash",
    0x6FFFFFFF: ".gnu.version",
    0x6FFFFFFD: ".gnu.version_d",
    0x6FFFFFFE: ".gnu.version_r",
}

#: ``p_type`` -> the map name radare2 uses for non-LOAD segments.
_PROGRAM_NAMES = {
    PT_PHDR: "PHDR",
    PT_INTERP: "INTERP",
    PT_DYNAMIC: "DYNAMIC",
    PT_GNU_STACK: "GNU_STACK",
    PT_ARM_EXIDX: "EXIDX",
}


def _PHDR_PERM(flags: int) -> str:
    """Program-header flags to r2's ``-rwx`` string."""
    return (
        "-"
        + ("r" if flags & 0x4 else "-")
        + ("w" if flags & 0x2 else "-")
        + ("x" if flags & 0x1 else "-")
    )

SHN_UNDEF = 0
SHN_ABS = 0xFFF1

EM_NONE = 0
EM_SPARC = 2
EM_386 = 3
EM_68K = 4
EM_MIPS = 8
EM_MIPS_RS3_LE = 10
EM_PPC = 20
EM_PPC64 = 21
EM_S390 = 22
EM_ARM = 40
EM_SH = 42
EM_SPARCV9 = 43
EM_X86_64 = 62
EM_AARCH64 = 183
EM_RISCV = 243

#: ``e_machine`` -> radare2's bin arch name (``Elf_(get_arch)``).
ARCH_NAMES = {
    EM_NONE: "null",
    EM_SPARC: "sparc",
    EM_386: "x86",
    EM_68K: "m68k",
    EM_MIPS: "mips",
    EM_MIPS_RS3_LE: "mips",
    EM_PPC: "ppc",
    EM_PPC64: "ppc",
    EM_S390: "s390",
    EM_ARM: "arm",
    EM_AARCH64: "arm",
    EM_SH: "sh",
    EM_SPARCV9: "sparc",
    EM_X86_64: "x86",
    EM_RISCV: "riscv",
}

#: ``e_machine`` -> radare2's machine description (``Elf_(get_machine_name)``).
MACHINE_NAMES = {
    EM_NONE: "No machine",
    EM_SPARC: "SUN SPARC",
    EM_386: "Intel 80386",
    EM_68K: "Motorola m68k family",
    EM_MIPS: "MIPS R3000",
    EM_MIPS_RS3_LE: "MIPS R3000 little-endian",
    EM_PPC: "PowerPC",
    EM_PPC64: "PowerPC 64-bit",
    EM_S390: "IBM S390",
    EM_ARM: "ARM",
    EM_SH: "Hitachi SH",
    EM_SPARCV9: "SPARC v9 64-bit",
    EM_X86_64: "AMD x86-64 architecture",
    EM_AARCH64: "ARM aarch64",
    EM_RISCV: "RISC V",
}

#: ARM ``e_flags`` EABI version bits and soft/8-bit float markers.
EF_ARM_EABIMASK = 0xFF000000
EF_ARM_BE8 = 0x00800000
EF_ARM_LE8 = 0x00400000

#: MIPS ``e_flags`` ABI bits (see ``is_mips_*`` in radare2's elf.c).
EF_MIPS_ABI = 0x0000F000
EF_MIPS_ABI_O32 = 0x00001000
EF_MIPS_ABI2 = 0x00000020
EF_MIPS_MICROMIPS = 0x02000000

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
class ElfHeader:
    """The ELF file header (``Elf_Ehdr``), as read from the input file."""

    ident: bytes
    type: int
    machine: int
    version: int
    entry: int
    phoff: int
    shoff: int
    flags: int
    ehsize: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int


#: radare2's ``bin_elf`` ``fields`` table: ``(name, offset, size, pf format)``.
#: The field order, offsets and formats are what ``ih``/``iH`` print, and the
#: ``pf`` rows embedded in ``ihj`` come from the same formats.
HEADER_FIELDS_32 = (
    ("ELF", 0x00, 4, "x"),
    ("Type", 0x10, 2, "w"),
    ("Machine", 0x12, 2, "w"),
    ("Version", 0x14, 4, "x"),
    ("EntryPoint", 0x18, 4, "x"),
    ("PhOff", 0x1C, 4, "x"),
    ("ShOff", 0x20, 4, "x"),
    ("Flags", 0x24, 4, "x"),
    ("EhSize", 0x28, 2, "w"),
    ("PhentSize", 0x2A, 2, "w"),
    ("PhNum", 0x2C, 2, "w"),
    ("ShentSize", 0x2E, 2, "w"),
    ("ShNum", 0x30, 2, "w"),
    ("ShrStrndx", 0x32, 2, "w"),
)

HEADER_FIELDS_64 = (
    ("ELF", 0x00, 4, "x"),
    ("Type", 0x10, 2, "w"),
    ("Machine", 0x12, 2, "w"),
    ("Version", 0x14, 4, "x"),
    ("EntryPoint", 0x18, 8, "q"),
    ("PhOff", 0x20, 8, "q"),
    ("ShOff", 0x28, 8, "q"),
    ("Flags", 0x30, 4, "x"),
    ("EhSize", 0x34, 2, "w"),
    ("PhentSize", 0x36, 2, "w"),
    ("PhNum", 0x38, 2, "w"),
    ("ShentSize", 0x3A, 2, "w"),
    ("ShNum", 0x3C, 2, "w"),
    ("ShrStrndx", 0x3E, 2, "w"),
)

#: ``UT64_MAX``, which r2 treats as "no value" for a field.
_NO_VALUE = 0xFFFFFFFFFFFFFFFF


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
    #: ``sh_info`` and ``sh_addralign`` (``iSh``).
    info: int = 0
    addralign: int = 0
    #: ``p_type`` when this is an ``.ARM.exidx`` section, else ``None``.
    exec_marker: int | None = None

    def perm(self) -> str:
        """r2's 4-column perm string for ELF sections (``-r--``)."""
        read = bool(self.flags & SHF_ALLOC) or self.type == SHT_NOBITS
        write = bool(self.flags & SHF_WRITE)
        execute = bool(self.flags & SHF_EXECINSTR)
        return (
            "-"
            + ("r" if read else "-")
            + ("w" if write else "-")
            + ("x" if execute else "-")
        )

    def type_name(self) -> str:
        return SECTION_TYPES.get(self.type, "")

    def r2_name(self) -> str:
        """The name radare2's ELF plugin reports for this section.

        r2 does not always use ``sh_name``: ``.ARM.exidx``, ``.dynsym`` and
        the array sections are renamed from ``sh_type``.
        """
        by_type = SECTION_NAMES_BY_TYPE.get(self.type)
        if by_type:
            return by_type
        return self.name or SECTION_NAMES_BY_TYPE.get(self.type, "")

    def vsize(self) -> int:
        return self.size


@dataclass(frozen=True)
class SectionHeader:
    """One entry of the ELF section-header table (``iSh``)."""

    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass(frozen=True)
class SectionInfo:
    """r2's ``Elf_(sections)`` columns that come straight from the header."""

    paddr: int
    vaddr: int
    size: int
    vsize: int
    perm: str
    flags: int
    type: int
    name: str


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
class Relocation:
    offset: int
    type: int
    symbol_index: int
    addend: int
    section: str


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
        header: ElfHeader,
        file_size: int,
        sections: list[Section],
        programs: list[Program],
        dynsyms: list[Symbol],
        symtabs: list[Symbol],
        libs: list[str],
    ) -> None:
        self.path = path
        self.bits = bits
        self.endian = endian
        self.header = header
        self.machine = header.machine
        self.file_size = file_size
        self.sections = sections
        self.programs = programs
        self.dynsyms = dynsyms
        self.symtabs = symtabs
        self.libs = libs
        self.dynsyms_by_index = {symbol.index: symbol for symbol in dynsyms}
        self.symtabs_by_index = {symbol.index: symbol for symbol in symtabs}
        loads = [program.vaddr & ~0xFFF for program in programs if program.type == PT_LOAD]
        self.baddr = min(loads) if loads else 0
        self.relocs: list[Relocation] = []
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
                e_type,
                machine,
                version,
                entry,
                phoff,
                shoff,
                flags,
                ehsize,
                phentsize,
                phnum,
                shentsize,
                shnum,
                shstrndx,
            ) = header

            programs = cls._read_programs(handle, phoff, phnum, phentsize, ph_format)
            sections = cls._read_sections(handle, shoff, shnum, shentsize, sh_format, shstrndx)
            dynsyms, symtabs = cls._read_symbols(handle, sections, bits, sym_format, machine)
            relocs = cls._read_relocations(handle, sections, bits, endian)
            libs = cls._read_needed(handle, sections, programs, bits, endian)
            handle.seek(0, 2)
            file_size = handle.tell()

            result = cls(
                path=str(path),
                bits=bits,
                endian=endian,
                header=ElfHeader(
                    ident=ident,
                    type=e_type,
                    machine=machine,
                    version=version,
                    entry=entry,
                    phoff=phoff,
                    shoff=shoff,
                    flags=flags,
                    ehsize=ehsize,
                    phentsize=phentsize,
                    phnum=phnum,
                    shentsize=shentsize,
                    shnum=shnum,
                    shstrndx=shstrndx,
                ),
                file_size=file_size,
                sections=sections,
                programs=programs,
                dynsyms=dynsyms,
                symtabs=symtabs,
                libs=libs,
            )
            result.relocs = relocs
            result.import_plt = cls._compute_import_plt(handle, result, endian, relocs)
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
                    info=values[7],
                    addralign=values[8],
                    exec_marker=(
                        PT_ARM_EXIDX if values[1] == 0x70000001 else None
                    ),
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
    def _read_needed(
        handle: Any,
        sections: list[Section],
        programs: list[Program],
        bits: int,
        endian: str,
    ) -> list[str]:
        """``DT_NEEDED`` entries in file order (``il``).

        Like radare2 (and the ELF ABI), the dynamic segment is authoritative:
        firmware images often strip the section table but keep ``PT_DYNAMIC``.
        The section form is only a fallback for files without the segment.
        """
        fmt = endian + ("QQ" if bits == 64 else "II")
        size = struct.calcsize(fmt)
        entries: list[tuple[int, int]] = []

        def parse(raw: bytes) -> None:
            for position in range(0, len(raw) - size + 1, size):
                tag, value = struct.unpack(fmt, raw[position : position + size])
                if tag == 0:  # DT_NULL terminates the array
                    break
                entries.append((tag, value))

        for program in programs:
            if program.type != PT_DYNAMIC or not program.filesz:
                continue
            handle.seek(program.offset)
            parse(handle.read(program.filesz))
        if not entries:
            for section in sections:
                if section.type == SHT_DYNAMIC:
                    parse(_read_section(handle, section))
        if not entries:
            return []

        strtab_vaddr = next((value for tag, value in entries if tag == DT_STRTAB), None)
        if strtab_vaddr is None:
            return []
        strtab_paddr = _map_vaddr(programs, sections, strtab_vaddr)
        if strtab_paddr is None:
            return []

        out: list[str] = []
        for tag, value in entries:
            if tag != DT_NEEDED:
                continue
            handle.seek(strtab_paddr + value)
            name = _cstr(handle.read(256), 0)
            if name:
                out.append(name)
        return out

    @staticmethod
    def _read_relocations(
        handle: Any, sections: list[Section], bits: int, endian: str
    ) -> list[Relocation]:
        out: list[Relocation] = []
        for section in sections:
            if section.type not in (SHT_REL, SHT_RELA):
                continue
            raw = _read_section(handle, section)
            rela = section.type == SHT_RELA
            if bits == 64:
                fmt = endian + ("QQq" if rela else "QQ")
            else:
                fmt = endian + ("IIi" if rela else "II")
            size = struct.calcsize(fmt)
            entsize = section.entsize or size
            for offset in range(0, len(raw) - size + 1, entsize):
                values = struct.unpack(fmt, raw[offset : offset + size])
                rel_offset, info = values[0], values[1]
                addend = values[2] if rela else 0
                if bits == 64:
                    symbol_index = info >> 32
                    rel_type = info & 0xFFFFFFFF
                else:
                    symbol_index = info >> 8
                    rel_type = info & 0xFF
                out.append(
                    Relocation(rel_offset, rel_type, symbol_index, addend, section.name)
                )
        return out

    @staticmethod
    def _compute_import_plt(
        handle: Any, elf: ElfFile, endian: str, relocs: list[Relocation]
    ) -> dict[int, int]:
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
        for reloc in relocs:
            if reloc.type != R_ARM_JUMP_SLOT:
                continue
            got_file_offset = elf.vaddr_to_paddr(reloc.offset)
            if got_file_offset is None:
                continue
            handle.seek(got_file_offset)
            stub = handle.read(4)
            if len(stub) != 4:
                continue
            plt_header = struct.unpack(endian + "I", stub)[0]
            position = (reloc.offset - pltgot - 12) // 4
            if position < 0:
                continue
            out[reloc.symbol_index] = plt_header + position * 12 + 20
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

    # -- iS / iSS ---------------------------------------------------------

    def _file_handle(self) -> Any:
        return open(self.path, "rb")

    def _file_size(self, section: Section) -> int:
        """Bytes present in the file, as r2 reports ``size`` for an image."""
        if section.type == SHT_NOBITS:
            return 0
        if section.flags & SHF_ALLOC:
            for program in self.programs:
                if program.type != PT_LOAD:
                    continue
                if program.offset <= section.offset < program.offset + program.filesz:
                    remaining = program.filesz - (section.offset - program.offset)
                    return min(section.size, max(remaining, 0))
        return section.size

    def _vsize(self, section: Section) -> int:
        """r2's image size: NOBITS keeps ``sh_size``, PROGBITS uses filesz."""
        if section.type == SHT_NOBITS:
            return section.size
        return self._file_size(section)

    def _paddr(self, section: Section) -> int:
        if section.type == SHT_NOBITS or not (section.flags & SHF_ALLOC):
            return section.offset
        for program in self.programs:
            if program.type != PT_LOAD:
                continue
            if program.vaddr <= section.addr < program.vaddr + program.memsz:
                return program.offset + (section.addr - program.vaddr)
        return section.offset

    def section_rows(self) -> list[dict[str, Any]]:
        """One row per section for ``iS`` (including the NULL header)."""
        rows: list[dict[str, Any]] = []
        for section in self.sections:
            rows.append(
                {
                    "nth": section.index,
                    "paddr": self._paddr(section),
                    "size": self._file_size(section),
                    "vaddr": section.addr,
                    "vsize": self._vsize(section),
                    "perm": section.perm(),
                    "flags": section.flags,
                    "type": section.type_name(),
                    "name": section.r2_name(),
                    "class": "",
                }
            )
        return rows

    def section_bytes(self, section: Section) -> bytes:
        """The section's on-disk bytes (NOBITS returns an empty string)."""
        if section.type == SHT_NOBITS or section.size <= 0:
            return b""
        if not (section.flags & SHF_ALLOC):
            with self._file_handle() as handle:
                handle.seek(section.offset)
                return handle.read(section.size)
        for program in self.programs:
            if program.type != PT_LOAD:
                continue
            if program.offset <= section.offset < program.offset + program.filesz:
                length = min(section.size, program.filesz - (section.offset - program.offset))
                with self._file_handle() as handle:
                    handle.seek(section.offset)
                    return handle.read(max(length, 0))
        with self._file_handle() as handle:
            handle.seek(section.offset)
            return handle.read(section.size)

    def section_at_address(self, vaddr: int) -> Section | None:
        """The section containing a virtual address, including size-0 NOBITS.

        ``section_at`` skips empty ranges; ``iS.``/``iSw`` also need to find a
        zero-sized NOBITS section that starts exactly at the seek.
        """
        for section in self.sections:
            if section.type == SHT_NOBITS:
                if section.addr <= vaddr <= section.addr + section.size:
                    return section
            elif section.addr <= vaddr < section.addr + section.size:
                return section
        return None

    def section_header_rows(self) -> list[dict[str, Any]]:
        """Raw ``iSh`` rows: every field of every section header."""
        rows: list[dict[str, Any]] = []
        for section in self.sections:
            rows.append(
                {
                    "name": section.name,
                    "type": section.type,
                    "flags": section.flags,
                    "addr": section.addr,
                    "offset": section.offset,
                    "size": section.size,
                    "link": section.link,
                    "info": section.info,
                    "addralign": section.addralign,
                    "entsize": section.entsize,
                }
            )
        return rows

    def segment_rows(self) -> list[dict[str, Any]]:
        """Memory maps for ``iSS`` (r2's ``Elf_(maps)``)."""
        rows: list[dict[str, Any]] = []
        load_count = 0
        for program in self.programs:
            if program.type == PT_LOAD:
                name = f"LOAD{load_count}"
                load_count += 1
            else:
                name = _PROGRAM_NAMES.get(program.type, f"PT_{program.type:x}")
            rows.append(
                {
                    "nth": len(rows),
                    "paddr": program.offset,
                    "size": program.filesz,
                    "vaddr": program.vaddr,
                    "vsize": program.memsz,
                    "perm": _PHDR_PERM(program.flags),
                    "flags": 0,
                    "type": "MAP",
                    "name": name,
                    "class": "",
                }
            )
        # The ELF header itself is not a program header, but r2 maps it.
        rows.append(
            {
                "nth": len(rows),
                "paddr": 0,
                "size": self.header.ehsize,
                "vaddr": self.baddr,
                "vsize": self.header.ehsize,
                "perm": "-rw-",
                "flags": 0,
                "type": "MAP",
                "name": "ehdr",
                "class": "",
            }
        )
        return rows

    def section_for_symbol(self, table: str, value: int) -> str:
        """Section name for a symbol table entry (``iSm``).

        IDA does not expose the ELF ``st_shndx`` for most entries, so the
        section is inferred from the value instead of trusting the index.
        """
        section = self.section_at_address(value) if value else None
        if section is not None and section.name:
            return section.name
        return ""

    def locate(self, vaddr: int) -> tuple[int, str]:
        """``(paddr, section)`` for a string address."""
        paddr = self.vaddr_to_paddr(vaddr)
        section = self.section_at(vaddr)
        name = section.name if section and section.name else "unknown"
        return (paddr if paddr is not None else vaddr), name

    # -- listing rows ------------------------------------------------------

    def _abi(self) -> str | None:
        """radare2's ``Elf_(get_abi)`` for the ABIs IDA can load."""
        flags = self.header.flags
        if self.machine == EM_ARM:
            arg = ""
            if flags & EF_ARM_BE8:
                arg = " be8"
            elif flags & EF_ARM_LE8:
                arg = " le8"
            return f"eabi{(flags & EF_ARM_EABIMASK) >> 24}{arg}"
        if self.machine in (EM_MIPS, EM_MIPS_RS3_LE):
            if self.bits == 64:
                return "n64"
            abi2 = flags & EF_MIPS_ABI2
            abi = flags & EF_MIPS_ABI
            if abi2 and not abi:
                return "n32"
            if not abi2 and (not abi or abi == EF_MIPS_ABI_O32):
                return "o32"
            if flags & EF_MIPS_MICROMIPS:
                return "micro"
        return None

    def arch_rows(self) -> list[dict[str, Any]]:
        """Rows in ``ia`` order: the file's arch/bits/offset/size/abi/machine."""
        row: dict[str, Any] = {
            "arch": ARCH_NAMES.get(self.machine, "unknown"),
            "bits": self.bits,
            "offset": 0,
            "size": self.file_size,
        }
        abi = self._abi()
        if abi:
            row["abi"] = abi
        row["machine"] = MACHINE_NAMES.get(self.machine, "unknown_machine")
        return [row]

    def header_rows(self) -> list[dict[str, Any]]:
        """Rows in ``ih`` order: radare2's ``fields`` table.

        The values are the file header's own, but the layout (offsets, sizes
        and ``pf`` formats) is the plugin's, so each row looks like a field
        found at that file offset.  ``value`` is omitted for zero fields,
        exactly like ``bin_fields``' JSON printer.
        """
        layout = HEADER_FIELDS_64 if self.bits == 64 else HEADER_FIELDS_32
        values = {
            "ELF": int.from_bytes(self.header.ident[:4], "little"),
            "Type": self.header.type,
            "Machine": self.header.machine,
            "Version": self.header.version,
            "EntryPoint": self.header.entry,
            "PhOff": self.header.phoff,
            "ShOff": self.header.shoff,
            "Flags": self.header.flags,
            "EhSize": self.header.ehsize,
            "PhentSize": self.header.phentsize,
            "PhNum": self.header.phnum,
            "ShentSize": self.header.shentsize,
            "ShNum": self.header.shnum,
            "ShrStrndx": self.header.shstrndx,
        }
        rows: list[dict[str, Any]] = []
        for name, offset, size, fmt in layout:
            value = values[name]
            row: dict[str, Any] = {
                "name": name,
                "vaddr": offset,
                "paddr": offset,
                "size": size,
            }
            if value and value != _NO_VALUE:
                row["value"] = value
            row["format"] = fmt
            row["pf"] = [{"type": fmt, "offset": offset, "value": value}]
            rows.append(row)
        return rows

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

    def export_rows(self) -> Iterator[dict[str, Any]]:
        """Rows in ``iE`` order: defined GLOBAL symbols from both tables.

        r2's ``its_an_export`` is just "not imported and bind == GLOBAL", so
        symtab entries that duplicate the dynsym are listed too (weak symbols
        are not exports).  The order is the same as :meth:`symbol_rows`.
        """
        for table in (self.dynsyms, self.symtabs):
            for symbol in table:
                if symbol.shndx == SHN_UNDEF or symbol.bind != "GLOBAL":
                    continue
                yield self._symbol_row(symbol)

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

    def reloc_rows(self) -> Iterator[dict[str, Any]]:
        """Rows in ``ir`` order: relocation sections sorted by address."""
        for reloc in sorted(self.relocs, key=lambda item: item.offset):
            symbol = self.dynsyms_by_index.get(reloc.symbol_index)
            if symbol is None:
                symbol = self.symtabs_by_index.get(reloc.symbol_index)
            name = symbol.name if symbol is not None else ""
            if reloc.addend < 0:
                name += f" - 0x{-reloc.addend:08x}"
            elif reloc.addend:
                name += (" +" if name else "") + f" 0x{reloc.addend:08x}"
            yield {
                "name": name,
                "type": "SET_32" if self.bits == 32 else "SET_64",
                "ntype": reloc.type,
                "vaddr": reloc.offset,
                "paddr": self.vaddr_to_paddr(reloc.offset),
                "is_ifunc": False,
            }


def _map_vaddr(
    programs: list[Program], sections: list[Section], vaddr: int
) -> int | None:
    """Map a virtual address to a file offset (used while loading)."""
    for program in programs:
        if program.type == PT_LOAD and program.vaddr <= vaddr < program.vaddr + program.filesz:
            return program.offset + (vaddr - program.vaddr)
    for section in sections:
        if (
            section.flags & SHF_ALLOC
            and section.type != SHT_NOBITS
            and section.size
            and section.addr <= vaddr < section.addr + section.size
        ):
            return section.offset + (vaddr - section.addr)
    return None


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
