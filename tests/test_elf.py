"""The minimal ELF reader behind the ``iz``/``ii``/``is`` fields.

The fixtures are synthetic ELFs so the tests stay offline and can pin every
field radare2 prints: section names, file offsets, symbol bind/type/size and
the dynsym ordinals used as ``nth``.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from idare2.remote.elf import (
    SHT_DYNAMIC,
    SHT_DYNSYM,
    SHT_NOBITS,
    SHT_REL,
    SHT_STRTAB,
    SHT_SYMTAB,
    load_elf,
)


def _names() -> tuple[bytes, dict[str, int]]:
    names = [
        b"", b".text", b".dynsym", b".dynstr", b".symtab", b".strtab", b".bss",
        b".rel.dyn", b".shstrtab", b".dynamic",
    ]
    data = b""
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name.decode()] = len(data)
        data += name + b"\0"
    return data, offsets


def _build(bits: int, endian: str = "<", machine: int = 40) -> bytes:
    shstrtab, shname = _names()
    dynstr = b"\0foo\0puts\0zero_import\0"
    strtab = b"\0test.c\0bss_obj\0foo\0$d\0"
    strname = {"test.c": 1, "bss_obj": 8, "foo": 16, "$d": 20}

    shstr_off = 0x260
    shoff = 0x300
    shnum = 11
    shentsize = 64 if bits == 64 else 40
    phoff = 0x40 if bits == 64 else 0x34
    phentsize = 56 if bits == 64 else 32
    total = shoff + shnum * shentsize
    buf = bytearray(total)
    dyn_off = 0x2B0
    rel_off = 0x2E0 if bits == 32 else 0x2F0
    dynstr = b"\0foo\0puts\0zero_import\0libc.so.6\0"

    # -- section contents --------------------------------------------------
    buf[0x100:0x110] = b"hello\0" + b"\0" * 10
    dynsym = [
        (0, 0, 0, 0, 0, 0),
        (1, 0x400100, 16, 0x12, 0, 1),
        (5, 0x400104, 0, 0x12, 0, 0),
        (10, 0, 0, 0x12, 0, 0),
    ]
    symtab = [
        (0, 0, 0, 0, 0, 0),
        (0, 0x400100, 0, 0x03, 0, 1),
        (strname["test.c"], 0, 0, 0x04, 0, 0xFFF1),
        (strname["bss_obj"], 0x400300, 4, 0x01, 0, 6),
        (strname["foo"], 0x400100, 16, 0x12, 0, 1),
        (strname["$d"], 0x10, 0, 0x00, 0, 1),
    ]
    buf[0x130:0x130 + len(dynsym) * (24 if bits == 64 else 16)] = b"".join(
        _pack_symbol(bits, entry, endian) for entry in dynsym
    )
    buf[0x190:0x190 + len(dynstr)] = dynstr
    buf[0x1B0:0x1B0 + len(symtab) * (24 if bits == 64 else 16)] = b"".join(
        _pack_symbol(bits, entry, endian) for entry in symtab
    )
    buf[0x240:0x240 + len(strtab)] = strtab
    if bits == 64:
        struct.pack_into(endian + "QQ", buf, rel_off, 0x400104, (2 << 32) | 22)
    else:
        struct.pack_into(endian + "II", buf, rel_off, 0x400104, (2 << 8) | 22)
    buf[shstr_off:shstr_off + len(shstrtab)] = shstrtab
    # .dynamic: DT_NEEDED + DT_STRTAB + DT_STRSZ + DT_NULL.
    dyn_entry = 16 if bits == 64 else 8
    dyn_fmt = endian + ("QQ" if bits == 64 else "II")
    needed = dynstr.index(b"libc.so.6")
    struct.pack_into(dyn_fmt, buf, dyn_off, 1, needed)
    struct.pack_into(dyn_fmt, buf, dyn_off + dyn_entry, 5, 0x400190)
    struct.pack_into(dyn_fmt, buf, dyn_off + 2 * dyn_entry, 10, len(dynstr))
    struct.pack_into(dyn_fmt, buf, dyn_off + 3 * dyn_entry, 0, 0)

    # -- ELF header --------------------------------------------------------
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "<" else 2, 1]) + b"\0" * 9
    buf[:16] = ident
    if bits == 64:
        struct.pack_into(
            endian + "HHIQQQIHHHHHH",
            buf,
            16,
            2, machine, 1, 0x400100, phoff, shoff, 0, 64, phentsize, 2, shentsize, shnum, 8,
        )
        struct.pack_into(
            endian + "IIQQQQQQ",
            buf,
            phoff,
            1, 0x5, 0, 0x400000, 0x400000, 0x300, 0x400, 0x1000,
        )
        struct.pack_into(
            endian + "IIQQQQQQ",
            buf,
            phoff + phentsize,
            2, 0x6, 0x2B0, 0x4002B0, 0x4002B0, 0x60, 0x60, 4,
        )
    else:
        struct.pack_into(
            endian + "HHIIIIIHHHHHH",
            buf,
            16,
            2, machine, 1, 0x400100, phoff, shoff, 0, 52, phentsize, 2, shentsize, shnum, 8,
        )
        struct.pack_into(
            endian + "IIIIIIII",
            buf,
            phoff,
            1, 0, 0x400000, 0x400000, 0x300, 0x400, 0x5, 0x1000,
        )
        struct.pack_into(
            endian + "IIIIIIII",
            buf,
            phoff + phentsize,
            2, 0x2B0, 0x4002B0, 0x4002B0, 0x40, 0x40, 0x6, 4,
        )

    # -- section headers ---------------------------------------------------
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (shname[".text"], 1, 0x6, 0x400100, 0x100, 0x10, 0, 0, 4, 0),
        (shname[".dynsym"], SHT_DYNSYM, 0x2, 0x400130, 0x130, 4 * (24 if bits == 64 else 16), 3, 1, 4, 24 if bits == 64 else 16),
        (shname[".dynstr"], SHT_STRTAB, 0x2, 0x400190, 0x190, len(dynstr), 0, 0, 1, 0),
        (shname[".symtab"], SHT_SYMTAB, 0x0, 0, 0x1B0, 6 * (24 if bits == 64 else 16), 5, 1, 4, 24 if bits == 64 else 16),
        (shname[".strtab"], SHT_STRTAB, 0x0, 0, 0x240, len(strtab), 0, 0, 1, 0),
        (shname[".bss"], SHT_NOBITS, 0x3, 0x400300, 0x260, 0x40, 0, 0, 4, 0),
        (
            shname[".rel.dyn"], SHT_REL, 0x0, 0, rel_off,
            16 if bits == 64 else 8, 2, 0, 4, 16 if bits == 64 else 8,
        ),
        (shname[".shstrtab"], SHT_STRTAB, 0x0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0),
        (
            shname[".dynamic"], SHT_DYNAMIC, 0x3, 0x4002B0, 0x2B0,
            4 * dyn_entry, 3, 0, 4, dyn_entry,
        ),
    ]
    sh_fmt = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    for index, section in enumerate(sections):
        struct.pack_into(sh_fmt, buf, shoff + index * shentsize, *section)

    return bytes(buf)


def _pack_symbol(
    bits: int, entry: tuple[int, int, int, int, int, int], endian: str = "<"
) -> bytes:
    name, value, size, info, other, shndx = entry
    if bits == 64:
        return struct.pack(endian + "IBBHQQ", name, info, other, shndx, value, size)
    return struct.pack(endian + "IIIBBH", name, value, size, info, other, shndx)


@pytest.fixture(params=[32, 64])
def elf(request, tmp_path: Path):
    path = tmp_path / f"sample{request.param}"
    path.write_bytes(_build(request.param))
    parsed = load_elf(str(path))
    assert parsed is not None
    return parsed


def test_sections_and_file_offsets(elf) -> None:
    assert [section.name for section in elf.sections][1:3] == [".text", ".dynsym"]
    assert elf.vaddr_to_paddr(0x400100) == 0x100
    # .bss is inside the PT_LOAD memory image but past p_filesz.
    assert elf.vaddr_to_paddr(0x400300) is None
    assert elf.paddr_to_vaddr(0x104) == 0x400104
    assert elf.section_at(0x400300).name == ".bss"


def test_header_fields_match_radare2_layout(elf) -> None:
    """``ih``'s field table: names, offsets, sizes and pf formats from bin_elf."""
    rows = elf.header_rows()
    if elf.bits == 64:
        expected = [
            ("ELF", 0x00, 4, 0x464C457F, "x"),
            ("Type", 0x10, 2, 2, "w"),
            ("Machine", 0x12, 2, 40, "w"),
            ("Version", 0x14, 4, 1, "x"),
            ("EntryPoint", 0x18, 8, 0x400100, "q"),
            ("PhOff", 0x20, 8, 0x40, "q"),
            ("ShOff", 0x28, 8, 0x300, "q"),
            ("Flags", 0x30, 4, None, "x"),
            ("EhSize", 0x34, 2, 64, "w"),
            ("PhentSize", 0x36, 2, 56, "w"),
            ("PhNum", 0x38, 2, 2, "w"),
            ("ShentSize", 0x3A, 2, 64, "w"),
            ("ShNum", 0x3C, 2, 11, "w"),
            ("ShrStrndx", 0x3E, 2, 8, "w"),
        ]
    else:
        expected = [
            ("ELF", 0x00, 4, 0x464C457F, "x"),
            ("Type", 0x10, 2, 2, "w"),
            ("Machine", 0x12, 2, 40, "w"),
            ("Version", 0x14, 4, 1, "x"),
            ("EntryPoint", 0x18, 4, 0x400100, "x"),
            ("PhOff", 0x1C, 4, 0x34, "x"),
            ("ShOff", 0x20, 4, 0x300, "x"),
            ("Flags", 0x24, 4, None, "x"),
            ("EhSize", 0x28, 2, 52, "w"),
            ("PhentSize", 0x2A, 2, 32, "w"),
            ("PhNum", 0x2C, 2, 2, "w"),
            ("ShentSize", 0x2E, 2, 40, "w"),
            ("ShNum", 0x30, 2, 11, "w"),
            ("ShrStrndx", 0x32, 2, 8, "w"),
        ]

    summary = [
        (row["name"], row["vaddr"], row["size"], row.get("value"), row["format"])
        for row in rows
    ]
    assert summary == expected
    # ``paddr`` mirrors ``vaddr`` for header fields, and zero-valued fields keep
    # their pf decode while dropping the top-level ``value`` (as bin_fields does).
    for row, (_name, offset, _size, value, fmt) in zip(rows, expected, strict=True):
        assert row["paddr"] == offset
        assert row["pf"] == [{"type": fmt, "offset": offset, "value": value or 0}]
        assert ("value" in row) == (value is not None)


def test_header_fields_follow_the_file_endianness(tmp_path: Path) -> None:
    """The ELF reader is endian-aware; r2's ``iH`` text is not (it reads LE)."""
    path = tmp_path / "sample-be"
    path.write_bytes(_build(32, ">"))
    parsed = load_elf(str(path))
    assert parsed is not None
    assert parsed.endian == ">"
    rows = {row["name"]: row for row in parsed.header_rows()}
    assert rows["Machine"]["value"] == 40
    assert rows["EntryPoint"]["value"] == 0x400100
    assert rows["ShOff"]["value"] == 0x300


def test_arch_rows_match_radare2_ia(elf) -> None:
    """``ia``: arch name, bits, file size, ARM EABI and the machine text."""
    assert elf.arch_rows() == [
        {
            "arch": "arm",
            "bits": elf.bits,
            "offset": 0,
            "size": elf.file_size,
            "abi": "eabi0",
            "machine": "ARM",
        }
    ]


def test_mips_abi_names_follow_radare2(tmp_path: Path) -> None:
    from idare2.remote.elf import EM_MIPS

    path = tmp_path / "mips32"
    path.write_bytes(_build(32, "<", EM_MIPS))
    parsed = load_elf(str(path))
    assert parsed is not None
    row = parsed.arch_rows()[0]
    assert (row["arch"], row["abi"], row["machine"]) == ("mips", "o32", "MIPS R3000")

    path = tmp_path / "mips64"
    path.write_bytes(_build(64, "<", EM_MIPS))
    parsed = load_elf(str(path))
    assert parsed is not None
    assert parsed.arch_rows()[0]["abi"] == "n64"


def test_symbol_rows_follow_radare2_order_and_fields(elf) -> None:
    rows = list(elf.symbol_rows())
    summary = [
        (row["ordinal"], row["name"], row["bind"], row["type"], row["paddr"], row["vaddr"], row["size"])
        for row in rows
    ]
    assert summary == [
        (1, "foo", "GLOBAL", "FUNC", 0x100, 0x400100, 16),
        (1, ".text", "LOCAL", "SECT", 0x100, 0x400100, 0),
        (2, "test.c", "LOCAL", "FILE", None, 0, 0),
        (3, "bss_obj", "LOCAL", "OBJ", None, 0x400300, 4),
        (4, "foo", "GLOBAL", "FUNC", 0x100, 0x400100, 16),
        (5, "$d", "LOCAL", "SPCL", 0x10, 0x400010, 0),
        (2, "imp.puts", "GLOBAL", "FUNC", 0x104, 0x400104, 16),
        (3, "imp.zero_import", "GLOBAL", "FUNC", None, None, 16),
    ]


def test_import_rows_use_dynsym_ordinals(elf) -> None:
    assert list(elf.import_rows()) == [
        {
            "ordinal": 2,
            "ea": 0x400104,
            "vaddr": 0x400104,
            "bind": "GLOBAL",
            "type": "FUNC",
            "lib": "",
            "name": "puts",
        },
        {
            "ordinal": 3,
            "ea": 0,
            "vaddr": None,
            "bind": "GLOBAL",
            "type": "FUNC",
            "lib": "",
            "name": "zero_import",
        },
    ]


def test_string_location_uses_section_names(elf) -> None:
    assert elf.locate(0x400100) == (0x100, ".text")


def test_relocation_rows_match_radare2_table_fields(elf) -> None:
    assert list(elf.reloc_rows()) == [
        {
            "name": "puts",
            "type": "SET_32" if elf.bits == 32 else "SET_64",
            "ntype": 22,
            "vaddr": 0x400104,
            "paddr": 0x104,
            "is_ifunc": False,
        }
    ]


def test_export_rows_keep_defined_global_symbols(elf) -> None:
    """``iE``: defined GLOBAL symbols from dynsym and symtab, in table order."""
    rows = list(elf.export_rows())
    assert [(row["ordinal"], row["name"], row["bind"], row["type"]) for row in rows] == [
        (1, "foo", "GLOBAL", "FUNC"),
        (4, "foo", "GLOBAL", "FUNC"),
    ]


def test_needed_libraries_come_from_dynamic(elf) -> None:
    """``il``: DT_NEEDED entries, resolved through .dynstr."""
    assert elf.libs == ["libc.so.6"]


def test_non_elf_and_missing_files_return_none(tmp_path: Path) -> None:
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not an elf")
    assert load_elf(str(plain)) is None
    assert load_elf(str(tmp_path / "missing")) is None
    assert load_elf(None) is None
