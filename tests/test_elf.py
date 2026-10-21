"""The minimal ELF reader behind the ``iz``/``ii``/``is`` fields.

The fixtures are synthetic ELFs so the tests stay offline and can pin every
field radare2 prints: section names, file offsets, symbol bind/type/size and
the dynsym ordinals used as ``nth``.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from idare2.remote.elf import SHT_DYNSYM, SHT_NOBITS, SHT_STRTAB, SHT_SYMTAB, load_elf


def _names() -> tuple[bytes, dict[str, int]]:
    names = [b"", b".text", b".dynsym", b".dynstr", b".symtab", b".strtab", b".bss", b".shstrtab"]
    data = b""
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name.decode()] = len(data)
        data += name + b"\0"
    return data, offsets


def _build(bits: int) -> bytes:
    endian = "<"
    shstrtab, shname = _names()
    dynstr = b"\0foo\0puts\0zero_import\0"
    strtab = b"\0test.c\0bss_obj\0foo\0$d\0"
    strname = {"test.c": 1, "bss_obj": 8, "foo": 16, "$d": 20}

    shstr_off = 0x260
    shoff = 0x300
    shnum = 8
    shentsize = 64 if bits == 64 else 40
    phoff = 0x40 if bits == 64 else 0x34
    phentsize = 56 if bits == 64 else 32
    total = shoff + shnum * shentsize
    buf = bytearray(total)

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
        (strname["bss_obj"], 0x400200, 4, 0x01, 0, 6),
        (strname["foo"], 0x400100, 16, 0x12, 0, 1),
        (strname["$d"], 0x10, 0, 0x00, 0, 1),
    ]
    buf[0x130:0x130 + len(dynsym) * (24 if bits == 64 else 16)] = b"".join(
        _pack_symbol(bits, entry) for entry in dynsym
    )
    buf[0x190:0x190 + len(dynstr)] = dynstr
    buf[0x1B0:0x1B0 + len(symtab) * (24 if bits == 64 else 16)] = b"".join(
        _pack_symbol(bits, entry) for entry in symtab
    )
    buf[0x240:0x240 + len(strtab)] = strtab
    buf[shstr_off:shstr_off + len(shstrtab)] = shstrtab

    # -- ELF header --------------------------------------------------------
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1]) + b"\0" * 9
    buf[:16] = ident
    if bits == 64:
        struct.pack_into(
            endian + "HHIQQQIHHHHHH",
            buf,
            16,
            2, 40, 1, 0x400100, phoff, shoff, 0, 64, phentsize, 1, shentsize, shnum, 7,
        )
        struct.pack_into(
            endian + "IIQQQQQQ",
            buf,
            phoff,
            1, 0x5, 0, 0x400000, 0x400000, 0x200, 0x300, 0x1000,
        )
    else:
        struct.pack_into(
            endian + "HHIIIIIHHHHHH",
            buf,
            16,
            2, 40, 1, 0x400100, phoff, shoff, 0, 52, phentsize, 1, shentsize, shnum, 7,
        )
        struct.pack_into(
            endian + "IIIIIIII",
            buf,
            phoff,
            1, 0, 0x400000, 0x400000, 0x200, 0x300, 0x5, 0x1000,
        )

    # -- section headers ---------------------------------------------------
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (shname[".text"], 1, 0x6, 0x400100, 0x100, 0x10, 0, 0, 4, 0),
        (shname[".dynsym"], SHT_DYNSYM, 0x2, 0x400130, 0x130, 4 * (24 if bits == 64 else 16), 3, 1, 4, 24 if bits == 64 else 16),
        (shname[".dynstr"], SHT_STRTAB, 0x2, 0x400190, 0x190, len(dynstr), 0, 0, 1, 0),
        (shname[".symtab"], SHT_SYMTAB, 0x0, 0, 0x1B0, 6 * (24 if bits == 64 else 16), 5, 1, 4, 24 if bits == 64 else 16),
        (shname[".strtab"], SHT_STRTAB, 0x0, 0, 0x240, len(strtab), 0, 0, 1, 0),
        (shname[".bss"], SHT_NOBITS, 0x3, 0x400200, 0x260, 0x40, 0, 0, 4, 0),
        (shname[".shstrtab"], SHT_STRTAB, 0x0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0),
    ]
    sh_fmt = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    for index, section in enumerate(sections):
        struct.pack_into(sh_fmt, buf, shoff + index * shentsize, *section)

    return bytes(buf)


def _pack_symbol(bits: int, entry: tuple[int, int, int, int, int, int]) -> bytes:
    name, value, size, info, other, shndx = entry
    if bits == 64:
        return struct.pack("<IBBHQQ", name, info, other, shndx, value, size)
    return struct.pack("<IIIBBH", name, value, size, info, other, shndx)


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
    assert elf.vaddr_to_paddr(0x400200) is None
    assert elf.paddr_to_vaddr(0x104) == 0x400104
    assert elf.section_at(0x400200).name == ".bss"


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
        (3, "bss_obj", "LOCAL", "OBJ", None, 0x400200, 4),
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


def test_non_elf_and_missing_files_return_none(tmp_path: Path) -> None:
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not an elf")
    assert load_elf(str(plain)) is None
    assert load_elf(str(tmp_path / "missing")) is None
    assert load_elf(None) is None
