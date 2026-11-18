"""radare2 architecture names -> IDA processor names."""

from __future__ import annotations

import pytest

from idare2 import arch


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("x86", "metapc"),
        ("i386", "metapc"),
        ("x86_64", "metapc"),
        ("amd64", "metapc"),
        ("arm", "arm"),
        ("arm64", "arm:ARMv8"),
        ("aarch64", "arm:ARMv8"),
        ("mips", "mipsl"),
        ("mipsbe", "mipsb"),
        ("mipsle", "mipsl"),
        ("mips64", "mipsl"),
        ("ppc", "ppc"),
        ("ppc64le", "ppc"),
        ("riscv", "riscv"),
        ("riscv64", "riscv"),
        ("m68k", "68000"),
        ("sparc", "sparcl"),
        ("sparc64", "sparcl"),
        ("sh", "sh4"),
        ("s390", "s390"),
        ("tricore", "TRICORE"),
        ("xtensa", "XTENSA"),
        ("avr", "avr"),
        ("wasm", "wasm"),
        ("z80", "z80"),
        ("6502", "M6502"),
        ("8051", "8051"),
        ("h8300", "H8300"),
    ],
)
def test_r2_names_resolve_to_ida_processors(name: str, expected: str) -> None:
    assert arch.resolve(name) == expected


def test_explicit_bits_and_endian_win() -> None:
    assert arch.resolve("arm", 64) == "arm:ARMv8"
    assert arch.resolve("arm", 32) == "arm:ARMv7"
    assert arch.resolve("mips", 32, "big") == "mipsb"
    assert arch.resolve("mips", 64, "little") == "mipsl"
    assert arch.resolve("sparc", 64, "big") == "sparcb"
    assert arch.resolve("xtensa", 32, "big") == "XTENSAB"


@pytest.mark.parametrize(
    "name",
    ["metapc", "mipsb", "mipsl", "sparcb", "sparcl", "68000", "XTENSAB", "arm:ARMv7"],
)
def test_ida_names_pass_through(name: str) -> None:
    assert arch.resolve(name) == name


def test_aliases_imply_width_when_it_is_in_the_name() -> None:
    assert arch.implied_bits("x86_64") == 64
    assert arch.implied_bits("aarch64be") == 64
    assert arch.implied_bits("mips64le") == 64
    assert arch.implied_bits("i386") == 32
    assert arch.implied_bits("x86") is None
    assert arch.implied_bits("arm") is None


def test_byte_order_aliases_and_r2_default() -> None:
    assert arch.implied_endian("mips") == "little"
    assert arch.implied_endian("sparc") == "little"
    assert arch.implied_endian("ppc") == "little"
    assert arch.implied_endian("mipsbe") == "big"
    assert arch.implied_endian("ppcbe") == "big"
    assert arch.implied_endian("ppc64le") == "little"
    assert arch.implied_endian("mips", "big") == "big"
    assert arch.implied_endian("x86") is None
    assert arch.implied_endian("mipsb") is None
