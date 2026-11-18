"""radare2 architecture names and the IDA processors they select.

``idare2`` copies radare2's command line, so ``-a`` must accept radare2's
``asm.arch`` names (``x86``, ``arm``, ``mips``...).  IDA speaks a different
vocabulary: x86 is ``metapc``, MIPS and SPARC carry the byte order in the
processor name, m68k is ``68000`` and SuperH is ``sh4``.

Names that are not in the alias table are returned unchanged, so IDA's own
processor names (and ``arm:ARMv7`` style subtypes) keep working.
"""

from __future__ import annotations

#: radare2 ``asm.arch`` (and common aliases) -> architecture family.
_FAMILY = {
    "x86": "x86",
    "i386": "x86",
    "i486": "x86",
    "i586": "x86",
    "i686": "x86",
    "x86_64": "x86",
    "x64": "x86",
    "amd64": "x86",
    "arm": "arm",
    "armle": "arm",
    "armbe": "arm",
    "arm64": "arm",
    "aarch64": "arm",
    "aarch64be": "arm",
    "mips": "mips",
    "mipsle": "mips",
    "mipsbe": "mips",
    "mips64": "mips",
    "mips64le": "mips",
    "mips64be": "mips",
    "ppc": "ppc",
    "powerpc": "ppc",
    "ppc64": "ppc",
    "ppcle": "ppc",
    "ppcbe": "ppc",
    "ppc64le": "ppc",
    "ppc64be": "ppc",
    "riscv": "riscv",
    "riscv32": "riscv",
    "riscv64": "riscv",
    "m68k": "m68k",
    "sparc": "sparc",
    "sparc64": "sparc",
    "sh": "sh",
    "sh1": "sh",
    "sh2": "sh",
    "sh2a": "sh",
    "sh4": "sh",
    "s390": "s390",
    "systemz": "s390",
    "s390x": "s390",
    "tricore": "tricore",
    "xtensa": "xtensa",
    "avr": "avr",
    "wasm": "wasm",
    "z80": "z80",
    "8051": "8051",
    "6502": "6502",
    "m6502": "6502",
    "65816": "65816",
    "m65816": "65816",
    "msp430": "msp430",
    "ebc": "ebc",
    "hexagon": "hexagon",
    "hppa": "hppa",
    "alpha": "alpha",
    "arc": "arc",
    "m32r": "m32r",
    "mcore": "mcore",
    "i960": "i960",
    "pdp11": "pdp11",
    "h8300": "h8300",
    "v850": "v850",
    "c166": "c166",
    "spc700": "spc700",
    "st20": "st20",
    "st7": "st7",
    "st9": "st9",
    "rl78": "rl78",
    "78k0": "78k0",
    "nds32": "nds32",
    "h8500": "h8500",
    "fr": "fr",
    "rx": "rx",
    "sam8": "sam8",
}

#: Families whose IDA processor name encodes the byte order.
_ENDIAN_FAMILIES = frozenset({"mips", "sparc", "xtensa", "ppc"})

#: IDA processor name for families that need no width/endian special case.
_IDA_NAME = {
    "ppc": "ppc",
    "riscv": "riscv",
    "m68k": "68000",
    "sh": "sh4",
    "s390": "s390",
    "tricore": "TRICORE",
    "avr": "avr",
    "wasm": "wasm",
    "z80": "z80",
    "8051": "8051",
    "6502": "M6502",
    "65816": "m65816",
    "msp430": "msp430",
    "ebc": "ebc",
    "hexagon": "hexagon",
    "hppa": "hppa",
    "alpha": "alphal",
    "arc": "arc",
    "m32r": "m32r",
    "mcore": "mcore",
    "i960": "i960",
    "pdp11": "pdp11",
    "h8300": "H8300",
    "v850": "V850",
    "c166": "c166",
    "spc700": "spc700",
    "st20": "st20",
    "st7": "st7",
    "st9": "st9",
    "rl78": "RL78",
    "78k0": "78k0",
    "nds32": "nds32",
    "h8500": "h8500",
    "fr": "fr",
    "rx": "rx",
    "sam8": "SAM8",
}

#: Names whose bit width is part of the alias rather than the ``-b`` flag.
_BITS = {
    "i386": 32,
    "i486": 32,
    "i586": 32,
    "i686": 32,
    "aarch64be": 64,
    "mips64le": 64,
    "mips64be": 64,
    "ppc64le": 64,
    "ppc64be": 64,
}


def family(name: str | None) -> str | None:
    """Return the architecture family for a known radare2 name."""
    if not name:
        return None
    key = name.strip().lower()
    if not key or ":" in key:
        return None
    return _FAMILY.get(key)


def implied_bits(name: str | None) -> int | None:
    """The bit width a radare2 alias implies, if any.

    ``x86_64``, ``aarch64`` and ``riscv64`` say how wide they are; bare
    ``x86``/``arm`` do not, so ``-b`` remains in charge there.
    """
    if not name:
        return None
    key = name.strip().lower()
    if key in _BITS:
        return _BITS[key]
    if key.endswith("64"):
        return 64
    if key.endswith("16"):
        return 16
    return None


def implied_endian(name: str | None, endian: str | None = None) -> str | None:
    """The byte order a radare2 alias implies, if any.

    An explicit ``-e cfg.bigendian`` always wins.  Suffixes such as
    ``mipsbe`` next.  For MIPS, SPARC and Xtensa the IDA processor name itself
    has to choose a byte order; radare2's default is little-endian, so that is
    the fallback.  IDA's PowerPC processor defaults to big-endian, which also
    disagrees with r2, so ppc is included; other families leave the choice to
    IDA, as before.
    """
    if endian is not None:
        return endian
    if not name:
        return None
    key = name.strip().lower()
    if ":" in key:
        return None
    if key.endswith("be"):
        return "big"
    if key.endswith("le"):
        return "little"
    if _FAMILY.get(key) in _ENDIAN_FAMILIES:
        return "little"
    return None


def resolve(name: str | None, bits: int | None = None, endian: str | None = None) -> str | None:
    """Translate an ``-a`` value into the IDA processor name it selects."""
    if not name:
        return name
    text = name.strip()
    if ":" in text:
        return text
    key = text.lower()
    arch = _FAMILY.get(key)
    if arch is None:
        return text

    width = bits if bits is not None else implied_bits(text)
    big = implied_endian(text, endian) == "big"

    if arch == "x86":
        return "metapc"
    if arch == "arm":
        if width == 64:
            return "arm:ARMv8"
        if width == 32:
            return "arm:ARMv7"
        return "arm"
    if arch == "mips":
        return "mipsb" if big else "mipsl"
    if arch == "sparc":
        return "sparcb" if big else "sparcl"
    if arch == "xtensa":
        return "XTENSAB" if big else "XTENSA"
    return _IDA_NAME[arch]
