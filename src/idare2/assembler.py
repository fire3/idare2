"""Client-side assembly backend shared by ``pa`` and ``wa``.

IDA owns the authoritative disassembler for the current database, and for x86 it
also provides an assembler through ``idautils.Assemble``.  Most other processor
modules registered in IDA do not provide the reverse operation.  radare2 solves
that with per-architecture assembler plugins; when ``rasm2`` is installed we use
the same backend as an optional fallback instead of turning ``pa``/``wa`` into
x86-only commands.

The fallback is deliberately optional: IDA remains the primary implementation,
and a missing ``rasm2`` leaves the original IDA error untouched.  This mirrors
radare2's own split between the generic assembler frontend (``r_asm``) and the
architecture plugins in ``libr/arch/p``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

from idare2.errors import CommandError, UsageError

if TYPE_CHECKING:
    from idare2.session import Session


#: Enough for assembling a shellcode-sized block without hanging a session.
RASM2_TIMEOUT = 15.0
MAX_ASSEMBLY = 1 << 20


#: IDA processor names -> radare2 assembler plugin names.  IDA reports the
#: architecture, not the plugin name, so this is the small translation layer
#: between the two engines.
_R2_ARCH = {
    "metapc": "x86",
    "x86": "x86",
    "x86_64": "x86",
    "amd64": "x86",
    "arm": "arm",
    "arm64": "arm",
    "arm64e": "arm",
    "aarch64": "arm",
    "mips": "mips",
    "mipsel": "mips",
    "mips64": "mips",
    "ppc": "ppc",
    "powerpc": "ppc",
    "riscv": "riscv",
    "risc-v": "riscv",
    "m68k": "m68k",
    "68000": "m68k",
    "s390": "s390",
    "s390x": "s390",
    "sparc": "sparc",
    "sparc64": "sparc",
    "sh": "sh",
    "sh4": "sh",
    "superh": "sh",
    "msp430": "msp430",
    "avr": "avr",
    "8051": "8051",
    "h8300": "h8300",
    "v850": "v850",
    "tricore": "tricore",
    "bpf": "bpf",
    "ebpf": "bpf",
    "evm": "evm",
    "dalvik": "dalvik",
    "java": "java",
    "cil": "cil",
    "wasm": "wasm",
    "6502": "6502",
    "z80": "z80",
}


def assemble(session: Session, raw_text: str, *, ea: int | None = None) -> bytes:
    """Assemble ``raw_text`` at ``ea`` (the seek by default).

    The IDA operation is read-only: it returns bytes so callers can either print
    them (``pa``) or pass them through the write cache (``wa``).
    """
    text = instruction_text(raw_text)
    if not text:
        raise UsageError("assembly needs an instruction")
    target = session.seek if ea is None else int(ea)
    # r2 substitutes `$$` with the assembler's program counter before handing
    # the expression to the architecture plugin.
    text = text.replace("$$", f"0x{target:x}")

    try:
        payload = session.remote.call("assemble", ea=target, text=text)
    except CommandError as ida_error:
        if "assembl" not in str(ida_error).lower():
            raise
        fallback = _rasm2_assemble(session, text, target, ida_error)
        if fallback is None:
            raise
        return fallback

    raw = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
    elif isinstance(raw, str):
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            raise CommandError(f"assembler returned invalid hexpairs: {raw!r}") from None
    else:
        raise CommandError(
            f"assembler returned {type(raw).__name__} instead of bytes"
        )
    if not data:
        raise CommandError(f"assembler produced nothing for {text!r}")
    if len(data) > MAX_ASSEMBLY:
        raise CommandError(f"refusing to assemble {len(data)} bytes at once")
    return data


def instruction_text(raw_text: str) -> str:
    """Strip r2's optional quoting around an assembly expression."""
    text = raw_text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"`":
        return text[1:-1].strip()
    return text


def r2_arch(session: Session) -> str | None:
    """The radare2 assembler plugin for the attached database, if known."""
    name = str(
        session.info.get("architecture") or session.info.get("arch") or ""
    ).strip().lower()
    return _R2_ARCH.get(name)


def _rasm2_assemble(
    session: Session, text: str, ea: int, ida_error: CommandError
) -> bytes | None:
    """Try the optional ``rasm2`` fallback; ``None`` means it is unavailable."""
    plugin = r2_arch(session)
    if plugin is None:
        return None
    executable = os.environ.get("IDARE2_RASM2") or shutil.which("rasm2")
    if not executable:
        return None

    # `open_summary` exposes ``bitness``; ``file_info``/the session also expose
    # ``bits``.  Use both, otherwise rasm2 silently defaults to 64 bits.
    bits = int(session.info.get("bitness") or session.info.get("bits") or 0)
    argv = [executable, "-q", "-a", plugin, "-s", f"0x{ea:x}"]
    if bits:
        argv.extend(["-b", str(bits)])
    if session.info.get("endian") == "big":
        argv.append("-e")
    argv.extend(["--", text])

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=RASM2_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        raise CommandError(
            f"rasm2 timed out after {RASM2_TIMEOUT:g}s assembling {text!r}"
        ) from ida_error
    except OSError as exc:
        raise CommandError(f"cannot run rasm2: {exc}") from ida_error

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise CommandError(
            f"IDA could not assemble {text!r}; rasm2 ({plugin}) also failed"
            + (f": {detail}" if detail else "")
        ) from ida_error

    encoded = "".join(completed.stdout.split())
    if not encoded or len(encoded) % 2:
        raise CommandError(
            f"rasm2 returned invalid hexpairs for {text!r}: {completed.stdout!r}"
        ) from ida_error
    try:
        raw = bytes.fromhex(encoded)
    except ValueError:
        raise CommandError(
            f"rasm2 returned invalid hexpairs for {text!r}: {completed.stdout!r}"
        ) from ida_error
    if not raw:
        raise CommandError(f"assembler produced nothing for {text!r}") from ida_error
    if len(raw) > MAX_ASSEMBLY:
        raise CommandError(f"refusing to assemble {len(raw)} bytes at once") from ida_error
    return raw
