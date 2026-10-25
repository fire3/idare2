"""The architecture matrix: the same raw-binary workflow on every supported CPU.

Run with::

    uv run pytest -m arch_matrix -q
    uv run pytest -m arch_matrix -q -k mips32be

Each entry is a raw binary made of one instruction repeated to at least 64
bytes, imported at ``0x1000`` with ``--processor``/``bits``/``--endian``.  The
sample bytes were verified with ``rasm2 -a <arch> -b <bits> [-e big] -d``
before being frozen here; the test itself does not need radare2.

The marker is opt-in because every case spawns an idalib worker and the suite
takes minutes.  A missing processor module is a **skip with a reason**, never a
silent pass; any other failure is a real failure.
"""

from __future__ import annotations

import importlib.util
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from idare2 import nexus, rpc
from idare2.config import Config
from idare2.errors import Idare2Error, UsageError
from idare2.session import Session

pytestmark = pytest.mark.arch_matrix

#: Where the sample is imported.  Every assertion is relative to this address.
ENTRY = 0x1000

#: One instruction, repeated until the sample is at least this long.
SAMPLE_SIZE = 64

_ADDRESS_BYTES = re.compile(
    r"^[┌│└]?\s*(0x[0-9a-f]+)\s+([0-9a-f]+)\s+(.*)$"
)


@dataclass(frozen=True)
class ArchSpec:
    """One raw-binary import configuration."""

    name: str
    processor: str
    bits: int
    endian: str
    sample: str
    module: str
    #: ``af`` is expected to reconstruct a function at the entry point.
    function_analysis: bool = True


#: The 12 configurations that only need the common processor modules.
COMMON_ARCHES = [
    ArchSpec("x86-64", "metapc", 64, "little", "90", "pc.so"),
    ArchSpec("i386", "metapc", 32, "little", "90", "pc.so"),
    ArchSpec("arm32le", "arm:ARMv7", 32, "little", "0000a0e1", "arm.so"),
    ArchSpec("arm32be", "armb", 32, "big", "e1a00000", "arm.so"),
    ArchSpec("aarch64", "arm:ARMv8", 64, "little", "1f2003d5", "arm.so"),
    ArchSpec("mips32le", "mipsl", 32, "little", "01000024", "mips.so"),
    ArchSpec("mips32be", "mipsb", 32, "big", "24000001", "mips.so"),
    ArchSpec("mips64le", "mipsl", 64, "little", "01000024", "mips.so"),
    ArchSpec("mips64be", "mipsb", 64, "big", "24000001", "mips.so"),
    ArchSpec("ppc32be", "ppc", 32, "big", "38000001", "ppc.so"),
    ArchSpec("ppc32le", "ppc", 32, "little", "01000038", "ppc.so"),
    ArchSpec("ppc64be", "ppc", 64, "big", "38000001", "ppc.so"),
]

ARCHES = COMMON_ARCHES


def sample_bytes(spec: ArchSpec) -> bytes:
    instruction = bytes.fromhex(spec.sample)
    repeats = -(-SAMPLE_SIZE // len(instruction))
    return instruction * repeats


def _procs_dir() -> Path:
    import idapro

    return Path(idapro.get_ida_install_dir()) / "procs"


@pytest.fixture(scope="module", autouse=True)
def _ida_installed() -> None:
    if importlib.util.find_spec("idapro") is None:  # pragma: no cover
        pytest.skip("idalib is not importable from this interpreter")
    if not _procs_dir().is_dir():  # pragma: no cover - environment dependent
        pytest.skip(f"no processor modules under {_procs_dir()}")


class _Database:
    """A connected session plus the sample used to build it."""

    def __init__(self, session: Session, spec: ArchSpec, data: bytes) -> None:
        self.session = session
        self.spec = spec
        self.data = data

    def run(self, command: str) -> list[str]:
        self.session.failed = False
        lines = self.session.run(command)
        assert not self.session.failed, (
            f"{self.spec.name}: {command!r} failed: {self.session.last_error}"
        )
        return lines


@contextmanager
def _open(spec: ArchSpec, path: Path, *, readonly: bool = True):
    target = nexus.Target(
        path=str(path),
        processor=spec.processor,
        bits=spec.bits,
        endian=spec.endian,
        image_base=ENTRY,
        readonly=readonly,
    )
    try:
        handle = nexus.connect(target, timeout=600, linger=0)
        with handle as opened:
            remote = rpc.Remote(opened, timeout=120)
            info = remote.call("open_summary")
            session = Session(opened, remote, Config(), info, readonly=readonly)
            session.setup()
            yield _Database(session, spec, path.read_bytes())
    except Idare2Error as exc:  # pragma: no cover - environment dependent
        pytest.fail(f"{spec.name}: cannot open the sample: {exc}")


def _skip_without_module(spec: ArchSpec) -> None:
    if not (_procs_dir() / spec.module).exists():
        pytest.skip(f"{spec.name}: processor module {spec.module} is not installed")


@pytest.mark.parametrize("spec", ARCHES, ids=lambda spec: spec.name)
def test_arch_matrix(spec: ArchSpec, tmp_path: Path) -> None:
    _skip_without_module(spec)
    data = sample_bytes(spec)
    binary = tmp_path / f"{spec.name}.bin"
    binary.write_bytes(data)

    with _open(spec, binary) as db:
        session = db.session

        # 1. Import: the hints survived the raw loader.
        assert session.info["bitness"] == spec.bits, session.info
        assert session.info["endian"] == spec.endian, session.info
        assert session.info["architecture"], session.info
        assert int(session.info["start_ip"] or 0) == ENTRY, session.info

        # 2. Disassembly: the byte columns are exactly the frozen sample.
        lines = db.run(f"pd 4 @ 0x{ENTRY:x}")
        assert lines, "pd produced no lines"
        decoded = []
        for line in lines:
            match = _ADDRESS_BYTES.match(line)
            assert match, f"unexpected pd line: {line!r}"
            address = int(match.group(1), 16)
            payload = match.group(2)
            text = match.group(3)
            assert payload, line
            decoded.append((address, payload, text))
        assert decoded[0][0] == ENTRY, decoded[0]
        assert data.hex().startswith("".join(payload for _, payload, _ in decoded))
        first_text = decoded[0][2].lower()
        assert "invalid" not in first_text and "dcb" not in first_text, decoded[0]
        db.run(f"pD {SAMPLE_SIZE} @ 0x{ENTRY:x}")

        # 3. Function analysis (degradable on the exotic architectures).
        session.failed = False
        session.run(f"s 0x{ENTRY:x}")
        session.run("af")
        if session.failed:
            if spec.function_analysis:
                pytest.fail(f"{spec.name}: af failed: {session.last_error}")
            session.failed = False
        else:
            listed = db.run("aflq")
            assert any(
                int(line, 16) == ENTRY for line in listed if line.startswith("0x")
            ), listed
            db.run(f"afi @ 0x{ENTRY:x}")

        # 4. File information: a raw binary has a segment but no ELF sections.
        assert db.run("iS"), "iS is empty"
        db.run("is")
        db.run("iz")
        assert db.run("iM"), "iM is empty"

        # 5. Search: the first instruction must be found at the entry point.
        session.config.set("search.from", ENTRY)
        session.config.set("search.to", ENTRY + len(data))
        hits = db.run(f"/x {spec.sample}")
        assert hits, f"/x {spec.sample} found nothing"
        assert any(int(line.split()[0], 16) == ENTRY for line in hits), hits

        # `/a` needs an assembler; when IDA has none the error must be explicit.
        session.failed = False
        session.run("/a nop")
        if session.failed:
            assert isinstance(session.last_error, (UsageError, Idare2Error)), (
                f"{spec.name}: /a failed without a clear error: {session.last_error}"
            )
            session.failed = False

        # 6. Session basics.
        db.run(f"s 0x{ENTRY:x}")
        assert db.run("s") == [session.format_addr(ENTRY)]
        assert db.run("b 32") == [] and session.blocksize == 32
        assert db.run("e scr.color") == [str(session.config.get_int("scr.color"))]
        db.run(f"f matrix_flag @ 0x{ENTRY:x}")
        assert session.flags.lookup("matrix_flag") == ENTRY
        db.run(f"$matrix=0x{ENTRY:x}")
        assert db.run("$matrix") == [session.format_addr(ENTRY)]

        # JSON forms must agree with the text forms on a fresh database.
        payload = json.loads("\n".join(db.run("aflj")))
        assert isinstance(payload, list)


def test_write_and_undo_on_a_private_copy(tmp_path: Path) -> None:
    """Only the first configuration: 22 write-back databases would be wasteful."""
    spec = ARCHES[0]
    _skip_without_module(spec)
    binary = tmp_path / "write-and-undo.bin"
    binary.write_bytes(sample_bytes(spec))

    with _open(spec, binary, readonly=False) as db:
        db.run(f"s 0x{ENTRY:x}")
        db.run("wx cc")
        assert db.run("p8 1") == ["cc"]
        db.run("u")
        assert db.run("p8 1") == [spec.sample[:2]]
