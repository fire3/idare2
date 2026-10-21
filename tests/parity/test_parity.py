"""Parity with radare2: the only objective check that "looks like r2" is true.

Run with::

    uv run pytest -m parity

Both engines analyse the same file independently, so exact text equality is
impossible: r2 names functions ``fcn.0001000`` where IDA names them ``sub_1000``,
IDA's comments are richer, and the two disassemblers may split bytes differently.
What *can* be compared is the part users actually depend on -- addresses, byte
sequences, table shapes -- so each test below narrows the comparison to that and
documents what it drops.

The target defaults to ``../vulfirm/RCE/Tenda/httpd`` relative to this checkout
(a local fixture, never committed) and can be overridden with
``IDARE2_PARITY_TARGET``.  Skipped unless both radare2 and a target are present.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from idare2 import nexus, rpc
from idare2.config import Config
from idare2.errors import Idare2Error
from idare2.session import Session

pytestmark = pytest.mark.parity

#: A firmware binary next to this repository, if the checkout layout has one.
FALLBACK_TARGET = (
    Path(__file__).resolve().parents[3] / "vulfirm" / "RCE" / "Tenda" / "httpd"
)
R2_TIMEOUT = 300


def _require_r2() -> str:
    r2 = shutil.which("r2")
    if not r2:
        pytest.skip("radare2 is not on PATH")
    return r2


def _target() -> Path:
    configured = os.environ.get("IDARE2_PARITY_TARGET")
    path = Path(configured).expanduser() if configured else FALLBACK_TARGET
    if not path.exists():
        pytest.skip(
            f"no parity target at {path}; set IDARE2_PARITY_TARGET to a binary"
        )
    return path


@pytest.fixture(scope="module")
def working_copy(tmp_path_factory) -> Path:
    """A private copy: opening a database must never dirty the repository."""
    import shutil

    source = _target()
    destination = tmp_path_factory.mktemp("idare2-parity") / source.name
    shutil.copy2(source, destination)
    return destination


@pytest.fixture(scope="module")
def r2(working_copy: Path):
    """Run one r2 command against the private copy."""
    binary = _require_r2()

    def run(command: str) -> list[str]:
        completed = subprocess.run(
            [binary, "-e", "scr.color=0", "-e", "scr.prompt=false",
             "-q", "-A", "-c", command, str(working_copy)],
            capture_output=True,
            text=True,
            timeout=R2_TIMEOUT,
        )
        return completed.stdout.splitlines()

    return run


@pytest.fixture(scope="module")
def session(working_copy: Path):
    try:
        with nexus.connect(
            nexus.Target(path=str(working_copy)), timeout=900, linger=0
        ) as handle:
            remote = rpc.Remote(handle, timeout=300)
            info = remote.call("open_summary")
            sess = Session(handle, remote, Config(), info, readonly=True)
            sess.setup()
            yield sess
    except Idare2Error as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"cannot attach to {working_copy}: {exc}")


# --------------------------------------------------------------------------
# normalisers
# --------------------------------------------------------------------------


def split_columns(line: str) -> list[str]:
    return line.split()


def pd_records(lines: list[str]) -> list[tuple[int, str]]:
    """(address, bytes) pairs from a ``pd`` listing.

    Drops mnemonics, operand syntax, comments and the gutter -- exactly the
    parts that belong to the disassembler rather than to the CLI.
    """
    out: list[tuple[int, str]] = []
    for line in lines:
        parts = split_columns(line)
        for index, part in enumerate(parts):
            if part.startswith("0x") and index + 1 < len(parts):
                raw = parts[index + 1]
                if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) % 2 == 0:
                    with contextlib.suppress(ValueError):
                        out.append((int(part, 16), raw.lower()))
                break
    return out


def px_rows(lines: list[str]) -> list[str]:
    """Hexdump rows with the address and byte cells only."""
    out = []
    for line in lines:
        parts = split_columns(line)
        if not parts or not parts[0].startswith("0x"):
            continue
        cells = "".join(part for part in parts[1:] if len(part) == 4)
        out.append(cells.lower())
    return out


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------


def test_hexdump_rows_match(session, r2) -> None:
    """``px`` is pure data formatting, so the rows should be identical."""
    address = 0x10000
    ours = px_rows(session.run(f"px 64 @ 0x{address:x}"))
    theirs = px_rows(r2(f"px 64 @ 0x{address:x}"))
    assert ours
    assert ours == theirs


def test_hexdump_header_matches(session, r2) -> None:
    address = 0x8D10
    ours = session.run(f"px 16 @ 0x{address:x}")[0]
    theirs = r2(f"px 16 @ 0x{address:x}")[0]
    assert ours == theirs


def test_disasm_instruction_boundaries_match(session, r2) -> None:
    """Both engines must walk the same instruction stream.

    Bytes are **not** compared: IDA applies ELF relocations when it loads a
    uClibc firmware binary (0x15e2c becomes a NOP after a GOT fixup) while r2
    leaves the file bytes alone.  What must agree is where instructions start
    and how long they are, because that is what every r2 command keys off.
    """
    address = 0x15E10
    ours = [item[0] for item in pd_records(session.run(f"pd 12 @ 0x{address:x}"))]
    theirs = [item[0] for item in pd_records(r2(f"pd 12 @ 0x{address:x}"))]
    assert ours, "idare2 produced no instruction records"
    assert theirs, "r2 produced no instruction records"

    shared_prefix = 0
    for left, right in zip(ours, theirs, strict=False):
        if left != right:
            break
        shared_prefix += 1
    assert shared_prefix >= min(len(ours), len(theirs)) - 1, (
        f"instruction boundaries diverge early: idare2={ours[:8]} r2={theirs[:8]}"
    )


def test_disasm_bytes_agree_on_unrelocated_code(session, r2) -> None:
    """In a region with no relocations, the byte columns should be identical."""
    address = 0x15E30  # past the GOT fixup at 0x15e2c
    ours = pd_records(session.run(f"pd 4 @ 0x{address:x}"))
    theirs = pd_records(r2(f"pd 4 @ 0x{address:x}"))
    assert ours and theirs
    assert ours == theirs


def test_assembly_matches_r2(session, r2) -> None:
    """`pa` should produce the same instruction encoding as r2's assembler."""
    if session.info.get("architecture") != "ARM" or session.info.get("bitness") != 32:
        pytest.skip("the parity target and its fixed NOP encoding are ARM32-specific")
    address = 0x15E10
    ours = session.run(f"pa nop @ 0x{address:x}")
    theirs = r2(f"pa nop @ 0x{address:x}")
    assert ours == ["0000a0e1"]
    assert ours == theirs


def test_pf_scalars_match_r2(session, r2) -> None:
    """``pf`` is byte formatting over the same data, so the rows are identical."""
    address = 0x15E30
    ours = session.run(f"pf xix @ 0x{address:x}")
    theirs = r2(f"pf xix @ 0x{address:x}")
    assert ours
    assert ours == theirs


def test_function_addresses_overlap(session, r2) -> None:
    """Both engines must find the same real functions, whatever they name them."""
    ours = {
        int(line.split()[0], 16)
        for line in session.run("afl")
        if line.startswith("0x")
    }
    theirs = {
        int(line.split()[0], 16)
        for line in r2("afl")
        if line.startswith("0x")
    }
    assert ours and theirs
    overlap = ours & theirs
    # IDA's FLIRT/signature matching finds more functions than r2, so require a
    # strong majority rather than equality.
    assert len(overlap) >= 0.5 * min(len(ours), len(theirs)), (
        f"weak overlap: idare2={len(ours)} r2={len(theirs)} shared={len(overlap)}"
    )


def _graph_edges(payload: list[dict]) -> dict[int, set[int]]:
    out = {}
    for block in payload[0]["blocks"]:
        out[int(block["addr"])] = {
            int(target)
            for target in (block.get("jump"), block.get("fail"))
            if target is not None
        }
    return out


def test_function_graph_blocks_and_edges_overlap(session, r2) -> None:
    """IDA and r2 may split blocks differently, but the CFG must agree broadly."""
    address = 0x15E10
    ours = json.loads("\n".join(session.run(f"agfj @ 0x{address:x}")))
    theirs = json.loads("\n".join(r2(f"agfj @ 0x{address:x}")))
    assert ours and theirs
    assert ours[0]["addr"] == theirs[0]["addr"] == address

    ours_edges = _graph_edges(ours)
    theirs_edges = _graph_edges(theirs)
    shared = set(ours_edges) & set(theirs_edges)
    assert shared
    assert len(shared) >= 0.5 * min(len(ours_edges), len(theirs_edges)), (
        f"weak block overlap: idare2={len(ours_edges)} r2={len(theirs_edges)} "
        f"shared={len(shared)}"
    )
    agreeing = sum(ours_edges[block] == theirs_edges[block] for block in shared)
    assert agreeing >= 0.5 * len(shared), (
        f"weak edge agreement on shared blocks: {agreeing}/{len(shared)}"
    )


def test_segment_table_shape(session, r2) -> None:
    """``iS`` must agree on the code segment's virtual address and size.

    The two tools print different column sets (r2 has ``nth paddr size vaddr
    vsize perm flags type name``, idare2 has ``nth paddr size vaddr vsize perm
    type name``), so this matches on the values rather than on a column index.
    """
    def text_segment(lines: list[str]) -> tuple[int, int]:
        for line in lines:
            if ".text" not in line:
                continue
            tokens = split_columns(line)
            # Both layouts open with nth/paddr/size/vaddr/vsize, so vaddr and
            # vsize sit at the same token positions even though r2 adds a
            # `flags` column further right.
            assert len(tokens) >= 6, f"unexpected iS row: {line!r}"
            return int(tokens[3], 16), int(tokens[4], 16)
        raise AssertionError("no .text segment found")

    ours_addr, ours_size = text_segment(session.run("iS"))
    theirs_addr, theirs_size = text_segment(r2("iS"))
    assert ours_addr == theirs_addr
    # ELF section vs loader segment granularity can differ by alignment padding.
    assert abs(ours_size - theirs_size) < 0x1000


def _import_rows(lines: list[str]) -> list[tuple[int, int | None, str, str, str]]:
    rows = []
    for line in lines[2:]:
        tokens = line.split()
        if len(tokens) < 5:
            continue
        vaddr = None if tokens[1].startswith("-") else int(tokens[1], 16)
        rows.append((int(tokens[0]), vaddr, tokens[2], tokens[3], tokens[4]))
    return rows


def test_import_table_matches_r2(session, r2) -> None:
    """``ii`` is dynsym order, so nth/vaddr/bind/type/name must all agree."""
    ours = _import_rows(session.run("ii"))
    theirs = _import_rows(r2("ii"))
    assert ours
    assert ours == theirs


def _symbol_rows(lines: list[str]) -> list[tuple[int, int | None, int, str, str, int, str]]:
    rows = []
    for line in lines[2:]:
        tokens = line.split()
        if len(tokens) < 7:
            continue
        paddr = None if tokens[1].startswith("-") else int(tokens[1], 16)
        vaddr = None if tokens[2].startswith("-") else int(tokens[2], 16)
        rows.append(
            (int(tokens[0]), paddr, vaddr, tokens[3], tokens[4], int(tokens[5]), tokens[6])
        )
    return rows


def test_symbol_table_matches_r2(session, r2) -> None:
    """``is`` needs the ELF section table IDA discards (SECT/FILE/SPCL rows)."""
    ours = _symbol_rows(session.run("is"))
    theirs = _symbol_rows(r2("is"))
    assert ours
    assert ours == theirs


def _relocation_rows(
    lines: list[str],
) -> list[tuple[int, int | None, str, int, str]]:
    rows = []
    for line in lines[2:]:
        tokens = line.split(None, 4)
        if len(tokens) < 5 or not tokens[0].startswith("0x"):
            continue
        paddr = None if tokens[1].startswith("-") else int(tokens[1], 16)
        rows.append(
            (int(tokens[0], 16), paddr, tokens[2], int(tokens[3]), tokens[4])
        )
    return rows


def test_relocation_table_matches_r2(session, r2) -> None:
    """``ir`` uses the raw ELF relocation sections, which IDA does not expose."""
    ours = _relocation_rows(session.run("ir"))
    theirs = _relocation_rows(r2("ir"))
    assert ours
    assert ours == theirs


def _header_field_rows(lines: list[str]) -> list[tuple[int, int, int, str]]:
    rows = []
    for line in lines:
        tokens = line.split()
        if len(tokens) < 4 or not tokens[0].startswith("0x"):
            continue
        rows.append((int(tokens[0], 16), int(tokens[1], 16), int(tokens[2], 16), tokens[3]))
    return rows


def test_header_field_rows_match_r2(session, r2) -> None:
    """``ih``: every field's vaddr, paddr, value and name must agree."""
    ours = _header_field_rows(session.run("ih"))
    theirs = _header_field_rows(r2("ih"))
    assert ours
    assert ours == theirs


def test_header_text_matches_r2(session, r2) -> None:
    """``iH`` prints the same fixed ``headers32`` table as the ELF plugin."""
    ours = session.run("iH")
    theirs = [line for line in r2("iH") if line.startswith("0x")]
    assert ours
    assert ours == theirs


def test_header_json_matches_r2(session, r2) -> None:
    """``ihj`` rows (minus the embedded pf decode) are identical."""
    ours = json.loads("\n".join(session.run("ihj")))
    theirs = json.loads("\n".join(r2("ihj")))
    # r2 evaluates the embedded `pf` at the field's vaddr through its IO map;
    # the header offsets (0..0x3e) sit below this firmware's first LOAD
    # (0x8000), so r2 reads 0xffff for every value.  idare2 decodes the field
    # bytes themselves, which is what the format describes, so compare rows.
    for row in ours + theirs:
        row.pop("pf", None)
    assert ours
    assert ours == theirs


def test_header_string_json_matches_r2(session, r2) -> None:
    """``iHj`` wraps the same header text, trailing newline included."""
    ours = json.loads("\n".join(session.run("iHj")))
    theirs = json.loads("\n".join(r2("iHj")))
    assert ours == theirs


def test_header_commands_match_r2(session, r2) -> None:
    """``ih*``/``iH*`` emit one flag per header field, byte for byte."""
    ours = session.run("ih*")
    theirs = [line for line in r2("ih*") if line.startswith("'")]
    assert ours
    assert ours == theirs
    assert session.run("iH*") == ours


def _string_rows(lines: list[str]) -> dict[str, list[tuple[int, int, str]]]:
    rows: dict[str, list[tuple[int, int, str]]] = {}
    for line in lines[2:]:
        tokens = line.split(None, 7)
        if len(tokens) < 8 or not tokens[1].startswith("0x") or not tokens[2].startswith("0x"):
            continue
        rows.setdefault(tokens[7], []).append(
            (int(tokens[1], 16), int(tokens[2], 16), tokens[5])
        )
    return rows


def test_string_addresses_and_sections_match_r2(session, r2) -> None:
    """``iz`` paddr and section come from the ELF section table, not IDA LOADs."""
    ours = _string_rows(session.run("iz"))
    theirs = _string_rows(r2("iz"))
    # Duplicate literals can be reported at different instances by the two
    # scanners; only unique texts pin down a single address and section.
    shared = {
        text for text in set(ours) & set(theirs)
        if len(ours[text]) == 1 and len(theirs[text]) == 1
    }
    assert len(shared) >= 100
    mismatched = [text for text in shared if ours[text] != theirs[text]]
    assert not mismatched, mismatched[:5]
