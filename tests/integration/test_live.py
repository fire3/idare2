"""End-to-end tests against a real IDA database.

Run with::

    uv run pytest -m real_ida

The target is ``$IDARE2_TEST_TARGET`` when set, otherwise a database placed at
``../vulfirm/VPN/Merlin-BE86/openvpn.i64`` relative to this checkout (a local
fixture, never committed).  Tests skip rather than fail when there is no
database to attach to, so the default suite stays offline.

These tests exercise the whole stack -- Nexus lease, remote bootstrap, the
ida-domain handlers, and the client-side formatters -- which unit tests cannot.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from idare2 import nexus, rpc
from idare2.config import Config
from idare2.errors import Idare2Error
from idare2.session import Session

pytestmark = pytest.mark.real_ida

#: A pre-built database next to this repository, if the checkout layout has one.
FALLBACK_TARGET = (
    Path(__file__).resolve().parents[3]
    / "vulfirm"
    / "VPN"
    / "Merlin-BE86"
    / "openvpn.i64"
)


def _target() -> Path:
    configured = os.environ.get("IDARE2_TEST_TARGET")
    if configured:
        path = Path(configured).expanduser()
        if not path.exists():
            pytest.skip(f"IDARE2_TEST_TARGET does not exist: {path}")
        return path
    if not FALLBACK_TARGET.exists():
        pytest.skip(
            "no IDA database available; set IDARE2_TEST_TARGET to an .i64 or executable"
        )
    return FALLBACK_TARGET


@pytest.fixture(scope="module")
def working_copy(tmp_path_factory) -> Path:
    """A private copy of the target.

    IDA rewrites an ``.i64`` whenever it closes one, even with no changes, so a
    test must never open a database that lives in a repository.
    """
    source = _target()
    destination = tmp_path_factory.mktemp("idare2-live") / source.name
    shutil.copy2(source, destination)
    return destination


@pytest.fixture(scope="module")
def session(working_copy: Path):
    try:
        with nexus.connect(
            nexus.Target(path=str(working_copy)), timeout=600, linger=0
        ) as handle:
            remote = rpc.Remote(handle, timeout=120)
            info = remote.call("open_summary")
            sess = Session(handle, remote, Config(), info, readonly=True)
            sess.setup()
            yield sess
    except Idare2Error as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"cannot attach to {working_copy}: {exc}")


def test_open_summary(session) -> None:
    assert session.info["architecture"]
    assert session.info["bitness"] in (16, 32, 64)
    assert session.info["filesize"]
    assert session.info["function_count"] > 0


def test_iI(session) -> None:
    lines = session.run("iI")
    assert any(line.startswith("arch") for line in lines)
    assert any(line.startswith("bits") for line in lines)


def test_it_hashes_the_input_file(session) -> None:
    """``itj`` hashes the input when reachable, otherwise uses the loader.

    The checked-in ``.i64`` was built on Windows, so its recorded input path
    (``C:\\...``) does not exist here: the fallback must still return the
    loader's md5/sha256 and simply omit sha1.  The file-read path is covered by
    the parity test, where the worker opens the ELF itself.
    """
    session.failed = False
    payload = json.loads("\n".join(session.run("itj")))
    assert payload["md5"] and payload["sha256"]
    assert payload["md5"] == session.info["md5"]
    assert payload["sha256"] == session.info["sha256"]
    assert not session.failed


def test_ia_lists_the_database_arch(session) -> None:
    """Without the original ELF, `ia` falls back to IDA's processor facts."""
    session.failed = False
    lines = session.run("ia")
    assert lines and lines[0].startswith("0   0x00000000 ")
    payload = json.loads("\n".join(session.run("iaj")))
    row = payload["bins"][0]
    assert row["arch"] and row["bits"] in (16, 32, 64)
    assert row["size"] == session.info["filesize"]
    assert not session.failed


def test_il_without_the_input_is_empty(session) -> None:
    """The .i64's recorded input is gone, so there is no ELF to read DT_NEEDED."""
    session.failed = False
    assert session.run("il") == []
    assert json.loads("\n".join(session.run("ilj"))) == []
    assert not session.failed


def test_iE_without_the_input_is_empty(session) -> None:
    """IDA cannot distinguish exports; without the ELF there are no rows.

    r2 still prints the table header and rule for an empty export table, so the
    text form keeps them while the JSON form is an empty array.
    """
    session.failed = False
    lines = session.run("iE")
    assert lines[0].startswith("nth paddr")
    assert json.loads("\n".join(session.run("iEj"))) == []
    assert not session.failed


def test_seek_history_name_forms(session) -> None:
    """``s==`` names each seek, ``s=*`` wraps it in r2 commands."""
    session.failed = False
    session.run("s 0x1000")
    session.run("s 0x2000")
    named = session.run("s==")
    assert named and " > " in named[0]
    commands = session.run("s=*")
    assert len(commands) == 3
    assert all(" ; " in line for line in commands)
    assert "# CUR " in commands[-1]
    assert session.run("s=!") == session.run("s=")
    assert session.run("s=j") == session.run("s=")


def test_afv_reports_hexrays_variables(session) -> None:
    """``afv``/``afvj`` expose Hex-Rays arguments and stack variables."""
    session.failed = False
    lines = session.run("afl")
    addresses = [line.split()[0] for line in lines]
    main = next((line.split()[0] for line in lines if line.endswith(" main")), None)
    candidates = [main] if main else addresses[:20]
    for address in candidates:
        session.run(f"s {address}")
        if session.run("afv"):
            break
    else:  # pragma: no cover - depends on the database
        pytest.skip("no function with Hex-Rays locals")

    payload = json.loads("\n".join(session.run("afvj")))
    assert set(payload) == {"reg", "sp", "bp"}
    assert payload["bp"] == []
    if payload["reg"]:
        assert set(payload["reg"][0]) == {"name", "kind", "type", "ref"}
    if payload["sp"]:
        ref = payload["sp"][0]["ref"]
        assert set(ref) == {"base", "offset"}
        assert isinstance(ref["offset"], int)
    assert not session.failed


def test_afx_reports_references_from_a_function(session) -> None:
    """Exercise the remote xref walk on a real database (types/shape only).

    Exact rows are not compared with r2: the two engines discover slightly
    different reference sets, but every row must carry r2's field names.
    """
    session.failed = False
    first = session.run("afl")[0].split()[0]
    rows = json.loads("\n".join(session.run(f"afxj @ {first}")))
    assert isinstance(rows, list)
    for row in rows:
        assert {"type", "from", "to"} <= set(row)
        assert row["type"] in ("CALL", "JUMP", "CODE", "DATA", "STRN")
    assert not session.failed


def test_iD_demangles_a_live_symbol(session) -> None:
    session.failed = False
    payload = json.loads("\n".join(session.run("iDj c++ _Z3foov")))
    assert payload["lang"] == "c++"
    assert payload["demangled"] == "foo(void)"
    failed = json.loads("\n".join(session.run("iDj c++ not_a_symbol")))
    assert failed == {
        "lang": "c++",
        "mangled": "not_a_symbol",
        "error": "Cannot demangle string",
    }
    assert not session.failed


def test_seek_sticks(session) -> None:
    # Regression: a temporary-seek scope used to restore the seek even for `s`,
    # which made `s main; s` print the old address.
    session.run("s 0x10000")
    assert session.run("s") == ["0x00010000"]


def test_pd_renders(session) -> None:
    lines = session.run("pd 5 @ 0x00016bb4")
    assert lines
    assert all(line >= "0x00016bb4" or line.startswith(("┌", "│", "└")) for line in lines)
    assert any("MOV" in line or "mov" in line for line in lines)


def test_pa_assembles_without_writing(session) -> None:
    """`pa` is the reverse of `pd`; it must work in a read-only session."""
    arch = str(session.info.get("architecture") or "")
    bits = session.info.get("bitness") or session.info.get("bits")
    if arch == "metapc":
        expected = "90"
    elif arch in ("ARM", "ARM64", "AARCH64") and bits == 64:
        expected = "1f2003d5"
    elif arch == "ARM" and bits == 32:
        expected = "0000a0e1"
    else:
        expected = None
    if expected is None:
        pytest.skip("no stable NOP encoding for this architecture")
    session.failed = False
    assert session.run("pa nop @ 0x00016bb4") == [expected]
    assert not session.failed, session.last_error


def test_wa_star_previews_without_write_permission(session) -> None:
    arch = str(session.info.get("architecture") or "")
    bits = session.info.get("bitness") or session.info.get("bits")
    if arch == "metapc":
        expected = "90"
    elif arch in ("ARM", "ARM64", "AARCH64") and bits == 64:
        expected = "1f2003d5"
    elif arch == "ARM" and bits == 32:
        expected = "0000a0e1"
    else:
        expected = None
    if expected is None:
        pytest.skip("no stable NOP encoding for this architecture")
    session.failed = False
    assert session.run("wa* nop @ 0x00016bb4") == [f"wx {expected}"]
    assert not session.failed, session.last_error


def test_px_renders(session) -> None:
    lines = session.run("px 16 @ 0x10000")
    assert lines[0].startswith("- offset -")
    assert lines[1].startswith("0x00010000  7f45 4c46")  # ELF magic


def test_afl_lists_functions(session) -> None:
    lines = session.run("afl")
    assert len(lines) > 1
    assert all(line.startswith("0x") for line in lines)


def test_aflq_lists_the_same_addresses(session) -> None:
    session.failed = False
    listed = [
        int(line.split()[0], 16) for line in session.run("afl") if line.startswith("0x")
    ]
    quiet = [int(line, 16) for line in session.run("aflq") if line.startswith("0x")]
    assert quiet
    assert quiet == listed


def test_afi_reports_function_info(session) -> None:
    """Regression: ``int(FunctionFlags)`` raised TypeError and killed ``afi``."""
    start = int(session.run("afl")[0].split()[0], 16)
    session.failed = False
    lines = session.run(f"afi @ 0x{start:x}")
    assert not session.failed, session.last_error
    assert f"addr: 0x{start:08x}" in lines
    assert any(line.startswith("size: ") and int(line.split()[1]) > 0 for line in lines)
    assert any(line.startswith("nbbs: ") for line in lines)


def test_sf_and_sF_seek(session) -> None:
    """``sf``/``sF`` both go through ``function_info`` and used to crash there."""
    start = int(session.run("afl")[0].split()[0], 16)
    session.failed = False

    session.run(f"s 0x{start:x}")
    session.run("sf")
    assert not session.failed, session.last_error
    assert session.seek == start

    session.run("sF")
    assert not session.failed, session.last_error
    assert session.seek > start


def test_iz_survives_decompilation(session) -> None:
    """Regression: after `pdc`, `iz` died with "16 is not a valid StringType".

    Hex-Rays can leave behind a string whose type code ida-domain's `StringType`
    IntEnum rejects; the failure was persistent across sessions, so the ordering
    matters more than the target.
    """
    session.failed = False
    session.run("pdc @ 0x00016bb4")
    assert not session.failed, session.last_error
    lines = session.run("iz")
    assert not session.failed, session.last_error
    assert len(lines) > 2
    assert lines[0].startswith("nth")


def test_ph_hashes_exactly_what_p8_reads(session) -> None:
    """`ph` and `p8` must agree byte for byte -- including IDA's ELF fixups.

    Against the raw file the digest would differ (IDA turns the GOT add at
    0x15e2c into a NOP), so the oracle is idare2's own read path.
    """
    import hashlib

    address = "0x00016bb4"
    hexbytes = session.run(f"p8 64 @ {address}")[0]
    expected = hashlib.sha256(bytes.fromhex(hexbytes)).hexdigest()
    assert session.run(f"ph sha256 64 @ {address}") == [expected]


def test_ph_is_registered_and_lists_algorithms(session) -> None:
    session.failed = False
    lines = session.run("ph")
    assert not session.failed, session.last_error
    assert len(lines) == 1
    assert "sha256" in lines[0].split()


def test_axt(session) -> None:
    lines = session.run("axt @ 0x00016bb4")
    assert lines


def test_iz(session) -> None:
    lines = session.run("iz")
    assert lines
    assert lines[0].startswith("nth")


def test_ii(session) -> None:
    """``ii`` used to die in the dispatcher: the handler took no offset/count."""
    session.failed = False
    lines = session.run("ii")
    assert not session.failed, session.last_error
    assert lines
    assert lines[0].split() == ["nth", "vaddr", "bind", "type", "lib", "name"]
    for line in lines[2:7]:
        ordinal, ea, bind, kind, name = line.split(None, 4)
        assert ordinal.isdigit()
        assert ea.startswith("0x") or ea == "----------"
        assert bind in {"GLOBAL", "LOCAL", "WEAK", "NONE"}
        assert kind
        assert name


def test_ii_paginates(session) -> None:
    def rows(lines: list[str]) -> list[str]:
        # `with_more` appends r2's "[+more; resume with -o N]" hint.
        return [
            line for line in lines[2:]
            if not line.startswith("[+") and not line.startswith("―")
        ]

    first = rows(session.run("ii 2"))
    assert len(first) == 2
    rest = rows(session.run("ii -o 2"))
    assert rest
    assert rest[0] != first[0]


def test_ir_has_the_radare2_relocation_columns(session) -> None:
    session.failed = False
    lines = session.run("ir")
    assert not session.failed, session.last_error
    assert lines[0].split() == ["vaddr", "paddr", "type", "ntype", "name"]
    rows = [line for line in lines[2:] if not line.startswith("―")]
    if not rows:
        pytest.skip("the target has no relocations")
    for line in rows[:5]:
        vaddr, paddr, kind, ntype, name = line.split(None, 4)
        assert vaddr.startswith("0x")
        assert paddr.startswith("0x") or paddr == "----------"
        assert kind in {"SET_32", "SET_64", "ADD_32", "ADD_64"}
        assert ntype.isdigit()
        assert name


def test_is_has_the_radare2_symbol_columns(session) -> None:
    session.failed = False
    lines = session.run("is")
    assert not session.failed, session.last_error
    assert lines[0].split() == [
        "nth", "paddr", "vaddr", "bind", "type", "size", "lib", "name", "demangled",
    ]
    rows = [line for line in lines[2:] if not line.startswith("―")]
    assert rows
    for line in rows[:5]:
        tokens = line.split()
        assert len(tokens) >= 7
        assert tokens[1].startswith("0x") or tokens[1] == "----------"
        assert tokens[2].startswith("0x") or tokens[2] == "----------"
        assert tokens[3] in {"LOCAL", "GLOBAL", "WEAK", "NUM", "UNKNOWN"}


def test_grep_filter(session) -> None:
    everything = session.run("afl")
    name = everything[0].split()[-1]
    filtered = session.run(f"afl~{name}")
    assert filtered
    assert all(name in line for line in filtered)


def test_json_suffix(session) -> None:
    import json

    payload = json.loads("\n".join(session.run("pdj 2 @ 0x00016bb4")))
    assert payload["lines"]
    assert isinstance(payload["lines"][0]["bytes"], str)
    assert isinstance(payload["lines"][0]["ea"], int)


def test_f_size_and_address_follow_r2_order(session) -> None:
    """`f name 16 @ addr` is a 16-byte flag at addr, not a flag at 0x10.

    The size/address split used to be inverted, so the documented form landed
    the flag on the size and the IDB write failed with InvalidEAError.
    """
    session.run("f sized_flag 16 @ 0x10000")
    rows = [line for line in session.run("f") if line.endswith(" sized_flag")]
    assert rows, "sized_flag not in the flag listing"
    address, size, _name = rows[0].split()
    assert int(address, 16) == 0x10000
    assert int(size) == 16


def test_seek_history_matches_r2_shape(session) -> None:
    """`s=` used to be a by-name lookup ("s= needs a name") rather than history.

    r2's chain is the undo history, oldest first, with the current seek left
    out: from 0xf3ac, `s 0x1000; s 0x2000; s 0x3000` gives
    `0xf3ac > 0x1000 > 0x2000`.  The session is shared across this module, so
    the test appends to whatever history is already there rather than assuming
    a clean one.  Address padding is idare2's own (it also drives the prompt).
    """
    session.failed = False
    current = session.run("s")[0]
    before = session.run("s=")[0]

    def chain(*extra: str) -> str:
        return " > ".join(part for part in (before, current, *extra) if part)

    session.run("s 0x1000")
    assert session.run("s=") == [chain()]
    session.run("s 0x2000")
    assert session.run("s=") == [chain("0x00001000")]
    session.run("s 0x3000")
    assert session.run("s=") == [chain("0x00001000", "0x00002000")]
    session.run("s-")
    assert session.run("s=") == [chain("0x00001000")]
    assert not session.failed, session.last_error


def test_asm_arch_and_bits_reflect_the_database(session) -> None:
    """The README documented these as read-only; the keys did not exist."""
    session.failed = False
    arch = session.run("e asm.arch")
    bits = session.run("e asm.bits")
    assert not session.failed, session.last_error
    assert arch == [session.info["architecture"]]
    assert bits == [str(session.info["bitness"])]

    session.failed = False
    session.run("e asm.arch=x86")
    assert session.failed, "asm.arch must not be settable"
    assert "read-only" in str(session.last_error)


def test_json_default_switches_the_commands_that_have_a_j_form(session) -> None:
    """`-j` used to be an empty switch: set on the session, read by nobody."""
    import json

    session.json_default = True
    try:
        session.failed = False
        payload = json.loads("\n".join(session.run("pd 2 @ 0x00016bb4")))
        assert payload["lines"][0]["ea"] == 0x00016BB4
        assert isinstance(json.loads("\n".join(session.run("afl"))), list)
        # No `j` form: must still render as text, not become a usage error.
        assert session.run("px 8 @ 0x00016bb4")[0].startswith("- offset -")
        assert not session.failed, session.last_error
    finally:
        session.json_default = False


def test_afb_and_afi_json_forms(session) -> None:
    """Regression: the `afbj`/`afij` guards were unreachable dead branches."""
    import json

    session.failed = False
    blocks = json.loads("\n".join(session.run("afbj @ 0x00016bb4")))
    assert blocks and blocks[0]["start"] == 0x00016BB4
    info = json.loads("\n".join(session.run("afij @ 0x00016bb4")))
    assert info["ea"] == 0x00016BB4
    assert not session.failed, session.last_error


def test_function_graph_forms(session) -> None:
    """The graph commands must work entirely through the live IDA backend."""
    import json

    address = 0x00016BB4
    session.failed = False
    graph = json.loads("\n".join(session.run(f"agfj @ 0x{address:x}")))
    assert not session.failed, session.last_error
    assert len(graph) == 1
    function = graph[0]
    assert function["addr"] <= address < function["addr"] + function["size"]
    assert function["blocks"]
    assert any(block["ops"] for block in function["blocks"])

    ascii_lines = session.run(f"agf @ 0x{address:x}")
    assert not session.failed, session.last_error
    text = "\n".join(ascii_lines)
    assert "-- " in text and "blocks " in text
    assert session.format_addr(function["addr"]) in text

    dot = session.run(f"agfd @ 0x{address:x}")
    assert not session.failed, session.last_error
    assert dot[0] == "digraph code {"
    assert dot[-1] == "}"
    assert session.format_addr(function["addr"]) in "\n".join(dot)


def test_sized_iterator_sets_and_restores_blocksize(session) -> None:
    session.failed = False
    session.blocksize = 64
    assert session.run("b @@@= 0x00016bb4 8 0x00016bb8 16") == ["8", "16"]
    assert not session.failed, session.last_error
    assert session.blocksize == 64

    saved_seek = session.seek
    try:
        session.run("s 0x00016bb4")
        block_sizes = session.run("b @@@b")
    finally:
        session.run(f"s 0x{saved_seek:x}")
    assert not session.failed, session.last_error
    assert block_sizes
    assert all(size.isdigit() and int(size) > 0 for size in block_sizes)
    assert session.blocksize == 64


def test_completion_uses_live_function_names(session) -> None:
    from idare2.complete import Completer

    name = session.run("afl")[0].split()[-1]
    prefix = name[: min(3, len(name))]
    completer = Completer(session)
    line = f"s {prefix}"
    assert name in completer.candidates(line, 2, len(line))
    assert "scr.color" in completer.candidates("e scr.co", 2, 8)


def test_pf_decodes_live_memory_and_named_formats(session) -> None:
    import json

    address = 0x00015E30
    payload = session.remote.call("read_bytes", ea=address, count=12)
    raw = bytes(payload.get("data") or b"")
    endian = str(session.info.get("endian") or "little")
    first = int.from_bytes(raw[0:4], endian)
    middle = int.from_bytes(raw[4:8], endian, signed=True)
    last = int.from_bytes(raw[8:12], endian)

    session.failed = False
    assert session.run(f"pf xix @ 0x{address:x}") == [
        f"{session.format_addr(address)} = 0x{first:08x}",
        f"{session.format_addr(address + 4)} = {middle}",
        f"{session.format_addr(address + 8)} = 0x{last:08x}",
    ]
    assert not session.failed, session.last_error

    assert session.run("pf.obj xix first second third") == []
    assert session.run(f"pf.obj @ 0x{address:x}")[0].startswith(" first : ")
    assert session.run("pfs.obj") == ["12"]
    rows = json.loads(session.run("pfj.obj @ 0x00015E30")[0])
    assert [row["value"] for row in rows] == [first, middle, last]


def test_bare_cc_lists_comments(session) -> None:
    """`CC` used to be unreachable: it demanded -w, then demanded text."""
    session.failed = False
    lines = session.run("CC")
    assert not session.failed, session.last_error
    assert lines
    assert all(line.startswith("0x") for line in lines[:10])
    # The read must not have needed a write.
    session.failed = False
    session.run("CC")
    assert not session.failed


def test_f_query_reports_the_address(session) -> None:
    """`f? name` used to print the whole `f` help table instead of an answer."""
    session.run("f queried_flag @ 0x10000")
    assert session.run("f? queried_flag") == ["0x00010000"]
    assert session.run("f?queried_flag") == ["0x00010000"]
    assert session.run("f? never_defined_flag") == []


def test_flags_degrade_to_session_local_when_readonly(session) -> None:
    """`f` is a naming convenience, so read-only mode keeps the r2 behaviour.

    Unlike `wx`/`CC`/`afn`, creating a flag does not require touching the
    database: without `-w` it becomes a session-local flag and warns once.
    """
    session.run("f test_flag @ 0x10000")
    assert session.flags.lookup("test_flag") == 0x10000


def test_fn_fq_and_fx_use_real_names(session) -> None:
    """``fq``/``fn``/``fnj`` read IDA's demangled names; ``fx`` dumps a flag.

    ``demangled_names`` walks the whole name table, so this also proves the
    remote operation is safe on a real database (and that its signature matches
    what the client sends).
    """
    session.failed = False
    names = session.run("fq")
    assert names
    lines = session.run("fn")
    assert len(lines) == len(names)
    assert all(line.startswith("0x") for line in lines)
    assert not session.failed

    payload = json.loads("\n".join(session.run("fnj")))
    assert len(payload) == len(names)
    assert all({"name", "size", "addr"} <= set(row) for row in payload)

    address = int(session.run("afl")[0].split()[0], 16)
    session.run(f"f fx_probe 4 @ 0x{address:x}")
    out = session.run("fx fx_probe")
    assert out[0] == f"0x{address:08x}"
    assert len(out) > 1


def test_readonly_blocks_database_writes(session) -> None:
    """`run` reports errors instead of raising, so assert on the recorded state."""
    from idare2.errors import ReadOnlyError

    session.failed = False
    session.run("afn renamed_function")
    assert session.failed
    assert isinstance(session.last_error, ReadOnlyError)


def test_unknown_command(session) -> None:
    from idare2.errors import UnknownCommand

    session.failed = False
    session.run("zzz")
    assert session.failed
    assert isinstance(session.last_error, UnknownCommand)


def test_pj_pt_and_pu_live(session) -> None:
    """The new print helpers work against a real database, not just fakes."""
    session.failed = False
    first = session.run("afl")[0].split()[0]
    encoded = session.run(f"pu 8 @ {first}")
    assert encoded and encoded[0].startswith("%") and len(encoded[0]) == 24
    wide = session.run(f"puw 8 @ {first}")
    assert wide and len(wide[0]) == 12
    timestamps = session.run(f"pt 8 @ {first}")
    assert len(timestamps) == 2
    beats = session.run(f"ptb 8 @ {first}")
    assert beats and beats[0].startswith("@")
    stats = session.run(f"p=d 8 @ {first}")
    assert stats[0].startswith("min:") and stats[-1].startswith("size (of block):")
    # `pj` on non-JSON memory yields nothing rather than crashing.
    lines = session.run(f"pj 16 @ {first}")
    assert lines == []
    assert not session.failed


def test_p6_round_trips_against_the_database(session) -> None:
    session.failed = False
    encoded = session.run("p6es hello world")
    assert encoded == ["aGVsbG8gd29ybGQ="]
    assert session.run("p6ds aGVsbG8gd29ybGQ=") == ["hello world"]
    first = session.run("afl")[0].split()[0]
    encoded_block = session.run(f"p6e 4 @ {first}")
    assert encoded_block and len(encoded_block[0]) > 0
    assert not session.failed


def test_wide_search_live(session) -> None:
    """``/w`` searches UTF-16LE bytes; each match is two bytes per character."""
    session.failed = False
    payload = json.loads("\n".join(session.run("/wj a")))
    assert payload["kind"] == "wide"
    assert payload["match"] == 2
    assert isinstance(payload["hits"], list)
    lines = session.run("/w a")
    for line in lines:
        assert len(line.split()) >= 3
        assert len(line.split()[2]) % 2 == 0
    assert not session.failed


def test_afu_resizes_a_function_on_a_writable_copy(working_copy: Path) -> None:
    """``afu`` is a database write, so it runs against a scratch copy only."""
    try:
        with nexus.connect(
            nexus.Target(path=str(working_copy)), timeout=600, linger=0
        ) as handle:
            remote = rpc.Remote(handle, timeout=120)
            info = remote.call("open_summary")
            session = Session(handle, remote, Config(), info, readonly=False)
            session.setup()
            for line in session.run("afl"):
                if not line.startswith("0x"):
                    continue
                ea = int(line.split()[0], 16)
                before = json.loads("\n".join(session.run(f"afij @ 0x{ea:x}")))
                if int(before["size"]) <= 4:
                    continue
                new_end = int(before["end"]) - 4
                session.failed = False
                session.run(f"s 0x{ea:x}")
                assert session.run(f"afu 0x{new_end:x}") == []
                assert not session.failed, session.last_error
                after = json.loads("\n".join(session.run(f"afij @ 0x{ea:x}")))
                assert int(after["end"]) == new_end
                return
            pytest.skip("no function large enough to resize")
    except Idare2Error as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"cannot attach to {working_copy}: {exc}")
