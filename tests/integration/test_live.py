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


def test_px_renders(session) -> None:
    lines = session.run("px 16 @ 0x10000")
    assert lines[0].startswith("- offset -")
    assert lines[1].startswith("0x00010000  7f45 4c46")  # ELF magic


def test_afl_lists_functions(session) -> None:
    lines = session.run("afl")
    assert len(lines) > 1
    assert all(line.startswith("0x") for line in lines)


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
    for line in lines[:5]:
        ordinal, ea, _module, name = line.split(None, 3)
        # IDA reports 0 for imports it has no explicit ordinal for.
        assert ordinal.isdigit()
        assert ea.startswith("0x")
        assert name


def test_ii_paginates(session) -> None:
    def rows(lines: list[str]) -> list[str]:
        # `with_more` appends r2's "[+more; resume with -o N]" hint.
        return [line for line in lines if not line.startswith("[+")]

    first = rows(session.run("ii 2"))
    assert len(first) == 2
    rest = rows(session.run("ii -o 2"))
    assert rest
    assert rest[0] != first[0]


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


def test_flags_degrade_to_session_local_when_readonly(session) -> None:
    """`f` is a naming convenience, so read-only mode keeps the r2 behaviour.

    Unlike `wx`/`CC`/`afn`, creating a flag does not require touching the
    database: without `-w` it becomes a session-local flag and warns once.
    """
    session.run("f test_flag @ 0x10000")
    assert session.flags.lookup("test_flag") == 0x10000


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
