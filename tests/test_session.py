"""Session-level behaviour that does not need a database.

Everything here is driven through a fake remote, which is enough because the
session's job is orchestration: parse, seek, dispatch, filter, pipe, report.
"""

from __future__ import annotations

import pytest

from idare2 import filter as grep
from idare2 import parser
from idare2.config import Config
from idare2.errors import CommandError, ReadOnlyError, UnknownCommand
from idare2.session import Session


class FakeRemote:
    """Answers the handful of ops the session itself uses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail: set[str] = set()

    def call(self, operation: str, **arguments):
        self.calls.append((operation, arguments))
        if operation in self.fail:
            raise CommandError(f"{operation} failed")
        handlers = {
            "symbols": lambda: [
                {"ea": 0x1000, "name": "main"},
                {"ea": 0x2000, "name": "helper"},
            ],
            "read_value": lambda: {"ea": arguments["ea"], "width": 4, "value": 0x11223344},
            "read_bytes": lambda: {
                "ea": arguments["ea"],
                "count": arguments["count"],
                "data": b"\xaa" * arguments["count"],
            },
            "search": lambda: {"hits": [0x1000, 0x1010], "kind": "bytes", "pattern": "aa"},
            "search_ranges": lambda: [{"start": 0x1000, "end": 0x2000, "name": ".text"}],
            "patch_bytes": lambda: {"ea": arguments["ea"], "size": 2},
            "patch_many": lambda: {"patches": len(arguments["patches"])},
            "set_name": lambda: {"ea": arguments["ea"], "name": arguments["name"]},
            "delete_name": lambda: {"ea": arguments["ea"]},
            "disasm": lambda: {
                "mode": "count",
                "ea": arguments["ea"],
                "func": None,
                "lines": [],
            },
        }
        if operation not in handlers:
            raise AssertionError(f"unexpected remote call {operation}")
        return handlers[operation]()

    def call_with_meta(self, operation: str, **arguments):
        # Mirrors Remote.call_with_meta, which returns (result, meta).
        return self.call(operation, **arguments), None

    @property
    def operations(self) -> list[str]:
        return [name for name, _ in self.calls]


def make_session(**info) -> tuple[Session, FakeRemote]:
    remote = FakeRemote()
    session = Session(
        handle=object(),
        remote=remote,
        config=Config(),
        info={"bits": 32, "start_ip": 0x1000, "filesize": 0x1000, "base_address": 0x1000, **info},
        readonly=False,
    )
    return session, remote


def test_seek_is_permanent() -> None:
    session, _ = make_session()
    session.run("s 0x2000")
    assert session.seek == 0x2000
    assert session.run("s") == ["0x00002000"]


def test_temporary_seek_is_restored() -> None:
    session, _ = make_session()
    session.run("s 0x2000")
    session.run("s 0x3000")  # history only; no remote involved
    assert session.seek == 0x3000


def test_seek_history() -> None:
    session, _ = make_session()
    session.seek_to(0x2000)
    session.seek_to(0x3000)
    session.run("s-")
    assert session.seek == 0x2000
    session.run("s+")
    assert session.seek == 0x3000


def test_names_seed_flags_lazily() -> None:
    session, remote = make_session()
    assert session.lookup_name("main") == 0x1000
    assert remote.operations.count("symbols") == 1
    # Cached: a second lookup does not hit the remote again.
    assert session.lookup_name("helper") == 0x2000
    assert remote.operations.count("symbols") == 1


def test_dummy_names_resolve_without_a_round_trip() -> None:
    session, remote = make_session()
    assert session.lookup_name("sub_15E10") == 0x15E10
    assert "symbols" not in remote.operations


def test_alias_is_a_variable() -> None:
    session, _ = make_session()
    session.run("$m=main")
    assert session.get_var("m") == 0x1000
    assert session.run("$m") == ["0x00001000"]


def test_failing_statement_does_not_stop_the_line() -> None:
    session, _ = make_session()
    session.remote.fail.add("symbols")
    out = session.run("?e one; zzz; ?e three")
    assert out == ["one", "three"]
    assert session.failed is True
    assert isinstance(session.last_error, UnknownCommand)


def test_failure_is_reported_to_stderr_not_stdout(capsys) -> None:
    session, _ = make_session()
    out = session.run("zzz")
    captured = capsys.readouterr()
    assert out == []
    assert "ERROR" in captured.err
    assert captured.out == ""


def test_readonly_blocks_writes() -> None:
    session, _ = make_session()
    session.readonly = True
    with pytest.raises(ReadOnlyError):
        session.run_statement(parser.parse_statement("wx 90"))


def test_write_cache_buffers_until_commit() -> None:
    session, remote = make_session()
    session.config.set("io.cache", True)
    session.run("wx aabb")
    session.run("wx ccdd")
    assert "patch_bytes" not in remote.operations
    assert len(session.write_cache) == 2
    session.run("wc+")
    assert remote.operations.count("patch_many") == 1
    assert session.write_cache == []


def test_write_cache_discard() -> None:
    session, remote = make_session()
    session.config.set("io.cache", True)
    session.run("wx aabb")
    session.run("wc-")
    assert session.write_cache == []
    assert "patch_many" not in remote.operations


def test_yank_and_paste() -> None:
    session, remote = make_session()
    session.run("y 4")
    assert session.yank == b"\xaa" * 4
    session.run("yy")
    patches = [args for name, args in remote.calls if name == "patch_bytes"]
    assert patches and patches[-1]["data"] == "aaaaaaaa"
    assert patches[-1]["ea"] == 0x1000


def test_search_creates_session_flags() -> None:
    session, _ = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    lines = session.run("/x aa")
    assert len(lines) == 2
    assert "hit0_0" in lines[0]
    assert session.flags.lookup("hit0_1") == 0x1010


def test_search_repeat_uses_the_last_query() -> None:
    session, remote = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    session.run("/x aa")
    before = len(remote.calls)
    session.run("//")
    searches = [args for name, args in remote.calls[before:] if name == "search"]
    assert searches and searches[0]["pattern"] == "aa"


def test_blocksize() -> None:
    session, _ = make_session()
    assert session.run("b") == ["256"]
    session.run("b 64")
    assert session.blocksize == 64
    session.run("b+16")
    assert session.blocksize == 80
    session.run("b-")
    assert session.blocksize == 79


def test_config_is_readonly_for_derived_keys() -> None:
    session, _ = make_session()
    session.config.reflect("ida.backend", "idalib")
    assert session.config.get_str("ida.backend") == "idalib"
    with pytest.raises(Exception, match="read-only"):
        session.config.set("ida.backend", "gui")


def test_tmpseek_applies_to_one_statement_only() -> None:
    session, remote = make_session()
    session.seek = 0x1111
    session.run("pd 1 @ 0x2222")
    assert session.seek == 0x1111
    disassembled = [args["ea"] for name, args in remote.calls if name == "disasm"]
    assert disassembled == [0x2222]


def test_grep_and_pipe_apply_per_statement() -> None:
    session, _ = make_session()
    session.seek = 0x1000
    out = session.run("?e first~irs")
    assert out == ["first"]
    assert grep.apply_spec(["x"], "x") == ["x"]


# ---------------------------------------------------------------------------
# ph (hash of a block)
# ---------------------------------------------------------------------------


def _block(byte: int, n: int) -> bytes:
    return bytes([byte]) * n


def test_ph_lists_algorithms_when_bare() -> None:
    """r2 prints the algorithm list for a bare `ph` rather than a digest."""
    session, _remote = make_session()
    lines = session.run("ph")
    assert len(lines) == 1
    assert "sha256" in lines[0].split()
    assert "md5" in lines[0].split()


def test_ph_digest_is_bare_hex_over_the_block_size() -> None:
    """r2 prints the digest with no algorithm prefix, sized by `b`."""
    import hashlib

    session, _remote = make_session()
    session.blocksize = 8
    # FakeRemote answers every read_bytes with 0xaa * count.
    assert session.run("ph sha256") == [hashlib.sha256(_block(0xAA, 8)).hexdigest()]


def test_ph_length_is_the_second_positional() -> None:
    import hashlib

    session, _remote = make_session()
    session.blocksize = 64
    assert session.run("ph sha256 8") == [hashlib.sha256(_block(0xAA, 8)).hexdigest()]
    assert session.run("ph md5 4") == [hashlib.md5(_block(0xAA, 4)).hexdigest()]


def test_ph_numeric_first_argument_is_a_length_not_a_symbol() -> None:
    """`ph 16` must not be resolved as an address named "16"."""
    import hashlib

    session, _remote = make_session()
    session.blocksize = 64
    assert session.run("ph 16") == [hashlib.sha256(_block(0xAA, 16)).hexdigest()]


def test_ph_algorithm_is_not_resolved_as_an_address() -> None:
    """Regression: `target = resolve(rest[0])` used to run before the ph branch."""
    session, remote = make_session()
    session.failed = False
    session.run("ph md5")
    assert not session.failed, session.last_error
    assert all(call[0] == "read_bytes" for call in remote.calls)


def test_ph_unknown_algorithm_is_an_explicit_error() -> None:
    session, _remote = make_session()
    session.failed = False
    assert session.run("ph nosuch") == []
    assert session.failed
    assert "unknown hash algorithm" in str(session.last_error)


def test_ph_reads_at_the_seek() -> None:
    session, remote = make_session()
    session.seek = 0x2000
    session.run("ph sha256 4")
    assert ("read_bytes", {"ea": 0x2000, "count": 4}) in remote.calls


# ---------------------------------------------------------------------------
# f: size comes before the address, as in r2
# ---------------------------------------------------------------------------


def _flag(session, name: str):
    session._ensure_flags()
    return session.flags._by_name.get(name)


def test_f_bare_flag_lands_at_the_seek_with_size_one() -> None:
    session, remote = make_session()
    session.seek = 0x15E10
    session.run("f zz1")
    flag = _flag(session, "zz1")
    assert (flag.ea, flag.size) == (0x15E10, 1)
    assert ("set_name", {"ea": 0x15E10, "name": "zz1"}) in remote.calls


def test_f_second_positional_is_the_size_not_the_address() -> None:
    """Regression: `f x 16` used to create a flag at 0x10 with size 1."""
    session, remote = make_session()
    session.seek = 0x15E10
    session.run("f zz2 16")
    flag = _flag(session, "zz2")
    assert (flag.ea, flag.size) == (0x15E10, 16)
    assert ("set_name", {"ea": 0x15E10, "name": "zz2"}) in remote.calls


def test_f_third_positional_is_the_address() -> None:
    session, _remote = make_session()
    session.seek = 0x15E10
    session.run("f zz3 16 0x10000")
    flag = _flag(session, "zz3")
    assert (flag.ea, flag.size) == (0x10000, 16)


def test_f_size_and_temporary_seek() -> None:
    session, _remote = make_session()
    session.seek = 0x15E10
    session.run("f zz4 16 @ 0x20000")
    flag = _flag(session, "zz4")
    assert (flag.ea, flag.size) == (0x20000, 16)
    # `@` is temporary: the real seek must be untouched.
    assert session.seek == 0x15E10


def test_f_temporary_seek_without_a_size() -> None:
    session, _remote = make_session()
    session.run("f zz5 @ 0x30000")
    flag = _flag(session, "zz5")
    assert (flag.ea, flag.size) == (0x30000, 1)


def test_f_a_large_number_is_a_size_rather_than_an_address() -> None:
    """r2: `f zz6 0x40000` -> size 0x40000 at the seek, not a flag at 0x40000."""
    session, _remote = make_session()
    session.seek = 0x15E10
    session.run("f zz6 0x40000")
    flag = _flag(session, "zz6")
    assert (flag.ea, flag.size) == (0x15E10, 0x40000)


def test_f_rejects_a_fourth_positional() -> None:
    session, _remote = make_session()
    session.failed = False
    assert session.run("f zz7 16 0x10000 extra") == []
    assert session.failed
    assert "unexpected argument" in str(session.last_error)


# ---------------------------------------------------------------------------
# f? -- a query, not help
# ---------------------------------------------------------------------------


def test_f_query_with_a_space_reports_the_address() -> None:
    """Regression: `f? name` printed the whole `f` help table instead."""
    session, _remote = make_session()
    session.run("f probe_flag @ 0x4242")
    assert session.run("f? probe_flag") == ["0x00004242"]


def test_f_query_without_a_space_reports_the_address() -> None:
    """r2 spells it `f?name`; the parser keeps that as a single token."""
    session, _remote = make_session()
    session.run("f probe_flag @ 0x4242")
    assert session.run("f?probe_flag") == ["0x00004242"]


def test_f_query_for_a_missing_flag_is_silent() -> None:
    session, _remote = make_session()
    session.failed = False
    assert session.run("f? no_such_flag") == []
    assert not session.failed
    assert session.run("f?no_such_flag") == []


def test_bare_f_query_still_prints_help() -> None:
    session, _remote = make_session()
    lines = session.run("f?")
    assert lines and lines[0].startswith("Usage: f")


def test_help_stays_help_for_commands_that_did_not_opt_in() -> None:
    """`query_suffix` is opt-in: `pd? foo` must still print the pd table."""
    session, _remote = make_session()
    lines = session.run("pd? 5")
    assert lines and lines[0].startswith("Usage: p[dDiI]")
