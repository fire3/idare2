"""Session-level behaviour that does not need a database.

Everything here is driven through a fake remote, which is enough because the
session's job is orchestration: parse, seek, dispatch, filter, pipe, report.
"""

from __future__ import annotations

import json

import pytest

from idare2 import filter as grep
from idare2 import parser
from idare2.config import Config
from idare2.errors import CommandError, ReadOnlyError, UnknownCommand, UsageError
from idare2.session import Session


class FakeRemote:
    """Answers the handful of ops the session itself uses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail: set[str] = set()
        self.search_hits = [0x1000, 0x1010]
        self.read_floor: int | None = None
        self.assembly = b"\x90"

    def _read_bytes(self, arguments: dict):
        ea = arguments["ea"]
        if self.read_floor is not None and ea < self.read_floor:
            raise CommandError(f"read outside mapped segment at 0x{ea:x}")
        return {
            "ea": ea,
            "count": arguments["count"],
            "data": b"\xaa" * arguments["count"],
        }

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
            "read_bytes": lambda: self._read_bytes(arguments),
            "search": lambda: {
                "hits": list(self.search_hits),
                "kind": "bytes",
                "pattern": "aa",
            },
            "search_ranges": lambda: [{"start": 0x1000, "end": 0x2000, "name": ".text"}],
            "segments": lambda: [
                {"vaddr": 0x1000, "vsize": 0x1000, "paddr": 0x4000, "name": ".text"}
            ],
            "patch_bytes": lambda: {"ea": arguments["ea"], "size": 2},
            "patch_many": lambda: {"patches": len(arguments["patches"])},
            "assemble": lambda: {
                "ea": arguments["ea"],
                "size": len(self.assembly),
                "data": self.assembly,
            },
            "deep_analyze": lambda: {
                "analyzed": True,
                "start": 0x1000,
                "end": 0x2000,
            },
            "file_info": lambda: {"filesize": 0x3000, "architecture": "ARM"},
            "file_hashes": lambda: {
                "md5": "0" * 32,
                "sha1": "1" * 40,
                "sha256": "2" * 64,
            },
            "save": lambda: {"saved": True},
            "set_name": lambda: {"ea": arguments["ea"], "name": arguments["name"]},
            "delete_name": lambda: {"ea": arguments["ea"]},
            "comments": lambda: (
                [{"ea": arguments["ea"], "comment": "here", "repeatable": False}]
                if "ea" in arguments
                else [
                    {"ea": 0x1000, "comment": "first", "repeatable": False},
                    {"ea": 0x2000, "comment": "second", "repeatable": True},
                ]
            ),
            "set_comment": lambda: {
                "ea": arguments["ea"],
                "text": arguments["text"],
                "repeatable": arguments.get("repeatable", False),
            },
            "disasm": lambda: {
                "mode": "count",
                "ea": arguments["ea"],
                "func": None,
                "lines": [
                    {
                        "ea": arguments["ea"],
                        "size": 4,
                        # The wire layer hands these back as bytes, not hex.
                        "bytes": b"\x00\xb0\xa0\xe3",
                        "text": "MOV R11, #0",
                        "comment": "",
                        "is_call": False,
                        "is_jump": False,
                        "targets": [],
                    }
                ],
            },
            "functions": lambda: [
                {"ea": 0x1000, "nbbs": 2, "size": 8, "name": "main"},
                {"ea": 0x2000, "nbbs": 1, "size": 16, "name": "helper"},
            ],
            "blocks": lambda: [
                {"start": 0x1000, "end": 0x1008, "size": 8, "index": 0},
                {"start": 0x1008, "end": 0x1018, "size": 16, "index": 1},
            ],
            "strings": lambda: [
                {"ea": 0x4000, "size": 6, "text": "first"},
                {"ea": 0x4100, "size": 12, "text": "second"},
            ],
            "relocations": lambda: [
                {
                    "vaddr": 0xF9128,
                    "paddr": 0xE9128,
                    "type": "SET_32",
                    "ntype": 22,
                    "name": "pthread_detach",
                    "is_ifunc": False,
                },
            ],
            "demangled_names": lambda: [
                {"ea": 0x1000, "realname": "main_real"},
            ],
            "demangle": lambda: {
                "demangled": "foo()" if arguments["symbol"] == "_Z3foov" else None
            },
            "archs": lambda: [
                {
                    "arch": "arm",
                    "bits": 32,
                    "offset": 0,
                    "size": 0x3000,
                    "abi": "eabi5",
                    "machine": "ARM",
                }
            ],
            "libs": lambda: ["libc.so.6", "libm.so.6"],
            "header_fields": lambda: {
                "bits": 32,
                "fields": [
                    {
                        "name": "ELF",
                        "vaddr": 0,
                        "paddr": 0,
                        "size": 4,
                        "value": 0x464C457F,
                        "format": "x",
                        "pf": [{"type": "x", "offset": 0, "value": 0x464C457F}],
                    },
                    {
                        "name": "Type",
                        "vaddr": 0x10,
                        "paddr": 0x10,
                        "size": 2,
                        "value": 2,
                        "format": "w",
                        "pf": [{"type": "w", "offset": 0x10, "value": 2}],
                    },
                ],
            },
            "function_info": lambda: {
                "ea": arguments["ea"],
                "end": arguments["ea"] + 8,
                "name": "main",
                "size": 8,
                "nbbs": 1,
                "ninstrs": 2,
                "callers": 0,
                "callees": 0,
                "locals": 0,
                "noreturn": False,
                "signature": "int main(void)",
                "flags": 0,
            },
            "graph": lambda: {
                "name": "main",
                "addr": arguments["ea"],
                "end": arguments["ea"] + 0x18,
                "ninstr": 6,
                "nargs": 0,
                "nlocals": 0,
                "size": 0x18,
                "stack": 0,
                "type": "fcn",
                "signature": "int main(void)",
                "blocks": [
                    {
                        "addr": arguments["ea"],
                        "size": 8,
                        "jump": arguments["ea"] + 0x10,
                        "fail": arguments["ea"] + 8,
                        "successors": [arguments["ea"] + 0x10, arguments["ea"] + 8],
                        "ops": [
                            {
                                "addr": arguments["ea"],
                                "size": 4,
                                "bytes": b"\x00\xb0\xa0\xe3",
                                "disasm": "MOV R11, #0",
                                "opcode": "MOV R11, #0",
                                "comment": "",
                                "type": "cpu",
                                "targets": [],
                            },
                            {
                                "addr": arguments["ea"] + 4,
                                "size": 4,
                                "bytes": b"\x02\x00\x00\x0a",
                                "disasm": "BEQ 0x1010",
                                "opcode": "BEQ 0x1010",
                                "comment": "branch",
                                "type": "jmp",
                                "targets": [arguments["ea"] + 0x10],
                            },
                        ],
                    },
                    {
                        "addr": arguments["ea"] + 8,
                        "size": 8,
                        "successors": [],
                        "ops": [
                            {
                                "addr": arguments["ea"] + 8,
                                "size": 4,
                                "bytes": b"\x01\x30\xa0\xe3",
                                "disasm": "MOV R3, #1",
                                "opcode": "MOV R3, #1",
                                "comment": "",
                                "type": "cpu",
                                "targets": [],
                            }
                        ],
                    },
                    {
                        "addr": arguments["ea"] + 0x10,
                        "size": 8,
                        "successors": [],
                        "ops": [],
                    },
                ],
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


def test_aaa_runs_deep_analysis() -> None:
    from types import SimpleNamespace

    session, remote = make_session()
    session.handle = SimpleNamespace(
        instance=SimpleNamespace(backend="idalib"),
        wait_autoanalysis=lambda _timeout: None,
    )
    assert session.run("aa") == ["-- analysis complete --"]
    assert session.run("aaa") == ["-- analysis complete (deep) --"]
    assert session.run("aaaa") == ["-- analysis complete (deep) --"]
    assert [name for name, _ in remote.calls].count("deep_analyze") == 2


def test_dot_ida_reports_the_backend() -> None:
    from types import SimpleNamespace

    session, _remote = make_session()
    session.handle = SimpleNamespace(
        instance=SimpleNamespace(
            backend="idalib",
            record_id="42-abcdef",
            pid=42,
            port=12345,
            idb_path="/tmp/target.i64",
        ),
        connected=True,
        keepalive=30.0,
    )
    assert session.run(".ida") == [
        "backend    idalib",
        "record-id  42-abcdef",
        "pid        42",
        "port       12345",
        "path       /tmp/target.i64",
        "keepalive  30s",
        "lease      attached",
    ]


def test_dot_idaexec_prints_stdout_and_result() -> None:
    from types import SimpleNamespace

    session, _remote = make_session()
    session.handle = SimpleNamespace(
        execute_python=lambda code: {
            "stdout": "hello\n",
            "stderr": "",
            "result": {"code": code},
        }
    )
    assert session.run(".idaexec 1+1") == ["hello", "{'code': '1+1'}"]


def test_dot_idawatch_prints_a_bounded_number_of_events() -> None:
    from types import SimpleNamespace

    class Subscription:
        def __init__(self) -> None:
            self.events = iter([{"type": "rename", "ea": 1}, {"type": "comment", "ea": 2}])
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.events)

        def close(self) -> None:
            self.closed = True

    subscription = Subscription()
    session, _remote = make_session()
    session.handle = SimpleNamespace(subscribe_idb_events=lambda: subscription)
    assert session.run(".idawatch 2") == [
        '{"ea": 1, "type": "rename"}',
        '{"ea": 2, "type": "comment"}',
    ]
    assert subscription.closed


def test_dot_idasave_requires_write_access() -> None:
    session, remote = make_session()
    session.run(".idasave")
    assert "save" in remote.operations

    readonly, readonly_remote = make_session()
    readonly.readonly = True
    readonly.run(".idasave")
    assert readonly.failed
    assert "save" not in readonly_remote.operations


def test_dot_idasync_refreshes_metadata_and_caches() -> None:
    session, _remote = make_session()
    session.flags.seed([(0x1000, "main")])
    assert session.flags.seeded
    assert session.run(".idasync") == []
    assert session.info["filesize"] == 0x3000
    assert session.info["architecture"] == "ARM"
    assert not session.flags.seeded


def test_dot_idaclose_honours_no_save() -> None:
    from types import SimpleNamespace

    calls = []
    session, _remote = make_session()
    session.handle = SimpleNamespace(
        instance=SimpleNamespace(record_id="42-abcdef"),
        shutdown_database=lambda *, save: calls.append(save),
    )
    assert session.run(".idaclose --no-save") == [
        "-- closed 42-abcdef (discarded unsaved changes) --"
    ]
    assert calls == [False]


def test_dot_idahelp_lists_extensions() -> None:
    session, _remote = make_session()
    lines = session.run(".idahelp")
    assert any(line.startswith(".ida ") for line in lines)
    assert any(line.startswith(".idaexec ") for line in lines)


def test_dot_prefix_still_executes_output_as_commands() -> None:
    """Only the fixed ``.ida*`` names are intercepted."""
    session, _remote = make_session()
    assert session.run(". ?e ?e hi") == ["hi"]


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


@pytest.mark.parametrize(
    "command", ["y8", "yj", "y*", "yp", "y-", "y!", "yg", "yz"]
)
def test_unknown_yank_suffixes_fail_loudly(command: str) -> None:
    """Regression: these used to fall through and yank from memory instead."""
    session, remote = make_session()
    session.failed = False
    session.run(command)
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported yank command" in str(session.last_error)
    assert "read_bytes" not in remote.operations
    assert session.yank == b""


def test_compare_accepts_the_implemented_forms() -> None:
    session, _remote = make_session()
    for command in (
        "c 0x1000 0x1010 4",
        "cc 0x1000 0x1010 4",
        "c1 0x1000 0x1010 4",
    ):
        session.failed = False
        assert session.run(command) == ["-- blocks are identical --"]
        assert not session.failed


@pytest.mark.parametrize(
    "command",
    [
        "c2 0x1000 0x2000 4",
        "c4 0x1000 0x2000 4",
        "c8 0x1000 0x2000 4",
        "cf /etc/hostname",
        "cat /etc/hostname",
        "cd /tmp",
        "cj foo",
        "c* foo",
        "cu 0x1000",
    ],
)
def test_unknown_compare_suffixes_fail_loudly(command: str) -> None:
    """Regression: c2/c4/c8/cf/... silently ran the c comparison."""
    session, remote = make_session()
    session.failed = False
    session.run(command)
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported compare command" in str(session.last_error)
    assert "read_bytes" not in remote.operations


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


def test_sized_iterator_pairs_set_seek_and_blocksize_then_restore() -> None:
    session, _remote = make_session()
    session.seek = 0x3000
    session.blocksize = 64

    assert session.run("s @@@= 0x1000 8 0x2000 16") == [
        "0x00001000",
        "0x00002000",
    ]
    assert session.run("b @@@= 0x1000 8 0x2000 16") == ["8", "16"]
    assert session.seek == 0x3000
    assert session.blocksize == 64


def test_sized_iterator_ignores_a_trailing_unpaired_value() -> None:
    """r2 only runs explicitly paired addresses, then stops."""
    session, _remote = make_session()
    assert session.run("b @@@= 0x1000 8 0x2000") == ["8"]


def test_sized_iterator_rejects_a_negative_size() -> None:
    session, _remote = make_session()
    session.failed = False
    assert session.run("b @@@= 0x1000 -1") == []
    assert session.failed
    assert "size must not be negative" in str(session.last_error)


def test_sized_iterators_for_blocks_and_functions() -> None:
    session, _remote = make_session()
    session.seek = 0x1000
    session.blocksize = 64

    assert session.run("b @@@b") == ["8", "16"]
    assert session.run("b @@@F") == ["8", "16"]
    assert session.blocksize == 64


def test_sized_iterators_for_instructions_flags_and_strings() -> None:
    session, _remote = make_session()
    session.run("f zz 32 @ 0x3000")

    assert session.run("b @@@i") == ["4"]
    assert session.run("b @@@f:zz") == ["32"]
    assert session.run("b @@@z") == ["6", "12"]


def test_sized_iterator_segments_and_unknown_selector() -> None:
    session, _remote = make_session()
    assert session.run("b @@@S") == ["4096"]
    assert session.run("b @@@SS") == ["4096"]

    session.failed = False
    assert session.run("b @@@q") == []
    assert session.failed
    assert "unsupported @@@ iterator" in str(session.last_error)


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


def test_run_propagates_quit_instead_of_reporting_it_as_an_error() -> None:
    """`q` must unwind out of the whole line, not be logged and skipped.

    Output is collected through `emit`, which is the path the CLI uses: `q`
    aborts the statement loop, so nothing after it runs, and it is not recorded
    as a command failure (which would have set the exit code to 1).
    """
    from idare2.errors import QuitRequested

    session, _remote = make_session()
    seen: list[str] = []
    with pytest.raises(QuitRequested) as caught:
        session.run("?e before; q; ?e after", emit=seen.extend)
    assert caught.value.code == 0
    assert seen == ["before"]
    assert not session.failed
    assert session.last_error is None


def test_quit_carries_the_requested_exit_code() -> None:
    from idare2.errors import QuitRequested

    session, _remote = make_session()
    with pytest.raises(QuitRequested) as caught:
        session.run("q 3")
    assert caught.value.code == 3


def test_grep_and_pipe_apply_per_statement() -> None:
    session, _ = make_session()
    session.seek = 0x1000
    out = session.run("?e first~irs")
    assert out == ["first"]
    assert grep.apply_spec(["x"], "x") == ["x"]


def test_pager_filter_warns_once_and_keeps_output(capsys) -> None:
    session, _ = make_session()
    assert session.run("?e hello~..") == ["hello"]
    err = capsys.readouterr().err
    assert "Internal less requires scr.interactive=true" in err
    assert "not implemented" not in err
    # A second use is silent: warn_once keys on the pager kind.
    assert session.run("?e again~..") == ["again"]
    assert capsys.readouterr().err == ""


def test_hud_filter_warns_and_keeps_output(capsys) -> None:
    session, _ = make_session()
    assert session.run("?e hello~...") == ["hello"]
    assert "Hud mode requires scr.interactive=true" in capsys.readouterr().err


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
# fq / fn / fnj / fN / fr / fx -- explicit suffixes, never a fall-through
# ---------------------------------------------------------------------------


def test_fq_lists_only_names() -> None:
    session, _remote = make_session()
    assert session.run("fq") == ["main", "helper"]


def test_fn_lists_real_names() -> None:
    session, _remote = make_session()
    assert session.run("fn") == [
        "0x00001000 1 main_real",
        "0x00002000 1 helper",
    ]


def test_fnj_marks_only_differing_real_names() -> None:
    session, _remote = make_session()
    rows = json.loads("\n".join(session.run("fnj")))
    assert rows == [
        {"name": "main", "realname": "main_real", "size": 1, "addr": 0x1000},
        {"name": "helper", "size": 1, "addr": 0x2000},
    ]


def test_fN_shows_the_real_name_at_the_seek() -> None:
    session, _remote = make_session()
    session.seek = 0x1000
    assert session.run("fN") == ["main_real"]
    session.seek = 0x3000
    assert session.run("fN") == []


def test_fN_set_is_refused() -> None:
    session, _remote = make_session()
    session.failed = False
    session.run("fN main other")
    assert session.failed
    assert "real-name" in str(session.last_error)


def test_fr_renames_the_flag_at_the_seek() -> None:
    session, remote = make_session()
    session.seek = 0x1000
    assert session.run("fr renamed") == []
    assert _flag(session, "renamed").ea == 0x1000
    assert _flag(session, "main") is None
    assert ("set_name", {"ea": 0x1000, "name": "renamed"}) in remote.calls


def test_fr_renames_a_named_flag_and_keeps_its_size() -> None:
    session, remote = make_session()
    session.run("f big 64 @ 0x2000")
    assert session.run("fr big huge") == []
    flag = _flag(session, "huge")
    assert (flag.ea, flag.size) == (0x2000, 64)
    assert _flag(session, "big") is None
    assert ("set_name", {"ea": 0x2000, "name": "huge"}) in remote.calls


def test_fr_without_a_flag_reports_an_error() -> None:
    session, _remote = make_session()
    session.failed = False
    session.run("fr nothing_here renamed")
    assert session.failed
    assert "no flag" in str(session.last_error)
    session.failed = False
    session.seek = 0x5000
    session.run("fr renamed")
    assert session.failed
    assert "no flag at the current address" in str(session.last_error)


def test_fx_hexdumps_the_flag_bytes() -> None:
    session, _remote = make_session()
    session.run("f blob 4 @ 0x5000")
    expected = ["0x00005000", *session.run("px 4 @ 0x5000")]
    assert session.run("fx blob") == expected


def test_known_suffix_with_arguments_does_not_create_a_flag() -> None:
    """Regression: `fn foo` used to create a flag named "foo"."""
    session, remote = make_session()
    session.failed = False
    session.run("fn foo")
    assert session.failed
    assert session.flags.get("foo") is None
    assert not any(name == "set_name" for name, _ in remote.calls)


@pytest.mark.parametrize(
    "command",
    [
        "fz", "fs", "ft", "fi", "f=", "f+", "f--", "fa", "fb", "fc",
        "fd", "fl", "fo", "fO", "fh", "fu", "fv", "f.",
    ],
)
def test_unknown_f_suffixes_fail_loudly(command: str) -> None:
    """Regression: unimplemented suffixes fell through to `_create` or crashed."""
    session, remote = make_session()
    session.failed = False
    session.run(command)
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported flag command" in str(session.last_error)
    assert not any(name == "set_name" for name, _ in remote.calls)


def test_f_suffix_errors_do_not_abort_the_line() -> None:
    """The old `IndexError` escaped `Session.run` and killed the rest of a line."""
    session, _remote = make_session()
    assert session.run("?e before; fz; ?e after") == ["before", "after"]
    assert session.failed


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


# ---------------------------------------------------------------------------
# C / CC: the comment list must not demand -w
# ---------------------------------------------------------------------------


def _readonly() -> tuple[Session, FakeRemote]:
    from idare2.config import Config

    remote = FakeRemote()
    session = Session(
        handle=object(),
        remote=remote,
        config=Config(),
        info={"bits": 32, "start_ip": 0x1000, "filesize": 0x1000, "base_address": 0x1000},
        readonly=True,
    )
    return session, remote


def test_bare_cc_lists_comments_in_a_readonly_session() -> None:
    """Regression: `CC` errored with "would modify the database" instead."""
    session, remote = _readonly()
    session.failed = False
    lines = session.run("CC")
    assert not session.failed, session.last_error
    assert lines == ["0x00001000 first", "0x00002000 second"]
    assert all(name != "set_comment" for name in remote.operations)


def test_cc_with_text_still_requires_a_write() -> None:
    session, _remote = _readonly()
    session.failed = False
    assert session.run("CC a comment") == []
    assert session.failed
    from idare2.errors import ReadOnlyError

    assert isinstance(session.last_error, ReadOnlyError)


def test_cc_with_text_writes_when_writable() -> None:
    session, remote = make_session()
    session.seek = 0x5000
    session.run("CC a comment")
    assert ("set_comment", {"ea": 0x5000, "text": "a comment", "repeatable": False}) in remote.calls


def test_ccr_marks_the_comment_repeatable() -> None:
    session, remote = make_session()
    session.seek = 0x5000
    session.run("CCr note")
    assert ("set_comment", {"ea": 0x5000, "text": "note", "repeatable": True}) in remote.calls


def test_ccr_without_text_names_itself_in_the_error() -> None:
    session, _remote = make_session()
    session.failed = False
    assert session.run("CCr") == []
    assert session.failed
    assert "CCr needs comment text" in str(session.last_error)


# ---------------------------------------------------------------------------
# -j: JSON becomes the default for the commands that have a `j` form
# ---------------------------------------------------------------------------


def _json_default() -> tuple[Session, FakeRemote]:
    session, remote = make_session()
    session.json_default = True
    return session, remote


def test_json_default_switches_pd_to_json() -> None:
    import json

    session, _remote = _json_default()
    payload = json.loads("\n".join(session.run("pd 2 @ 0x1000")))
    assert payload["mode"] == "count"


def test_json_default_leaves_commands_without_a_j_form_alone() -> None:
    """A blanket "append j" would turn `px` into a usage error."""
    session, _remote = _json_default()
    lines = session.run("px 8 @ 0x1000")
    assert lines[0].startswith("- offset -")


def test_pc_matches_r2_c_array_layout() -> None:
    session, _remote = make_session()
    assert session.run("pc 4 @ 0x1000") == [
        "#define _BUFFER_SIZE 4",
        "const uint8_t buffer[_BUFFER_SIZE] = {",
        "  0xaa, 0xaa, 0xaa, 0xaa",
        "};",
    ]


def test_pc_suffixes_match_r2() -> None:
    session, _remote = make_session()
    assert session.run("pcj 4 @ 0x1000") == ["[170,170,170,170]"]
    assert session.run("pc* 4 @ 0x1000") == ["wx+aaaaaaaa;", "s-4"]
    assert session.run("pcq 4 @ 0x1000") == ["  0xaa, 0xaa, 0xaa, 0xaa"]
    assert session.run("pcp 4 @ 0x1000") == [
        "import struct",
        'buf = struct.pack ("4B", *[',
        "0xaa,0xaa,0xaa,0xaa])",
    ]


def test_comment_star_emits_replayable_base64_commands() -> None:
    session, _remote = make_session()
    assert session.run("CC*") == [
        "CCu base64:Zmlyc3Q= @ 0x00001000",
        "CCu base64:c2Vjb25k @ 0x00002000",
    ]
    assert session.run("C*") == session.run("CC*")


def test_json_default_is_off_by_default() -> None:
    session, _remote = make_session()
    lines = session.run("pd 2 @ 0x1000")
    assert any("MOV R11, #0" in line for line in lines)
    assert not lines[0].startswith(("{", "["))


def test_json_default_does_not_double_the_suffix() -> None:
    import json

    session, _remote = _json_default()
    json.loads("\n".join(session.run("pdj 2 @ 0x1000")))


def test_json_default_keeps_help_as_help() -> None:
    session, _remote = _json_default()
    assert session.run("pd?")[0].startswith("Usage: p[dDiI]")


def test_json_default_switches_afl_and_afi() -> None:
    import json

    session, _remote = _json_default()
    assert json.loads("\n".join(session.run("afl")))[0]["name"] == "main"
    assert json.loads("\n".join(session.run("afi @ 0x1000")))["name"] == "main"


def test_json_default_switches_agf_without_touching_agfd() -> None:
    import json

    session, _remote = _json_default()
    assert json.loads("\n".join(session.run("agf @ 0x1000")))[0]["name"] == "main"
    assert session.run("agfd @ 0x1000")[0] == "digraph code {"


def test_afb_and_afi_json_forms_are_reachable() -> None:
    """`afbj`/`afij` used to fall through to "unsupported function command".

    The JSON branch inside each guard was dead code: the guard compared the
    whole token, so `afbj != "afb"` never entered the branch that tested for
    the `j` suffix.
    """
    import json

    session, _remote = make_session()
    blocks = json.loads("\n".join(session.run("afbj @ 0x1000")))
    assert blocks[0]["start"] == 0x1000
    info = json.loads("\n".join(session.run("afij @ 0x1000")))
    assert info["name"] == "main"


def test_aflq_lists_addresses_only() -> None:
    session, _remote = make_session()
    assert session.run("aflq") == ["0x00001000", "0x00002000"]


@pytest.mark.parametrize(
    "command",
    ["afl*", "aflm", "afll", "afln", "afls", "aflt", "afl,", "aflc", "aflp", "afl+", "afl="],
)
def test_unimplemented_afl_modifiers_fail_loudly(command: str) -> None:
    """Regression: these used to print the ordinary `afl` table."""
    session, remote = make_session()
    session.failed = False
    session.run(command)
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported function command" in str(session.last_error)
    assert "functions" not in remote.operations


def test_agfj_reports_a_radare2_shaped_function_graph() -> None:
    import json

    session, remote = make_session()
    payload = json.loads("\n".join(session.run("agfj @ 0x1000")))

    assert payload[0]["name"] == "main"
    assert payload[0]["addr"] == 0x1000
    first = payload[0]["blocks"][0]
    assert (first["addr"], first["size"]) == (0x1000, 8)
    assert first["jump"] == 0x1010
    assert first["fail"] == 0x1008
    assert first["successors"] == [0x1010, 0x1008]
    # bytes go through the JSON wire encoder as hexpairs, not Python reprs.
    assert first["ops"][0]["bytes"] == "00b0a0e3"
    assert ("graph", {"ea": 0x1000}) in remote.calls


def test_agf_renders_blocks_and_jump_fail_edges() -> None:
    session, _remote = make_session()
    text = "\n".join(session.run("agf @ 0x1000"))

    assert "main @ 0x00001000" in text
    assert "0x00001000  [#0]  size 8" in text
    assert "MOV R11, #0" in text
    assert "jump 0x00001010" in text
    assert "fail 0x00001008" in text
    assert "┌" in text and "└" in text


def test_agfd_and_agg_emit_graphviz_dot() -> None:
    session, _remote = make_session()
    for token in ("agfd", "agg", "aggd"):
        lines = session.run(f"{token} @ 0x1000")
        assert lines[0] == "digraph code {"
        assert lines[-1] == "}"
        text = "\n".join(lines)
        assert '"0x00001000" -> "0x00001010" [color="#13a10e"]' in text
        assert '"0x00001000" -> "0x00001008" [color="#c50f1f"]' in text


def test_agj_is_an_alias_for_agfj() -> None:
    import json

    session, _remote = make_session()
    assert json.loads("\n".join(session.run("agj @ 0x1000")))[0]["name"] == "main"


# ---------------------------------------------------------------------------
# e asm.arch / asm.bits -- derived, read-only, but present
# ---------------------------------------------------------------------------


def _setup_session(**info) -> tuple[Session, FakeRemote]:
    """A session that has run `setup()`, which reflects the database facts."""
    from types import SimpleNamespace

    remote = FakeRemote()
    session = Session(
        handle=SimpleNamespace(
            instance=SimpleNamespace(backend="idalib", record_id="1234-abcd")
        ),
        remote=remote,
        config=Config(),
        info={
            "bits": 32,
            "start_ip": 0x1000,
            "filesize": 0x1000,
            "base_address": 0x1000,
            "architecture": "ARM",
            "bitness": 32,
            "endian": "little",
            **info,
        },
        readonly=True,
    )
    session.setup()
    return session, remote


def test_asm_arch_and_bits_are_readable() -> None:
    """Regression: the README called them read-only, but the keys did not exist."""
    session, _remote = _setup_session()
    assert session.run("e asm.arch") == ["ARM"]
    assert session.run("e asm.bits") == ["32"]


def test_asm_arch_and_bits_appear_in_the_config_listing() -> None:
    session, _remote = _setup_session()
    listing = session.run("e")
    assert any(line.startswith("asm.arch") for line in listing)
    assert any(line.startswith("asm.bits") for line in listing)


def test_asm_arch_reflects_the_database() -> None:
    session, _remote = _setup_session(architecture="MIPS", bitness=64)
    assert session.run("e asm.arch") == ["MIPS"]
    assert session.run("e asm.bits") == ["64"]


def test_asm_arch_cannot_be_set() -> None:
    """The only way to change the architecture is to import with -a/-b."""
    session, _remote = _setup_session()
    session.failed = False
    session.run("e asm.arch=x86")
    assert session.failed
    assert "read-only" in str(session.last_error)


def test_asm_keys_have_a_help_row() -> None:
    session, _remote = _setup_session()
    lines = session.run("e asm.arch?")
    assert any("asm.arch" in line for line in lines)
    assert any("read-only" in line for line in lines)


# ---------------------------------------------------------------------------
# s= -- the undo seek history, as r2 prints it
# ---------------------------------------------------------------------------


def test_seek_history_is_empty_before_any_seek() -> None:
    session, _remote = make_session()
    assert session.run("s=") == [""]


def test_seek_history_starts_with_the_initial_address() -> None:
    session, _remote = make_session()
    session.run("s 0x2000")
    assert session.run("s=") == ["0x00001000"]


def test_seek_history_is_oldest_first_and_excludes_the_current_seek() -> None:
    """r2: `0xf3ac > 0x1000 > 0x2000` after three seeks from 0xf3ac."""
    session, _remote = make_session()
    session.run("s 0x2000")
    session.run("s 0x3000")
    session.run("s 0x4000")
    assert session.run("s=") == ["0x00001000 > 0x00002000 > 0x00003000"]


def test_undo_shortens_the_history() -> None:
    session, _remote = make_session()
    session.run("s 0x2000")
    session.run("s 0x3000")
    session.run("s-")
    assert session.run("s=") == ["0x00001000"]


def test_history_modifiers_are_reported_as_unimplemented() -> None:
    """r2 documents s[j*=!]; saying so beats inventing output for them."""
    session, _remote = make_session()
    for token in ("s==", "s=*", "s=!", "s=j"):
        session.failed = False
        assert session.run(token) == []
        assert session.failed, token
        assert "not implemented yet" in str(session.last_error)


def test_s_still_seeks_to_a_name() -> None:
    """`s=` used to be the by-name lookup; plain `s name` keeps working."""
    session, _remote = make_session()
    session.run("s helper")
    assert session.seek == 0x2000


# ---------------------------------------------------------------------------
# $ variables, ? commands and the i/w command families
# ---------------------------------------------------------------------------


def test_dollar_assignment_and_query_are_distinct_commands() -> None:
    session, _remote = make_session()
    assert session.run("$foo=0x1234") == []
    assert session.run("$foo") == ["0x00001234"]
    assert session.run("$foo-") == []
    session.failed = False
    assert session.run("$foo") == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)


def test_question_set_last_result() -> None:
    session, _remote = make_session()
    assert session.run("?= 5") == []
    assert session.run("?v $?") == ["0x5"]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("?h abc", ["0x0ad5a985"]),
        ("?l abc", ["3"]),
        ("?f 5 abc", ["AC"]),
        ("?s 1 5 2", ["1 3 5 "]),
    ],
)
def test_question_value_commands(command: str, expected: list[str]) -> None:
    session, _remote = make_session()
    assert session.run(command) == expected


def test_question_version_is_not_the_generic_help() -> None:
    session, _remote = make_session()
    lines = session.run("?V")
    assert lines[0].startswith("idare2")
    assert not any(line.startswith("Usage: ?") for line in lines)


@pytest.mark.parametrize("command", ["?d", "?d 5"])
def test_unsupported_question_command_is_an_error(command: str) -> None:
    session, _remote = make_session()
    assert session.run(command) == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported question command" in str(session.last_error)


@pytest.mark.parametrize(("command", "expected"), [("wi1+1", "45"), ("wi1-1", "43"), ("wi2+ 1", "4533"), ("wi4- 1", "43332211")])
def test_write_increment_forms(command: str, expected: str) -> None:
    session, remote = make_session()
    assert session.run(command) == []
    patches = [arguments for name, arguments in remote.calls if name == "patch_bytes"]
    assert patches[-1]["data"] == expected


def test_bare_write_increment_is_a_noop() -> None:
    session, remote = make_session()
    assert session.run("wi1") == []
    assert not session.failed
    assert "patch_bytes" not in remote.operations


def test_pa_prints_hexpairs_without_writing() -> None:
    session, remote = make_session()
    session.seek = 0x2000

    assert session.run("pa nop") == ["90"]
    assert ("assemble", {"ea": 0x2000, "text": "nop"}) in remote.calls
    assert "patch_bytes" not in remote.operations


def test_pa_honours_temporary_seek_and_quoted_instructions() -> None:
    session, remote = make_session()
    remote.assembly = b"\x90\x90"

    assert session.run('pa "nop;nop" @ 0x2000') == ["9090"]
    assert ("assemble", {"ea": 0x2000, "text": "nop;nop"}) in remote.calls
    assert session.seek == 0x1000


def test_pa_is_read_only() -> None:
    session, _remote = make_session()
    session.readonly = True
    assert session.run("pa nop") == ["90"]
    assert not session.failed, session.last_error


def test_pa_needs_an_instruction() -> None:
    session, remote = make_session()
    assert session.run("pa") == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "assemble" not in remote.operations


def test_pa_help_is_generated_from_the_registry() -> None:
    session, remote = make_session()
    lines = session.run("pa?")
    assert lines[0] == "Usage: pa [asm]"
    assert any(line.startswith("| pa ") for line in lines)
    assert "assemble" not in remote.operations


def test_wa_star_previews_without_patching() -> None:
    session, remote = make_session()
    assert session.run("wa* nop") == ["wx 90"]
    assert "assemble" in remote.operations
    assert "patch_bytes" not in remote.operations


def test_wa_star_works_in_read_only_mode() -> None:
    session, remote = make_session()
    session.readonly = True
    assert session.run("wa* nop") == ["wx 90"]
    assert not session.failed, session.last_error
    assert "patch_bytes" not in remote.operations


def test_wa_plus_writes_and_seeks_past_the_instruction() -> None:
    session, remote = make_session()
    remote.assembly = b"\x90\x90"
    session.seek = 0x2000

    assert session.run("wa+ nop") == ["-- wrote 2 bytes of nop at 0x00002000 --"]
    patches = [arguments for name, arguments in remote.calls if name == "patch_bytes"]
    assert patches == [{"ea": 0x2000, "data": "9090"}]
    assert session.seek == 0x2002


def test_waf_assembles_a_file_and_waF_prints_the_wx_command(tmp_path) -> None:
    source = tmp_path / "snippet.asm"
    source.write_text("nop\nnop\n", encoding="utf-8")
    session, remote = make_session()
    remote.assembly = b"\x90\x90"

    assert session.run(f"waF {source}") == ["wx 9090"]
    calls = [arguments for name, arguments in remote.calls if name == "assemble"]
    assert calls == [{"ea": 0x1000, "text": "nop\nnop"}]
    patches = [arguments for name, arguments in remote.calls if name == "patch_bytes"]
    assert patches == [{"ea": 0x1000, "data": "9090"}]


def test_waf_and_waF_star_forms(tmp_path) -> None:
    source = tmp_path / "snippet.asm"
    source.write_text("nop\n", encoding="utf-8")
    session, remote = make_session()

    assert session.run(f"waf {source}") == [
        "-- wrote 1 bytes of nop at 0x00001000 --"
    ]
    assert [args for name, args in remote.calls if name == "patch_bytes"] == [
        {"ea": 0x1000, "data": "90"}
    ]

    remote.calls.clear()
    session.readonly = True
    assert session.run(f"waF* {source}") == ["wx 90"]
    assert "patch_bytes" not in remote.operations


def test_write_increment_requires_a_width() -> None:
    session, _remote = make_session()
    assert session.run("wi+1") == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)


@pytest.mark.parametrize(
    ("command", "expected"),
    [("w6d YWJj", "616263"), ("w6e abc", "59574a6a"), ("w6x 616263", "59574a6a")],
)
def test_base64_write_modes(command: str, expected: str) -> None:
    session, remote = make_session()
    assert session.run(command) == []
    patches = [arguments for name, arguments in remote.calls if name == "patch_bytes"]
    assert patches[-1]["data"] == expected


@pytest.mark.parametrize("command", ["w6 !!!", "w6 hello", "w6d !!!"])
def test_invalid_base64_write_is_a_usage_error(command: str) -> None:
    session, remote = make_session()
    assert session.run(command) == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "w6" in str(session.last_error)
    assert "patch_bytes" not in remote.operations


@pytest.mark.parametrize("command", ["ic", "iee", "iic", "izz"])
def test_unimplemented_info_commands_do_not_fall_through(command: str) -> None:
    session, _remote = make_session()
    assert session.run(command) == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported information command" in str(session.last_error)


def test_it_lists_the_file_hashes() -> None:
    session, _remote = make_session()
    assert session.run("it") == [
        f"md5 {'0' * 32}",
        f"sha1 {'1' * 40}",
        f"sha256 {'2' * 64}",
    ]


def test_itj_is_a_hash_object() -> None:
    session, _remote = make_session()
    payload = json.loads("\n".join(session.run("itj")))
    assert payload == {"md5": "0" * 32, "sha1": "1" * 40, "sha256": "2" * 64}


def test_it_respects_bin_hashlimit() -> None:
    """r2 hashes only inputs up to bin.hashlimit; `10M` is a size, not an int."""
    session, remote = make_session()
    assert session.run("e bin.hashlimit=10M") == []
    assert session.config.get_int("bin.hashlimit") == 10 * 1024 * 1024
    session.run("e bin.hashlimit=1024")
    assert session.run("it") == []
    assert json.loads("\n".join(session.run("itj"))) == {}
    assert "file_hashes" not in remote.operations


def test_it_with_a_zero_limit_disables_hashing() -> None:
    session, remote = make_session()
    session.run("e bin.hashlimit=0")
    assert session.run("it") == []
    assert "file_hashes" not in remote.operations


def test_bin_hashlimit_rejects_bad_sizes() -> None:
    session, _remote = make_session()
    session.failed = False
    session.run("e bin.hashlimit=10X")
    assert session.failed
    assert isinstance(session.last_error, UsageError)


def test_iD_demangles_with_an_explicit_language() -> None:
    session, _remote = make_session()
    assert session.run("iD c++ _Z3foov") == ["foo()"]


def test_iD_uses_bin_lang_for_a_single_argument() -> None:
    session, _remote = make_session()
    assert session.run("e bin.lang=c++") == []
    assert session.run("iD _Z3foov") == ["foo()"]


def test_iD_uses_the_default_c_language() -> None:
    """r2's bin.lang defaults to c, and `iD sym` still demangles with it."""
    session, _remote = make_session()
    assert session.run("iD _Z3foov") == ["foo()"]
    assert json.loads("\n".join(session.run("iDj _Z3foov"))) == {
        "lang": "c",
        "mangled": "_Z3foov",
        "demangled": "foo()",
    }


def test_iD_json_reports_success_and_failure_like_r2() -> None:
    session, _remote = make_session()
    assert json.loads("\n".join(session.run("iDj c++ _Z3foov"))) == {
        "lang": "c++",
        "mangled": "_Z3foov",
        "demangled": "foo()",
    }
    assert json.loads("\n".join(session.run("iDj c++ nope"))) == {
        "lang": "c++",
        "mangled": "nope",
        "error": "Cannot demangle string",
    }


def test_iD_rejects_an_unknown_language() -> None:
    session, remote = make_session()
    session.failed = False
    session.run("iD notalang foo")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "supported" in str(session.last_error)
    assert "demangle" not in remote.operations


def test_iD_accepts_radare2_language_aliases() -> None:
    session, _remote = make_session()
    assert session.run("iD cxx _Z3foov") == ["foo()"]


def test_ia_matches_the_r2_table_shape() -> None:
    session, _remote = make_session()
    assert session.run("ia") == ["0   0x00000000 12288 arm_32 abi=eabi5 machine=ARM"]


def test_iaj_nests_the_rows_under_bins() -> None:
    session, _remote = make_session()
    assert json.loads("\n".join(session.run("iaj"))) == {
        "bins": [
            {
                "arch": "arm",
                "bits": 32,
                "offset": 0,
                "size": 0x3000,
                "abi": "eabi5",
                "machine": "ARM",
            }
        ]
    }


def test_il_forms_list_the_needed_libraries() -> None:
    session, _remote = make_session()
    assert session.run("il") == ["libc.so.6", "libm.so.6"]
    assert session.run("ilq") == ["libc.so.6", "libm.so.6"]
    assert json.loads("\n".join(session.run("ilj"))) == ["libc.so.6", "libm.so.6"]


def test_ir_renders_the_relocation_table() -> None:
    session, _remote = make_session()
    lines = session.run("ir")
    assert not session.failed, session.last_error
    assert lines[0].split() == ["vaddr", "paddr", "type", "ntype", "name"]
    assert lines[2].split() == [
        "0x000f9128", "0x000e9128", "SET_32", "22", "pthread_detach",
    ]


def test_iM_reports_main_virtual_and_physical_addresses() -> None:
    session, _remote = make_session()
    assert session.run("iM") == ["vaddr=0x00001000 paddr=0x00004000"]


def test_ih_and_iH_render_the_elf_header() -> None:
    session, _remote = make_session()
    assert session.run("ih") == [
        "0x00000000 0x00000000 0x464c457f ELF",
        "0x00000010 0x00000010 0x00000002 Type",
    ]
    assert not session.failed
    assert session.run("iH") == [
        "0x00000000  ELF MAGIC   0x464c457f",
        "0x00000010  Type        0x0002",
    ]


def test_ihj_and_iHj_keep_radare2_shapes() -> None:
    session, _remote = make_session()
    rows = json.loads("\n".join(session.run("ihj")))
    assert [row["name"] for row in rows] == ["ELF", "Type"]
    assert rows[0]["pf"] == [{"type": "x", "offset": 0, "value": 0x464C457F}]

    wrapped = json.loads("\n".join(session.run("iHj")))
    assert wrapped["header"].splitlines()[0] == "0x00000000  ELF MAGIC   0x464c457f"
    assert wrapped["header"].endswith("\n")


def test_ih_star_renders_bin_fields_commands() -> None:
    session, remote = make_session()
    lines = session.run("ih*")
    assert lines[0] == "'fs+header"
    assert "'f header.ELF.value 1 0x464c457f" in lines
    assert "'pf.Type w" in lines
    assert lines[-1] == "'fs-"
    assert "header_fields" in remote.operations


def test_ih_rejects_unknown_modifiers() -> None:
    session, _remote = make_session()
    session.run("ihx")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported information command" in str(session.last_error)


def test_text_search_context_is_clamped_to_the_mapped_segment() -> None:
    session, remote = make_session()
    remote.search_hits = [0x1004]
    remote.read_floor = 0x1000
    lines = session.run("/ needle")
    assert lines == [f'0x00001004 hit0_0 "{"." * 20}"']
    reads = [arguments for name, arguments in remote.calls if name == "read_bytes"]
    assert reads[-1] == {"ea": 0x1000, "count": 0x14}
