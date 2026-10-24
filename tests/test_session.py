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


def _fake_type_format(arguments):
    name = arguments["name"]
    if name == "bar":
        rows = [
            {"name": "x", "offset": 0, "size": 4, "kind": "scalar",
             "type": "int", "value": 0x57C, "unsigned": 0x57C, "signed": False},
            {"name": "y", "offset": 4, "size": 1, "kind": "scalar",
             "type": "unsigned char", "value": 0x11, "unsigned": 0x11, "signed": False},
        ]
        return {"name": name, "base": arguments["ea"], "kind": "struct", "rows": rows}
    if name == "s":
        rows = [{"name": "p", "offset": 0, "size": 8, "kind": "ptr",
                 "type": "char *", "pointer": 0x1000, "text": "hello"}]
        return {"name": name, "base": arguments["ea"], "kind": "struct", "rows": rows}
    if name == "c":
        rows = [{"name": "c", "offset": 0, "size": 1, "kind": "scalar",
                 "type": "char", "value": 65, "unsigned": 65, "char": "A"}]
        return {"name": name, "base": arguments["ea"], "kind": "scalar", "rows": rows}
    if name == "f":
        rows = [{"name": "f", "offset": 0, "size": 4, "kind": "other",
                 "type": "float", "float": 1.0}]
        return {"name": name, "base": arguments["ea"], "kind": "scalar", "rows": rows}
    rows = [{"name": name, "offset": 0, "size": 4, "kind": "scalar",
             "type": "int", "value": 0x57C, "unsigned": 0x57C}]
    return {"name": name, "base": arguments["ea"], "kind": "scalar", "rows": rows}


class FakeRemote:
    """Answers the handful of ops the session itself uses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail: set[str] = set()
        self.search_hits = [0x1000, 0x1010]
        self.read_floor: int | None = None
        self.read_data: bytes | None = None
        self.assembly = b"\x90"

    def _read_bytes(self, arguments: dict):
        ea = arguments["ea"]
        if self.read_floor is not None and ea < self.read_floor:
            raise CommandError(f"read outside mapped segment at 0x{ea:x}")
        if self.read_data is not None:
            data = self.read_data[: arguments["count"]]
            data += b"\x00" * (arguments["count"] - len(data))
        else:
            data = b"\xaa" * arguments["count"]
        return {
            "ea": ea,
            "count": arguments["count"],
            "data": data,
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
            "read_string": lambda: {
                "ea": arguments["ea"],
                "text": "hello",
                "length": 5,
                "encoding": arguments.get("encoding", "auto"),
            },
            "read_values": lambda: {
                "ea": arguments["ea"],
                "width": arguments["width"],
                "count": arguments["count"],
                "values": [0xAA] * arguments["count"],
            },
            "read_bytes": lambda: self._read_bytes(arguments),
            "search_patterns": lambda: {
                "start": 0,
                "end": 0x100,
                "size": arguments["size"],
                "groups": [
                    {"bytes": "6162", "hits": [0, 4, 8]},
                    {"bytes": "6364", "hits": [2, 6]},
                ],
            },
            "search": lambda: {
                "hits": list(self.search_hits),
                "kind": arguments["kind"],
                "pattern": arguments["pattern"],
                "match": (
                    len(arguments["pattern"].encode("utf-16-le"))
                    if arguments["kind"].startswith("wide")
                    else None
                ),
            },
            "search_ranges": lambda: [{"start": 0x1000, "end": 0x2000, "name": ".text"}],
            "segments": lambda: [
                {
                    "vaddr": 0x1000,
                    "vsize": 0x1000,
                    "paddr": 0x4000,
                    "name": ".text",
                    "perm": "r-x",
                }
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
            "block_info": lambda: {
                "start": 0x1000,
                "end": 0x1008,
                "size": 8,
                "index": 0,
                "count": 2,
            },
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
            "exports": lambda: [
                {
                    "ordinal": 1,
                    "ea": 0x2000,
                    "paddr": 0x2000,
                    "vaddr": 0x2000,
                    "bind": "GLOBAL",
                    "type": "FUNC",
                    "size": 32,
                    "lib": "",
                    "name": "exported",
                    "demangled": "",
                }
            ],
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
            "function_locals": lambda: {
                "reg": [
                    {"name": "arg1", "kind": "reg", "type": "int64_t", "ref": "rdx"},
                ],
                "sp": [
                    {
                        "name": "var_10h",
                        "kind": "var",
                        "type": "int32_t",
                        "ref": {"base": "rsp", "offset": 0x10},
                    },
                ],
                "bp": [],
            },
            "function_xrefs": lambda: [
                {"type": "CALL", "from": 0x1000, "to": 0x2000, "text": "bl sym.imp.printf"},
                {
                    "type": "STRN",
                    "from": 0x1004,
                    "to": 0x4000,
                    "string": "hello",
                    "text": "ldr r0, [pc]",
                },
            ],
            "op_info_many": lambda: [
                {
                    "address": arguments["ea"] + index * 4,
                    "opcode": "mov r0, r1",
                    "disasm": "mov r0, r1",
                    "mnemonic": "mov",
                    "family": "mov",
                    "bytes": "0100a0e1",
                    "size": 4,
                    "sign": False,
                    "type": "null" if index == 0 else "jmp",
                }
                for index in range(arguments["count"])
            ],
            "var_accesses": lambda: [
                {
                    "name": "arg1",
                    "read": [0x1004, 0x1008],
                    "write": [],
                },
                {
                    "name": "var_10h",
                    "read": [0x100c],
                    "write": [0x1010, 0x1014],
                },
            ],
            "string_meta": lambda: {
                "ea": 0x1000,
                "is_string": True,
                "text": "hello",
                "hidden": False,
            },
            "set_string_meta": lambda: {
                "ea": arguments["ea"],
                "is_string": arguments["value"],
            },
            "set_hidden": lambda: {
                "ea": arguments["ea"],
                "hidden": arguments["value"],
            },
            "type_typedefs": lambda: ["foo_t", "size_t"],
            "type_members": lambda: {
                "name": arguments["name"],
                "size": 8,
                "members": [
                    {"name": "a", "type": "int", "offset": 0, "size": 4, "bitfield": False},
                    {"name": "b", "type": "char *", "offset": 4, "size": 4, "bitfield": False},
                ],
            },
            "type_load_header": lambda: {
                "path": arguments["path"],
                "errors": 0,
                "created": ["foo", "color"],
            },
            "type_format": lambda: _fake_type_format(arguments),
            "noreturn_functions": lambda: [
                {"ea": 0x2000, "name": "panic"},
                {"ea": 0x3000, "name": "die"},
            ],
            "set_noreturn": lambda: {"ea": arguments["ea"], "noreturn": arguments["value"]},
            "function_signature": lambda: {
                "name": "main",
                "ret": "int",
                "cc": "arm32",
                "ret_reg": "r0",
                "args": [
                    {"type": "int", "name": "argc", "size": 4, "offset": 0, "loc": "r0"},
                    {"type": "char **", "name": "argv", "size": 4, "offset": 4, "loc": "r1"},
                ],
                "size": 8,
            },
            "resize_function": lambda: {
                "ea": 0x1000,
                "end": arguments["end"],
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


def test_x_is_a_px_alias() -> None:
    session, _remote = make_session()
    assert session.run("x 4 @ 0x1000") == session.run("px 4 @ 0x1000")
    assert session.run("x8 4 @ 0x1000") == session.run("px 4 @ 0x1000")
    assert session.run("xw 2 @ 0x1000") == session.run("pxw 2 @ 0x1000")
    assert session.run("xq 1 @ 0x1000") == session.run("pxq 1 @ 0x1000")


def test_xj_is_a_json_byte_array() -> None:
    session, _remote = make_session()
    assert json.loads("\n".join(session.run("xj 4 @ 0x1000"))) == [0xAA] * 4


@pytest.mark.parametrize("command", ["xh 4", "x/ 4", "xz", "xb 4"])
def test_unknown_x_forms_fail_loudly(command: str) -> None:
    session, remote = make_session()
    session.failed = False
    session.run(command)
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "unsupported print modifier" in str(session.last_error)
    assert "read_bytes" not in remote.operations


def test_p_equal_dict_statistics_match_r2() -> None:
    session, remote = make_session()
    remote.read_data = bytes([0, 1, 2, 3, 0xA8, 0xA8, 5, 7])
    assert session.run("p=d 8 @ 0x1000") == [
        "min:              0  0x0",
        "max:              168  0xa8",
        "unique (count):   7  0x7",
        "range (max-min):  168  0xa8",
        "size (of block):  8  0x8",
    ]


def test_p_equal_defaults_to_the_block_size() -> None:
    session, remote = make_session()
    session.blocksize = 4
    remote.read_data = b"\x01\x01\x02\x03"
    lines = session.run("p=d")
    assert lines[0] == "min:              1  0x1"
    assert lines[4] == "size (of block):  4  0x4"


def test_p_equal_rejects_unimplemented_modes() -> None:
    session, remote = make_session()
    for command in ("p=", "p=e 16", "p=0 16", "p=b"):
        session.failed = False
        session.run(command)
        assert session.failed, command
        assert isinstance(session.last_error, UsageError)


def test_pdi_aligns_bytes_and_text_like_r2() -> None:
    session, _remote = make_session()
    lines = session.run("pdi 1 @ 0x1000")
    assert lines == [
        "0x00001000             00b0a0e3  MOV R11, #0",
    ]
    assert lines[0].index("00b0a0e3") == 23
    assert lines[0].index("MOV R11") == 33


def test_pi_family_text_only_forms() -> None:
    session, _remote = make_session()
    for command in ("pi 1", "pI 1", "pib 1", "pif 1", "pir 1"):
        assert session.run(command) == ["MOV R11, #0"], command


def test_pd_projections_and_json_forms() -> None:
    session, _remote = make_session()
    assert session.run("pdq 1 @ 0x1000") == ["0x00001000 MOV R11, #0"]
    assert session.run("pdl 1 @ 0x1000") == ["4"]
    assert session.run("pdC 1 @ 0x1000") == []

    rows = json.loads("\n".join(session.run("pij 1 @ 0x1000")))
    assert rows[0]["addr"] == 0x1000
    assert rows[0]["bytes"] == "00b0a0e3"
    assert rows[0]["disasm"] == "MOV R11, #0"
    assert rows[0]["type"] == "cpu"

    formatted = json.loads("\n".join(session.run("pdJ 1 @ 0x1000")))
    assert formatted[0]["addr"] == 0x1000
    assert formatted[0]["text"] == "MOV R11, #0"


def test_pd_table_uses_the_columns_ida_can_fill() -> None:
    session, _remote = make_session()
    lines = session.run("pd, 1 @ 0x1000")
    assert lines[0].split() == ["name", "addr", "bytes", "disasm", "comment"]
    assert "0x00001000" in lines[2]
    assert "00b0a0e3" in lines[2]
    assert "MOV R11, #0" in lines[2]


@pytest.mark.parametrize(
    "command",
    [
        "pds 1",
        "pd-- 1",
        "pdk 1",
        "pda 1",
        "pde 1",
        "pdu 1",
        "pd* 1",
        "pdg 1",
        "pdd 1",
        "pdo 1",
        "pdp 1",
        "pd: 1",
        "pdx 1",
        "pia 1",
        "pie 1",
        "piE 1",
        "piu 1",
        "pix 1",
        "pdzz 1",
    ],
)
def test_unimplemented_pd_suffixes_fail_loudly(command: str) -> None:
    session, remote = make_session()
    remote.calls.clear()
    session.failed = False
    session.run(f"{command} @ 0x1000")
    assert session.failed, command
    assert isinstance(session.last_error, UsageError)
    assert "unsupported print modifier" in str(session.last_error)
    assert "disasm" not in remote.operations


def test_pd_rejects_negative_counts_instead_of_disassembling_everything() -> None:
    session, remote = make_session()
    remote.calls.clear()
    session.failed = False
    session.run("pd -1")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "disasm" not in remote.operations


def test_afvR_and_afvW_list_variable_accesses() -> None:
    session, remote = make_session()
    assert session.run("afvR") == [
        "      arg1  0x1004,0x1008",
        "   var_10h  0x100c",
    ]
    assert session.run("afvW") == [
        "      arg1",
        "   var_10h  0x1010,0x1014",
    ]
    payload = json.loads("\n".join(session.run("afvRj")))
    assert payload[1] == {"name": "var_10h", "addrs": [0x100c]}
    assert ("var_accesses", {"ea": 0x1000, "name": None}) in remote.calls


def test_afvR_can_filter_by_name() -> None:
    session, remote = make_session()
    session.run("afvR arg1")
    calls = [args for name, args in remote.calls if name == "var_accesses"]
    assert calls[-1] == {"ea": 0x1000, "name": "arg1"}


def test_cs_string_metadata_forms() -> None:
    session, remote = make_session()
    assert session.run("Cs.") == ["hello"]
    payload = json.loads("\n".join(session.run("Cs.j")))
    assert payload == {"ea": 0x1000, "is_string": True, "text": "hello", "hidden": False}
    assert session.run("Cs 32") == []
    assert ("set_string_meta", {"ea": 0x1000, "size": 32, "value": True}) in remote.calls
    assert session.run("Cs-") == []
    assert ("set_string_meta", {"ea": 0x1000, "value": False}) in remote.calls


def test_ch_hides_and_unhides() -> None:
    session, remote = make_session()
    assert session.run("Ch") == []
    assert ("set_hidden", {"ea": 0x1000, "value": True}) in remote.calls
    assert session.run("Ch-") == []
    assert ("set_hidden", {"ea": 0x1000, "value": False}) in remote.calls


def test_string_and_hide_writes_need_permission() -> None:
    session, remote = make_session()
    session.readonly = True
    for command in ("Cs", "Cs-", "Ch", "Ch-"):
        session.failed = False
        session.run(command)
        assert session.failed, command
    assert "set_string_meta" not in remote.operations
    assert "set_hidden" not in remote.operations


def test_tt_lists_typedefs_and_tu_lists_members() -> None:
    session, remote = make_session()
    assert session.run("tt-") == ["foo_t", "size_t"]
    lines = session.run("tu foo")
    assert lines[0] == "-- foo (size 8) --"
    assert lines[1].split()[1] == "a"
    assert ("type_members", {"name": "foo"}) in remote.calls


def test_td_and_tc_parse_declarations() -> None:
    session, remote = make_session()
    monkeypatched = {"type_parse": lambda: {"errors": 0, "created": ["baz"]}}
    remote._extra = None
    # Wire the parse handler through the same call path a real remote uses.
    original = remote.call

    def call(operation, **arguments):
        if operation == "type_parse":
            return monkeypatched["type_parse"]()
        return original(operation, **arguments)

    remote.call = call
    session.failed = False
    assert session.run('td "struct baz { int q; };"') == ["-- defined baz --"]
    assert not session.failed


def test_tp_and_tpx_format_typed_data() -> None:
    session, remote = make_session()
    session.seek = 0x1000
    assert session.run("tp bar") == [
        " x : 0x00001000 = 0x57c",
        " y : 0x00001004 = 0x11",
    ]
    assert session.run("tpx bar 7c05000011") == [
        " x : 0x00001000 = 0x57c",
        " y : 0x00001004 = 0x11",
    ]
    assert session.run("tp name") == ["0x00001000 = 0x57c"]
    assert ("type_format", {"name": "bar", "ea": 0x1000, "data_hex": "7c05000011"}) in remote.calls


def test_tp_renders_pointers_chars_and_floats() -> None:
    session, _remote = make_session()
    session.seek = 0x1000
    assert session.run("tp s") == [' p : 0x00001000 = "hello"']
    assert session.run("tpx c 41") == ["0x00001000 = 'A'"]
    assert session.run("tpx f 0000803f") == ["0x00001000 = 1"]


def test_to_loads_types_from_a_header() -> None:
    session, remote = make_session()
    assert session.run("to /tmp/h.h") == ["-- loaded foo, color from /tmp/h.h --"]
    assert ("type_load_header", {"path": "/tmp/h.h"}) in remote.calls


def test_to_requires_write_access_and_a_path() -> None:
    session, remote = make_session()
    session.readonly = True
    session.failed = False
    session.run("to /tmp/h.h")
    assert session.failed
    assert "type_load_header" not in remote.operations
    session.readonly = False
    session.failed = False
    session.run("to")
    assert session.failed
    assert isinstance(session.last_error, UsageError)


def test_tn_lists_and_marks_noreturn_functions() -> None:
    session, remote = make_session()
    assert session.run("tn") == ["panic", "die"]
    assert session.run("tn 0x2000") == ["0x2000"]
    assert ("set_noreturn", {"ea": 0x2000, "value": True}) in remote.calls
    assert session.run("tn- 0x2000 0x3000") == []
    assert ("set_noreturn", {"ea": 0x3000, "value": False}) in remote.calls


def test_tn_requires_write_access_for_changes() -> None:
    session, remote = make_session()
    session.readonly = True
    session.failed = False
    session.run("tn 0x2000")
    assert session.failed
    assert "set_noreturn" not in remote.operations
    # Listing stays available in read-only sessions.
    assert session.run("tn") == ["panic", "die"]


def test_tnf_fails_loudly() -> None:
    session, _remote = make_session()
    session.failed = False
    session.run("tnf")
    assert session.failed
    assert isinstance(session.last_error, UsageError)


def test_tf_prints_r2_function_keys() -> None:
    session, _remote = make_session()
    assert session.run("tf main") == [
        "func.main.ret=int",
        "func.main.args=2",
        "func.main.arg.0=int,argc",
        "func.main.arg.1=char **,argv",
    ]


def test_tfj_and_tfc_have_r2_shapes() -> None:
    session, _remote = make_session()
    payload = json.loads("\n".join(session.run("tfj main")))
    assert payload["cc"] == "arm32"
    assert payload["ret_reg"] == "r0"
    assert payload["args"][1] == {
        "type": "char **",
        "name": "argv",
        "size": 4,
        "offset": 4,
        "loc": "r1",
    }
    assert session.run("tfc main") == ["int main (int argc, char ** argv);"]


def test_tf_uses_the_seek_without_a_name() -> None:
    session, remote = make_session()
    session.run("tf")
    call = [args for name, args in remote.calls if name == "function_signature"][-1]
    assert call == {"ea": 0x1000}


def test_ao_reports_ida_fields_and_skips_r2_only_ones() -> None:
    session, _remote = make_session()
    assert session.run("ao") == [
        "address: 0x1000",
        "opcode: mov r0, r1",
        "disasm: mov r0, r1",
        "mnemonic: mov",
        "bytes: 0100a0e1",
        "size: 4",
        "sign: false",
        "type: null",
        "family: mov",
    ]


def test_aoj_is_an_array_and_ao_n_counts() -> None:
    session, remote = make_session()
    rows = json.loads("\n".join(session.run("aoj 2")))
    assert len(rows) == 2
    assert rows[1]["type"] == "jmp"
    assert ("op_info_many", {"ea": 0x1000, "count": 2}) in remote.calls


def test_ao_rejects_bad_counts() -> None:
    session, _remote = make_session()
    for command in ("ao x", "ao 0", "aO"):
        session.failed = False
        session.run(command)
        assert session.failed, command


def test_pj_reindents_the_json_value() -> None:
    session, remote = make_session()
    remote.read_data = b'{"a":1,"b":[2,3]}'
    session.blocksize = 64
    assert session.run("pj") == [
        "{",
        '  "a": 1,',
        '  "b": [',
        "    2,",
        "    3",
        "  ]",
        "}",
    ]


def test_pj_skips_leading_noise_like_r2() -> None:
    session, remote = make_session()
    remote.read_data = b"\x00\x01 {\"a\":true}"
    session.blocksize = 64
    lines = session.run("pj")
    assert lines[0] == "{"
    assert lines[1] == '  "a": true'
    assert lines[-1] == "}"


def test_pu_url_encodes_every_byte() -> None:
    session, remote = make_session()
    remote.read_data = bytes([0x7C, 0x05, 0x00, 0xFF])
    assert session.run("pu 4 @ 0x1000") == ["%7c%05%00%ff"]
    assert session.run("puw 4 @ 0x1000") == ["%7c%00"]


def test_pt_variants_decode_timestamps() -> None:
    import struct
    import time

    session, remote = make_session()
    epoch = 1234567890
    remote.read_data = struct.pack("<I", epoch)
    expected = time.strftime("%a %b %e %H:%M:%S %Y", time.localtime(epoch))
    assert session.run("pt 4 @ 0x1000") == [expected]
    assert session.run("pth 4 @ 0x1000") == [
        time.strftime("%a %b %e %H:%M:%S %Y", time.localtime(epoch + 2082844800))
    ]

    ntfs = struct.pack("<Q", (epoch + 0x2B6109100) * 10_000_000)
    remote.read_data = ntfs
    assert session.run("ptn 8 @ 0x1000") == [expected]


def test_ptb_prints_swatch_beats() -> None:
    import struct

    session, remote = make_session()
    remote.read_data = struct.pack("<Q", 1234567890 * 10**6)
    assert session.run("ptb 8 @ 0x1000") == ["@980.208"]
    remote.read_data = struct.pack("<Q", 1234567890)
    assert session.run("ptb 8 @ 0x1000") == ["@014.282"]


def test_pt_needs_enough_bytes() -> None:
    session, remote = make_session()
    remote.read_data = b"\x00"
    session.failed = False
    session.run("ptn 1 @ 0x1000")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "at least 8 bytes" in str(session.last_error)


def test_p6_encodes_and_decodes_base64() -> None:
    session, _remote = make_session()
    assert session.run("p6es hello world") == ["aGVsbG8gd29ybGQ="]
    assert session.run("p6ds aGVsbG8gd29ybGQ=") == ["hello world"]
    # Four 0xaa bytes encode to "qqqqqg==" (padding included).
    assert session.run("p6e 4 @ 0x1000") == ["qqqqqg=="]


def test_p6_zero_terminated_forms_stop_at_nul() -> None:
    session, remote = make_session()
    remote.read_data = b"hi\0there"
    assert session.run("p6ez") == ["aGk="]
    remote.read_data = b"aGk=\0junk"
    assert session.run("p6dz @ 0x1000") == ["hi"]


def test_p6_rejects_bad_input() -> None:
    session, _remote = make_session()
    for command in ("p6", "p6x", "p6dx", "p6ds !!!", "p6es"):
        session.failed = False
        session.run(command)
        assert session.failed, command
        assert isinstance(session.last_error, UsageError)


def test_pv_prints_one_value_per_line_like_r2() -> None:
    session, remote = make_session()
    assert session.run("pv 2 @ 0x1000") == ["0x000000aa", "0x000000aa"]
    assert session.run("pv1 2 @ 0x1000") == ["0xaa", "0xaa"]
    assert session.run("pv8 1 @ 0x1000") == ["0x00000000000000aa"]
    assert remote.calls[-1][1]["width"] == 8


def test_pv_unsigned_signed_and_pointer_modes() -> None:
    session, _remote = make_session()
    assert session.run("pvu 2 @ 0x1000") == ["170", "170"]
    assert session.run("pvd1 2 @ 0x1000") == ["-86", "-86"]
    assert session.run("pv1d 1 @ 0x1000") == ["-86"]
    assert session.run("pvp 1 @ 0x1000") == ["0x000000aa"]


def test_pv_json_and_string_alias() -> None:
    session, remote = make_session()
    rows = json.loads("\n".join(session.run("pv4j 2 @ 0x1000")))
    assert rows == [
        {"value": 0xAA, "string": "", "address": 0x1000},
        {"value": 0xAA, "string": "", "address": 0x1004},
    ]
    remote.read_data = b"hello\0junk"
    assert session.run("pvz @ 0x1000") == ["hello"]
    payload = json.loads("\n".join(session.run("pvzj @ 0x1000")))
    assert payload["string"] == "hello"
    assert payload["type"] == "ascii"


def test_ps_variants_decode_the_requested_encoding() -> None:
    session, remote = make_session()
    remote.read_data = b"hi\0there"
    assert session.run("psz 8 @ 0x1000") == ["hi"]
    assert session.run("ps 8 @ 0x1000") == ["hi"]
    remote.read_data = b"\x03abcjunk"
    assert session.run("psp 8 @ 0x1000") == ["abc"]
    remote.read_data = b"line\nrest"
    assert session.run("psn 8 @ 0x1000") == ["line"]
    remote.read_data = b"\x41\x00\x42\x00"
    assert session.run("psu 4 @ 0x1000") == ["A\\u0000B\\u0000"]
    assert session.run("psx 2 @ 0x1000") == ["A\\x00"]
    remote.read_data = b"A\0\0\0B\0\0\0"
    assert session.run("psW 8 @ 0x1000") == ["AB"]
    remote.read_data = b"h\0i\0"
    assert session.run("psw 4 @ 0x1000") == ["hi"]


def test_ps_stops_at_the_first_nul_instead_of_returning_a_whole_blob() -> None:
    session, remote = make_session()
    remote.read_data = b"action.c\0websValid(wp)\0"
    assert session.run("ps 32 @ 0x1000") == ["action.c"]


def test_ps_json_reports_section_and_length() -> None:
    session, remote = make_session()
    remote.read_data = b"hello\0junk"
    payload = json.loads("\n".join(session.run("psj @ 0x1000")))
    assert payload == {
        "string": "hello",
        "offset": 0x1000,
        "section": ".text",
        "length": 5,
        "type": "ascii",
    }


@pytest.mark.parametrize(
    "command",
    [
        "psb", "psi", "psq", "pss", "pso", "ps+", "psa", "pszz",
        "pve", "pvh", "pvzz", "pvx",
    ],
)
def test_unimplemented_ps_pv_suffixes_fail_loudly(command: str) -> None:
    session, remote = make_session()
    remote.calls.clear()
    session.failed = False
    session.run(f"{command} @ 0x1000")
    assert session.failed, command
    assert isinstance(session.last_error, UsageError)
    assert "unsupported print modifier" in str(session.last_error)
    assert not {"read_bytes", "read_string", "read_values"} & set(remote.operations)


def test_p8_projections() -> None:
    session, remote = make_session()
    assert session.run("p8 2 @ 0x1000") == ["aaaa"]
    assert json.loads("\n".join(session.run("p8j 4 @ 0x1000"))) == [0xAA] * 4
    assert session.run("p8s 2 @ 0x1000") == ["aa aa"]
    assert session.run("p8, 2 @ 0x1000") == ["0xaa,0xaa"]
    assert session.run("p8d 2 @ 0x1000") == ["170 170 "]
    assert session.run("p8* 2 @ 0x1000") == ["wx+ aaaa"]

    session.config.set("hex.cols", 2)
    assert session.run("p8x 4 @ 0x1000") == ["aaaa", "aaaa"]


def test_p8_block_and_function_forms_use_their_own_ranges() -> None:
    session, remote = make_session()
    assert session.run("p8b @ 0x1000") == ["aa" * 8]
    assert session.run("p8f @ 0x1000") == ["aa" * 8]
    assert json.loads("\n".join(session.run("p8fj @ 0x1000"))) == [0xAA] * 8
    assert ("block_info", {"ea": 0x1000}) in remote.calls
    assert ("function_info", {"ea": 0x1000}) in remote.calls


@pytest.mark.parametrize("command", ["p8fm", "p8fmj", "p8z", "p8q", "p8qj"])
def test_unimplemented_p8_suffixes_fail_loudly(command: str) -> None:
    session, remote = make_session()
    remote.calls.clear()
    session.failed = False
    session.run(f"{command} @ 0x1000")
    assert session.failed, command
    assert isinstance(session.last_error, UsageError)
    assert "unsupported print modifier" in str(session.last_error)
    assert not {"read_bytes", "block_info", "function_info"} & set(remote.operations)


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


def test_iterator_entry_and_export_selectors() -> None:
    """``@@E``/``@@R``/``@@m:r-x``/``@@s`` iterate the new tables."""
    session, _remote = make_session()
    assert session._iterator_addresses("E") == [0x2000]
    assert session._iterator_addresses("R") == [0xF9128]
    assert session._iterator_addresses("s") == [0x1000, 0x2000]
    assert session._iterator_addresses("m:r-x") == [0x1000]
    assert session._iterator_addresses("S") == [0x1000]
    assert session._iterator_addresses("SS") == [0x1000]
    assert session._iterator_addresses("G") == [0x1000]
    sized = session._sized_iterator_items("m:r-x")
    assert sized == [(0x1000, 0x1000)]


@pytest.mark.parametrize("spec", ["dbt*", "t", "r", "M", "C:", "c:"])
def test_unimplemented_iterators_fail_loudly(spec: str) -> None:
    session, _remote = make_session()
    with pytest.raises(UsageError):
        session._iterator_addresses(spec)


def test_temporary_instruction_and_value_selectors() -> None:
    """``@i:n``/``@B:n``/``@v:`` relocate the seek for one statement."""
    session, remote = make_session()
    session.seek = 0x1000
    lines = session.run("s @i:1")
    assert lines == []
    assert session.seek == 0x1000  # temporary: restored afterwards
    assert ("disasm", {"ea": 0x1000, "count": -1, "mode": "function"}) in remote.calls
    session.run("s @v:0x2000")
    assert session.seek == 0x1000


def test_temporary_command_selector_uses_its_first_address() -> None:
    session, _remote = make_session()
    session.seek = 0x1000
    assert session.run("s @c:?e 0x1234") == ["0x00001234"]
    assert session.seek == 0x1000


@pytest.mark.parametrize("spec", ["r:rax", "o:3", "p:42", "k:key", "x:4142"])
def test_unsupported_temporary_selectors_fail_loudly(spec: str) -> None:
    session, _remote = make_session()
    session.failed = False
    assert session.run(f"s @{spec}") == []
    assert session.failed
    assert isinstance(session.last_error, UsageError)


def test_search_creates_session_flags() -> None:
    session, _ = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    lines = session.run("/x aa")
    assert len(lines) == 2
    assert "hit0_0" in lines[0]
    assert session.flags.lookup("hit0_1") == 0x1010


def test_wide_search_uses_utf16_and_prints_the_matched_bytes() -> None:
    session, remote = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    lines = session.run("/w hello")
    assert lines[0] == "0x00001000 hit0_0 " + "aa" * 10
    search = [args for name, args in remote.calls if name == "search"][-1]
    assert search["kind"] == "wide"
    assert search["pattern"] == "hello"
    # The match width is 2 bytes per character, not the UTF-8 length.
    reads = [args for name, args in remote.calls if name == "read_bytes"]
    assert {"ea": 0x1000, "count": 10} in reads


def test_wide_case_insensitive_search_sets_the_kind() -> None:
    session, remote = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    session.run("/wi HELLO")
    search = [args for name, args in remote.calls if name == "search"][-1]
    assert search["kind"] == "wide-i"
    assert search["pattern"] == "HELLO"


def test_wide_json_reports_the_match_width() -> None:
    session, _remote = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    payload = json.loads("\n".join(session.run("/wj hi")))
    assert payload["match"] == 4
    assert payload["hits"] == [0x1000, 0x1010]


def test_pattern_search_renders_r2_groups() -> None:
    session, remote = make_session()
    lines = session.run("/p 2")
    assert lines == [
        "Searching patterns between 0x00000000 and 0x00000100",
        "",
        "bytes: 0: 6162",
        "found: 0: 0x00000000 0x00000004 0x00000008 ",
        "count: 0: 3",
        "",
        "bytes: 1: 6364",
        "found: 1: 0x00000002 0x00000006 ",
        "count: 1: 2",
    ]
    assert (
        "search_patterns",
        {"size": 2, "start": 0x1000, "end": 0x2000},
    ) in remote.calls


def test_pattern_search_rejects_bad_sizes_and_json() -> None:
    session, remote = make_session()
    for command in ("/p", "/p abc", "/pj 2"):
        session.failed = False
        session.run(command)
        assert session.failed, command
    assert "search_patterns" not in remote.operations


def test_assembled_search_uses_the_assembler_bytes(monkeypatch) -> None:
    """``/a`` assembles the text, then searches those bytes like ``/x``."""
    import idare2.assembler as assembler_module

    monkeypatch.setattr(
        assembler_module, "assemble", lambda session, text, ea=0: b"\x01\x00\xa0\xe1"
    )
    session, remote = make_session()
    session.config.set("search.from", 0x1000)
    session.config.set("search.to", 0x2000)
    assert session.run("/a nop")
    search = [args for name, args in remote.calls if name == "search"][-1]
    assert search["kind"] == "bytes"
    assert search["pattern"] == "0100a0e1"


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


def test_blocksize_r2_spellings_and_unknown_suffixes() -> None:
    session, _remote = make_session()
    assert session.run("b*") == ["b 256"]
    assert json.loads(session.run("bj")[0]) == {"blocksize": 256}
    session.run("b=64")
    assert session.blocksize == 64
    assert session.run("b*") == ["b 64"]

    for command in ("bz", "bf x", "bg x", "bm 1M", "b64:AA"):
        session.failed = False
        session.run(command)
        assert session.failed, command
        assert isinstance(session.last_error, UsageError)
        assert "unsupported blocksize modifier" in str(session.last_error)


def test_plain_iterators_apply_the_item_seek() -> None:
    """Each ``@@`` item runs with its own seek; the original is restored after."""
    session, _remote = make_session()
    session.seek = 0x3000
    assert session.run("?v $$ @@f") == ["0x1000", "0x2000"]
    assert session.run("?v $$ @@s:0x1000 0x1002") == ["0x1000", "0x1001"]
    assert session.seek == 0x3000


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


def test_afv_renders_args_and_stack_variables() -> None:
    """``afv``: r2's `arg <type> <name> @ <ref>` / `var ... @ rsp+0xNN`."""
    session, remote = make_session()
    assert session.run("afv") == [
        "arg int64_t arg1 @ rdx",
        "var int32_t var_10h @ rsp+0x10",
    ]
    payload = json.loads("\n".join(session.run("afvj")))
    assert payload == {
        "reg": [{"name": "arg1", "kind": "reg", "type": "int64_t", "ref": "rdx"}],
        "sp": [
            {
                "name": "var_10h",
                "kind": "var",
                "type": "int32_t",
                "ref": {"base": "rsp", "offset": 0x10},
            }
        ],
        "bp": [],
    }
    assert remote.calls == [
        ("function_locals", {"ea": 0x1000}),
        ("function_locals", {"ea": 0x1000}),
    ]


def test_afx_lists_function_references() -> None:
    """``afx``/``afxj``: r2's type char, from/to and the instruction text."""
    session, _remote = make_session()
    assert session.run("afx") == [
        "C 0x00001000 -> 0x00002000 bl sym.imp.printf",
        "s 0x00001004 -> 0x00004000 ldr r0, [pc]  hello",
    ]
    rows = json.loads("\n".join(session.run("afxj")))
    assert rows[0] == {
        "type": "CALL",
        "from": 0x1000,
        "to": 0x2000,
        "text": "bl sym.imp.printf",
    }
    assert rows[1]["string"] == "hello"


def test_afu_resizes_the_function_at_the_seek() -> None:
    session, remote = make_session()
    session.seek = 0x1000
    assert session.run("afu 0x2000") == []
    assert ("resize_function", {"ea": 0x1000, "end": 0x2000}) in remote.calls
    assert not session.failed


def test_afu_requires_write_access() -> None:
    session, remote = make_session()
    session.readonly = True
    session.failed = False
    session.run("afu 0x2000")
    assert session.failed
    assert "resize_function" not in remote.operations


def test_afu_needs_an_end_address() -> None:
    session, remote = make_session()
    session.failed = False
    session.run("afu")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "end address" in str(session.last_error)
    assert "resize_function" not in remote.operations


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


def test_seek_history_explicit_list_uses_names_and_offsets() -> None:
    """``s==``: r2 labels each entry by its nearest flag, then current/future."""
    session, _remote = make_session()
    session.run("s 0x2000")
    session.run("s 0x3000")
    assert session.run("s==") == ["main > helper > helper + 4096"]


def test_seek_history_as_commands() -> None:
    """``s=*``: `<addr> ; <n>s- # <comment>` rows, then the current seek."""
    session, _remote = make_session()
    session.run("s 0x2000")
    session.run("s 0x3000")
    assert session.run("s=*") == [
        "0x00001000 ; 2s- # main",
        "0x00002000 ; 1s- # helper",
        "0x00003000 ; # CUR helper + 4096",
    ]


def test_seek_history_as_commands_includes_redo_entries() -> None:
    session, _remote = make_session()
    session.run("s 0x2000")
    session.run("s 0x3000")
    session.run("s-")
    assert session.run("s=*") == [
        "0x00001000 ; 1s- # main",
        "0x00002000 ; # CUR helper",
        "0x00003000 ; 1s+ # helper + 4096",
    ]
    assert session.run("s==") == ["main > helper > helper + 4096"]


def test_seek_history_bang_and_json_are_r2_aliases() -> None:
    """r2 6.2.5 ignores the modifier and prints the plain chain."""
    session, _remote = make_session()
    session.run("s 0x2000")
    expected = ["0x00001000"]
    assert session.run("s=!") == expected
    assert session.run("s=j") == expected
    assert session.run("s=") == expected


def test_seek_history_forms_with_no_past_seeks() -> None:
    session, _remote = make_session()
    assert session.run("s==") == ["main"]
    assert session.run("s=*") == ["0x00001000 ; # CUR main"]


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


def test_iE_prints_the_export_table() -> None:
    """`iE` is the dynsym export table, not IDA's entry-point list."""
    session, remote = make_session()
    lines = session.run("iE")
    assert lines[0].split() == [
        "nth", "paddr", "vaddr", "bind", "type", "size", "lib", "name", "demangled",
    ]
    assert lines[2].split()[:7] == [
        "1", "0x00002000", "0x00002000", "GLOBAL", "FUNC", "32", "exported",
    ]
    assert "exports" in remote.operations


def test_iEj_is_the_export_rows_as_json() -> None:
    session, _remote = make_session()
    rows = json.loads("\n".join(session.run("iEj")))
    assert rows[0]["name"] == "exported"
    assert rows[0]["ordinal"] == 1


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
