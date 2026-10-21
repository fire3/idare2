"""radare2-style ``pf`` format parsing, rendering and command wiring."""

from __future__ import annotations

import json
import struct

import pytest

from idare2 import pf
from idare2.config import Config
from idare2.errors import UsageError
from idare2.session import Session


def _format(text: str, **kwargs) -> pf.Format:
    return pf.parse_format(text, pointer_size=4, **kwargs)


def test_scalar_fields_match_r2_layout() -> None:
    data = struct.pack("<IiiH2s8s", 0xDEADBEEF, -7, 123456, 0x1234, b"AB", b"hello\0xx")
    rendered = pf.render(data, 0, _format("xid"))
    assert rendered.lines == [
        "0x00000000 = 0xdeadbeef",
        "0x00000004 = -7",
        "0x00000008 = 0x0001e240",
    ]


def test_field_names_and_endianness() -> None:
    rendered = pf.render(
        b"\xde\xad\xbe\xef",
        0x1000,
        _format("x foo", names=["foo"]),
        endian="big",
    )
    assert rendered.lines == [" foo : 0x00001000 = 0xdeadbeef"]
    assert rendered.rows == [
        {"name": "foo", "type": "x", "offset": 0x1000, "value": 0xDEADBEEF}
    ]


def test_offset_controls_and_inline_arrays() -> None:
    data = b"\xef\xbe\xad\xde\xf9\xff\xff\xff"
    assert pf.render(data, 0, _format(".x")).lines == ["0x00000001 = 0xf9deadbe"]
    assert pf.render(data, 0, _format("[2]x")).lines == [
        "0x00000000 = [ 0xdeadbeef, 0xfffffff9 ]"
    ]


def test_repeat_groups_like_r2() -> None:
    rendered = pf.render(
        b"\x11\x00\x00\x00\x22\x00\x00\x00", 0, _format("x", repeat=2)
    )
    assert rendered.lines == [
        "0x00000000 [0] {",
        "  0x00000000 = 0x00000011",
        "}",
        "0x00000004 [1] {",
        "  0x00000004 = 0x00000022",
        "}",
    ]


def test_union_keeps_every_field_at_the_same_offset() -> None:
    rendered = pf.render(b"\xef\xbe\xad\xde", 0, _format("xi", union=True))
    assert rendered.lines == [
        "0x00000000 = 0xdeadbeef",
        "0x00000000 = -559038737",
    ]


def test_strings_are_null_terminated_and_quoted() -> None:
    data = b"hello\x00world\x00" + "Hi\x00".encode("utf-16-le")
    rendered = pf.render(data, 0, _format("zzZ"))
    assert rendered.lines == [
        '0x00000000 = "hello"',
        '0x00000006 = "world"',
        '0x0000000c = "Hi"',
    ]


def test_inline_string_is_fixed_width() -> None:
    rendered = pf.render(b"abcd\x00", 0, _format("[3]z"))
    assert rendered.lines == ['0x00000000 = "abc"']


def test_pointer_to_string_uses_the_reader_callback() -> None:
    seen: list[tuple[int, int]] = []

    def read_string(address: int, size: int) -> str:
        seen.append((address, size))
        return "target"

    rendered = pf.render(
        struct.pack("<I", 0x2000), 0, _format("s", names=["ptr"]), read_string=read_string
    )
    assert rendered.lines == [' ptr : 0x00000000 = 0x00002000 -> "target"']
    assert seen == [(0x2000, 256)]


def test_format_size_counts_repeats_and_strings() -> None:
    assert pf.format_size(_format("xi", repeat=2)) == 16
    assert pf.format_size(_format("[4]c")) == 4
    assert pf.format_size(_format("z")) == 1


@pytest.mark.parametrize("text", ["D", "u", "n3", "[x]i", "[2]"])
def test_unsupported_or_malformed_formats_fail_loudly(text: str) -> None:
    with pytest.raises(UsageError):
        _format(text)


def test_extra_field_names_are_ignored_like_r2() -> None:
    rendered = pf.render(b"\x01\x00\x00\x00", 0, _format("x", names=["one", "two"]))
    assert rendered.lines == [" one : 0x00000000 = 0x00000001"]


class _Remote:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def call(self, operation: str, **arguments):
        assert operation == "read_bytes"
        return {
            "ea": arguments["ea"],
            "count": arguments["count"],
            "data": self.data[: arguments["count"]],
        }

    def call_with_meta(self, operation: str, **arguments):
        return self.call(operation, **arguments), None


def _session(data: bytes = b"\xaa" * 16) -> Session:
    session = Session(
        handle=object(),
        remote=_Remote(data),
        config=Config(),
        info={"bits": 32, "start_ip": 0x1000, "filesize": 0x1000},
        readonly=False,
    )
    session.seek = 0x1000
    return session


def test_pf_command_renders_and_uses_field_names() -> None:
    session = _session()
    assert session.run("pf xi") == [
        "0x00001000 = 0xaaaaaaaa",
        "0x00001004 = -1431655766",
    ]
    assert session.run("pf xx foo bar") == [
        " foo : 0x00001000 = 0xaaaaaaaa",
        " bar : 0x00001004 = 0xaaaaaaaa",
    ]
    assert session.run("pfs xi") == ["8"]
    assert session.run("pfs 2xi") == ["8"]
    assert session.run("pf [2]x") == [
        "0x00001000 = [ 0xaaaaaaaa, 0xaaaaaaaa ]"
    ]
    assert session.run("pf 0xi") == [
        "0x00001000 = 0xaaaaaaaa",
        "0x00001000 = -1431655766",
    ]


def test_pf_repeat_and_json_output() -> None:
    session = _session()
    assert session.run("pf 2x") == [
        "0x00001000 [0] {",
        "  0x00001000 = 0xaaaaaaaa",
        "}",
        "0x00001004 [1] {",
        "  0x00001004 = 0xaaaaaaaa",
        "}",
    ]
    rows = json.loads(session.run("pfj x")[0])
    assert rows == [{"name": "", "type": "x", "offset": 0x1000, "value": 0xAAAAAAAA}]


def test_named_pf_formats_define_apply_and_inspect() -> None:
    session = _session()
    assert session.run("pf.foo xxd prev next value") == []
    assert session.run("pf.") == ["pf.foo xxd prev next value"]
    assert session.run("pf.foo") == [
        " prev : 0x00001000 = 0xaaaaaaaa",
        " next : 0x00001004 = 0xaaaaaaaa",
        " value : 0x00001008 = 0xaaaaaaaa",
    ]
    assert session.run("pfs.foo") == ["12"]
    assert session.run("pfj.foo")[0].startswith("[")
    assert session.run("pf? foo") == ["pf.foo xxd prev next value"]


def test_pf_errors_are_reported_without_breaking_the_session() -> None:
    session = _session()
    assert session.run("pf") == []
    session.run("pf D")
    assert session.failed is True
    assert "embedded disassembly" in str(session.last_error)
