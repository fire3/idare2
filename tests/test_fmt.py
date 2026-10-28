"""Formatters: golden text produced from real r2 measurements.

The expected strings here were captured from r2 6.2.5 on an ARM32 firmware
binary (``-e scr.color=0``), so a change that breaks compatibility with r2
fails a test rather than quietly drifting.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from idare2.config import Config
from idare2.fmt import disasm as fmt_disasm
from idare2.fmt import graph as fmt_graph
from idare2.fmt import listing as fmt_listing
from idare2.fmt import memory as fmt_memory
from idare2.fmt.colors import Colors


@dataclass
class FakeSession:
    config: Config
    info: dict
    colors: Colors

    def __init__(self, **info) -> None:
        self.config = Config()
        self.info = {"bits": 32, **info}
        self.colors = Colors(0)

    def comment_at(self, ea: int) -> str:
        return ""


@pytest.fixture
def session() -> FakeSession:
    return FakeSession()


def function_result(lines, *, func=None, mode="count"):
    return {"mode": mode, "ea": lines[0]["ea"], "func": func, "lines": lines}


def insn(ea, raw, text, comment="", size=None):
    return {
        "ea": ea,
        "size": size if size is not None else len(bytes.fromhex(raw)),
        "bytes": bytes.fromhex(raw),
        "text": text,
        "comment": comment,
        "is_call": False,
        "is_jump": False,
        "targets": [],
    }


LINES = [
    insn(0x00015E50, "b4379fe5", "LDR R3, [PC,#0x1C]", ""),
    insn(0x00015E54, "03308fe0", "ADD R3, PC, R3", ""),
    insn(0x00015E58, "0310a0e1", "MOV R1, R3", ""),
]


def test_disasm_columns(session: FakeSession) -> None:
    out = fmt_disasm.format_disasm(function_result(LINES), session)
    assert len(out) == 3
    # Measured r2 layout: gutter at 0, address at 12, bytes at 28, text at 43.
    first = out[0]
    assert first[0] == "┌"
    assert first.index("0x00015e50") == 12
    assert first.index("b4379fe5") == 28
    assert first.index("LDR") == 43
    assert out[-1][0] == "└"
    assert out[1][0] == "│"


def test_disasm_comment_column_is_absolute(session: FakeSession) -> None:
    line = insn(0x00015E50, "b4379fe5", "LDR R3", "argc")
    out = fmt_disasm.format_disasm(function_result([line]), session)
    assert out[0].index("; argc") == 71


def test_disasm_without_lines_has_no_gutter(session: FakeSession) -> None:
    session.config.set("asm.lines", False)
    out = fmt_disasm.format_disasm(function_result(LINES), session)
    assert out[0].startswith("0x00015e50")
    assert "│" not in "".join(out)


def test_disasm_without_bytes(session: FakeSession) -> None:
    # The r2 baseline for `e asm.bytes=false` was captured with the gutter off.
    session.config.set("asm.bytes", False)
    session.config.set("asm.lines", False)
    out = fmt_disasm.format_disasm(function_result(LINES), session)
    assert "b4379fe5" not in out[0]
    assert out[0].index("LDR") == 16


def test_function_header_only_at_a_function_start(session: FakeSession) -> None:
    start = LINES[0]["ea"]
    func = {"name": "main", "start": start, "end": start + 2036,
            "signature": "int main(int argc, char **argv)"}
    header = fmt_disasm.format_disasm(
        function_result(LINES, func=func), session
    )[0]
    assert header == "┌ 2036: int main(int argc, char **argv)"
    # Starting mid-function prints no header.
    elsewhere = {"name": "main", "start": 0x1000, "end": 0x2000}
    mid = fmt_disasm.format_disasm(
        function_result(LINES, func=elsewhere), session
    )
    assert not mid[0].startswith("┌ 2036")


def test_symbol_table_matches_radare2_columns(session: FakeSession) -> None:
    rows = [
        {
            "ordinal": 1,
            "paddr": 0x31614,
            "vaddr": 0x39614,
            "bind": "GLOBAL",
            "type": "FUNC",
            "size": 192,
            "lib": "",
            "name": "cJSON_CreateStringArray",
            "demangled": "",
        },
        {
            "ordinal": 2,
            "paddr": None,
            "vaddr": 0xFD77C,
            "bind": "LOCAL",
            "type": "OBJ",
            "size": 4,
            "lib": "",
            "name": "g_object",
            "demangled": "",
        },
    ]
    lines = fmt_listing.format_symbols(rows, session)
    assert lines[0].split() == [
        "nth", "paddr", "vaddr", "bind", "type", "size", "lib", "name", "demangled",
    ]
    assert lines[2].split() == [
        "1", "0x00031614", "0x00039614", "GLOBAL", "FUNC", "192", "cJSON_CreateStringArray",
    ]
    assert lines[3].split() == [
        "2", "----------", "0x000fd77c", "LOCAL", "OBJ", "4", "g_object",
    ]


def test_import_table_matches_radare2_columns(session: FakeSession) -> None:
    rows = [
        {
            "ordinal": 3,
            "vaddr": 0xE740,
            "bind": "GLOBAL",
            "type": "FUNC",
            "lib": "",
            "name": "pthread_detach",
        },
        {
            "ordinal": 50,
            "vaddr": None,
            "bind": "WEAK",
            "type": "NOTYPE",
            "lib": "",
            "name": "_ITM_deregisterTMCloneTable",
        },
    ]
    lines = fmt_listing.format_imports(rows, session)
    assert lines[0].split() == ["nth", "vaddr", "bind", "type", "lib", "name"]
    assert lines[2].split() == ["3", "0x0000e740", "GLOBAL", "FUNC", "pthread_detach"]
    assert lines[3].split() == [
        "50", "----------", "WEAK", "NOTYPE", "_ITM_deregisterTMCloneTable",
    ]


HEADER_FIELDS = [
    {
        "name": "ELF",
        "vaddr": 0x00,
        "paddr": 0x00,
        "size": 4,
        "value": 0x464C457F,
        "format": "x",
        "pf": [{"type": "x", "offset": 0x00, "value": 0x464C457F}],
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
    {
        "name": "EntryPoint",
        "vaddr": 0x18,
        "paddr": 0x18,
        "size": 4,
        "value": 0x400100,
        "format": "x",
        "pf": [{"type": "x", "offset": 0x18, "value": 0x400100}],
    },
    {
        "name": "Flags",
        "vaddr": 0x24,
        "paddr": 0x24,
        "size": 4,
        "format": "x",
        "pf": [{"type": "x", "offset": 0x24, "value": 0}],
    },
    {
        "name": "EhSize",
        "vaddr": 0x28,
        "paddr": 0x28,
        "size": 2,
        "value": 52,
        "format": "w",
        "pf": [{"type": "w", "offset": 0x28, "value": 52}],
    },
]


def test_header_table_matches_radare2_headers32(session: FakeSession) -> None:
    """``iH``: 4-digit hex for Type/Machine, decimal for the sizes, ELF MAGIC."""
    assert fmt_listing.format_header(HEADER_FIELDS, 32) == [
        "0x00000000  ELF MAGIC   0x464c457f",
        "0x00000010  Type        0x0002",
        "0x00000018  Entrypoint  0x00400100",
        "0x00000024  Flags       0x00000000",
        "0x00000028  EhSize      52",
    ]


def test_header_table_matches_radare2_headers64(session: FakeSession) -> None:
    """The same rows under the 64-bit plugin only change the magic label."""
    lines = fmt_listing.format_header(HEADER_FIELDS, 64)
    assert lines[0] == "0x00000000  ELF64       0x464c457f"
    assert lines[1] == "0x00000010  Type        0x0002"


def test_header_field_rows_match_radare2_ih(session: FakeSession) -> None:
    assert fmt_listing.format_header_fields(HEADER_FIELDS) == [
        "0x00000000 0x00000000 0x464c457f ELF",
        "0x00000010 0x00000010 0x00000002 Type",
        "0x00000018 0x00000018 0x00400100 EntryPoint",
        "0x00000024 0x00000024 0x00000000 Flags",
        "0x00000028 0x00000028 0x00000034 EhSize",
    ]
    assert fmt_listing.format_header_quiet(HEADER_FIELDS)[3] == "0x00000024 0x00000000 Flags"


def test_header_commands_match_bin_fields(session: FakeSession) -> None:
    """``ih*`` sets one flag per field plus a sized data definition."""
    assert fmt_listing.format_header_radare(HEADER_FIELDS) == [
        "'fs+header",
        "'f header.ELF 1 0x00000000",
        "'f header.ELF.value 1 0x464c457f",
        "'@0x0'Cd4",
        "'pf.ELF x",
        "'f header.Type 1 0x00000010",
        "'f header.Type.value 1 0x00000002",
        "'pf.Type w",
        "'f header.EntryPoint 1 0x00000018",
        "'f header.EntryPoint.value 1 0x00400100",
        "'@0x18'Cd4",
        "'pf.EntryPoint x",
        "'f header.Flags 1 0x00000024",
        "'@0x24'Cd4",
        "'pf.Flags x",
        "'f header.EhSize 1 0x00000028",
        "'f header.EhSize.value 1 0x00000034",
        "'pf.EhSize w",
        "'fs-",
    ]


HEXDUMP = {
    "ea": 0x00008D10,
    "count": 32,
    "data": bytes.fromhex(
        "9e0000000000000000000000" "30000000"
        "000000000000000000000000" "49000000"
    ),
}


def test_hexdump_matches_r2(session: FakeSession) -> None:
    out = fmt_memory.format_hexdump(HEXDUMP, session)
    assert out[0] == (
        "- offset -  1011 1213 1415 1617 1819 1A1B 1C1D 1E1F  "
        "0123456789ABCDEF"
    )
    assert out[1] == (
        "0x00008d10  9e00 0000 0000 0000 0000 0000 3000 0000  "
        "............0..."
    )
    assert out[2].startswith("0x00008d20")


def test_hexdump_wrap_at_ff(session: FakeSession) -> None:
    payload = {"ea": 0x00008D1B, "count": 16, "data": bytes.fromhex("00300000" + "00" * 12)}
    out = fmt_memory.format_hexdump(payload, session)
    assert out[0].startswith("- offset -  1B1C 1D1E 1F20")
    # The ASCII header is the low nibble of each offset, uppercase.
    assert out[0].endswith("BCDEF0123456789A")


def test_hexdump_header_can_be_disabled(session: FakeSession) -> None:
    session.config.set("hex.header", False)
    out = fmt_memory.format_hexdump(HEXDUMP, session)
    assert out[0].startswith("0x00008d10")


def test_hexdump_cols(session: FakeSession) -> None:
    session.config.set("hex.cols", 8)
    out = fmt_memory.format_hexdump(HEXDUMP, session)
    assert out[0] == "- offset -  1011 1213 1415 1617  01234567"
    assert out[1].startswith("0x00008d10  9e00 0000 0000 0000  ........")


def test_value_rendering(session: FakeSession) -> None:
    payload = {
        "ea": 0x1000,
        "width": 4,
        "value": 0xFFFFFFF0,
        "bytes": bytes.fromhex("f0ffffff"),
        "big_endian": False,
    }
    out = fmt_memory.format_value(payload, session)
    assert "hex     0xfffffff0" in out
    assert "uint    4294967280" in out
    assert "int     -16" in out


def test_string_rendering(session: FakeSession) -> None:
    assert fmt_memory.format_string({"text": "httpd"}, session) == ["httpd"]


def test_jsonable_bytes_become_hex() -> None:
    from idare2.fmt import jsonable

    assert jsonable({"bytes": b"\x10\x48"}) == {"bytes": "1048"}
    assert jsonable([b"\xff"]) == ["ff"]


GRAPH = {
    "name": "main",
    "addr": 0x1000,
    "end": 0x1020,
    "size": 0x20,
    "blocks": [
        {
            "addr": 0x1000,
            "size": 8,
            "jump": 0x1010,
            "fail": 0x1008,
            "successors": [0x1010, 0x1008],
            "ops": [
                {
                    "addr": 0x1000,
                    "size": 4,
                    "bytes": bytes.fromhex("0000a0e1"),
                    "disasm": "nop",
                    "comment": "keep going",
                }
            ],
        },
        {"addr": 0x1008, "size": 8, "successors": [], "ops": []},
    ],
}


def test_graph_ascii_has_boxes_ops_and_edges(session: FakeSession) -> None:
    lines = fmt_graph.format_ascii(GRAPH, session)
    text = "\n".join(lines)
    assert text.startswith("-- main @ 0x00001000 size 32 blocks 2 --")
    assert "0x00001000  [#0]  size 8" in text
    assert "nop ; keep going" in text
    assert "jump 0x00001010" in text
    assert "fail 0x00001008" in text
    assert lines[1].startswith("┌")


def test_graph_dot_escapes_labels_and_colours_edges(session: FakeSession) -> None:
    graph = {
        **GRAPH,
        "name": 'ma"in',
        "blocks": [
            {
                **GRAPH["blocks"][0],
                "ops": [
                    {
                        "addr": 0x1000,
                        "disasm": 'cmp r0, "x"',
                        "comment": "",
                    }
                ],
            }
        ],
    }
    lines = fmt_graph.format_dot(graph, session)
    text = "\n".join(lines)
    assert text.startswith("digraph code {")
    assert 'cmp r0, \\"x\\"' in text
    assert 'URL="ma\\"in/0x00001000"' in text
    assert '"0x00001000" -> "0x00001010" [color="#13a10e"]' in text
    assert '"0x00001000" -> "0x00001008" [color="#c50f1f"]' in text


# --- pxw / pxq / pxd / pxu: r2 6.2.5 row layout -------------------------
#
# Captured from r2 6.2.5 on /bin/true at 0x1000:
#   00000000 00000000 c89f0000 00000000
# The expected strings below are byte-for-byte copies, so a layout regression
# fails against the real tool rather than against our own assumptions.


def _values_payload(raw: bytes, width: int, *, ea: int = 0x1000, big_endian: bool = False):
    order = "big" if big_endian else "little"
    values = [
        int.from_bytes(raw[offset : offset + width], order)
        for offset in range(0, len(raw), width)
    ]
    return {
        "ea": ea,
        "width": width,
        "count": len(values),
        "big_endian": big_endian,
        "values": values,
    }


RAW16 = bytes.fromhex("00000000" "00000000" "c89f0000" "00000000")


def test_pxw_matches_r2_row_layout(session: FakeSession) -> None:
    out = fmt_memory.format_values(_values_payload(RAW16, 4), session)
    assert out == [
        "0x00001000  0x00000000 0x00000000 0x00009fc8 0x00000000  ................"
    ]


def test_pxq_matches_r2_row_layout(session: FakeSession) -> None:
    out = fmt_memory.format_values(_values_payload(RAW16, 8), session)
    assert out == [
        "0x00001000  0x0000000000000000  0x0000000000009fc8   ................"
    ]


def test_pxd_matches_r2_row_layout(session: FakeSession) -> None:
    out = fmt_memory.format_values(_values_payload(RAW16, 4), session, fmt="signed")
    assert out == [
        "- offset -    0  1   2  3   4  5   6  7   8  9   A  B   C  D   E  F  "
        "0123456789ABCDEF",
        "0x00001000              0             0         40904             0  "
        "................",
    ]


def test_pxu_matches_r2_row_layout(session: FakeSession) -> None:
    out = fmt_memory.format_values(_values_payload(RAW16, 4), session, fmt="unsigned")
    assert out == [
        "- offset -    0  1   2  3   4  5   6  7   8  9   A  B   C  D   E  F  "
        "0123456789ABCDEF",
        "0x00001000              0             0         40904             0  "
        "................",
    ]


def test_value_dumps_pad_partial_rows_like_r2(session: FakeSession) -> None:
    raw8 = RAW16[:8]
    assert fmt_memory.format_values(_values_payload(raw8, 4), session) == [
        "0x00001000  0x00000000 0x00000000                        ........"
    ]
    assert fmt_memory.format_values(_values_payload(raw8, 8), session) == [
        "0x00001000  0x0000000000000000                       ........"
    ]
    assert fmt_memory.format_values(
        _values_payload(raw8, 4), session, fmt="signed"
    ) == [
        "- offset -    0  1   2  3   4  5   6  7   8  9   A  B   C  D   E  F  "
        "0123456789ABCDEF",
        "0x00001000              0             0                              "
        "........",
    ]
    assert fmt_memory.format_values(
        _values_payload(raw8, 4), session, fmt="unsigned"
    ) == [
        "- offset -    0  1   2  3   4  5   6  7   8  9   A  B   C  D   E  F  "
        "0123456789ABCDEF",
        "0x00001000              0             0                      ........",
    ]


def test_value_dumps_honour_hex_cols(session: FakeSession) -> None:
    session.config.set("hex.cols", 8)
    assert fmt_memory.format_values(_values_payload(RAW16, 4), session) == [
        "0x00001000  0x00000000 0x00000000  ........",
        "0x00001008  0x00009fc8 0x00000000  ........",
    ]
    assert fmt_memory.format_values(_values_payload(RAW16, 8), session) == [
        "0x00001000  0x0000000000000000   ........",
        "0x00001008  0x0000000000009fc8   ........",
    ]
    assert fmt_memory.format_values(
        _values_payload(RAW16, 4), session, fmt="signed"
    ) == [
        "- offset -    0  1   2  3   4  5   6  7  01234567",
        "0x00001000              0             0  ........",
        "0x00001008          40904             0  ........",
    ]


def test_value_dump_ascii_is_reconstructed_from_endian_values(session: FakeSession) -> None:
    payload = _values_payload(bytes.fromhex("41424344"), 4, big_endian=True)
    out = fmt_memory.format_values(payload, session)
    assert out == ["0x00001000  0x41424344" + " " * 35 + "ABCD"]


def test_value_dump_rejects_zero_width(session: FakeSession) -> None:
    with pytest.raises(ValueError):
        fmt_memory.format_values(
            {"ea": 0x1000, "width": 0, "values": [], "big_endian": False}, session
        )
