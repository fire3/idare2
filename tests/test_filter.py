"""``~`` filter semantics.

The expectations here were captured from r2 6.2.5, including the two details
that are easiest to get wrong:

* ``~:N`` selects **lines**, not columns;
* ``~[n]`` is a 0-based column over whitespace-split fields, and the ``│``
  gutter that ``pd`` prints counts as column 0.
"""

from __future__ import annotations

import pytest

from idare2 import filter as grep
from idare2.errors import UsageError

LINES = [
    "│           0x00015e50      b4379fe5       ldr r3, aav.0x000b36e0",
    "│           0x00015e54      03308fe0       add r3, pc, r3",
    "│           0x00015e58      0310a0e1       mov r1, r3",
    "│           0x00015e5c      3ae2ffeb       bl sym.imp.printf",
]


def run(spec: str, lines: list[str] | None = None) -> list[str]:
    return grep.apply_spec(lines if lines is not None else LINES, spec)


def test_grep_substring() -> None:
    assert run("add") == [LINES[1]]


def test_grep_is_case_sensitive_by_default() -> None:
    assert run("ADD") == []


def test_case_insensitive_modifier() -> None:
    assert run("+ADD") == [LINES[1]]


def test_negate() -> None:
    assert run("!add") == [LINES[0], LINES[2], LINES[3]]


def test_anchor_start() -> None:
    # Every line starts with the gutter, so anchoring at the start of the
    # *word* fails for a word that only appears later.
    assert run("^add") == []


def test_anchor_end() -> None:
    assert run("r3$") == [LINES[1], LINES[2]]


def test_all_words_must_match() -> None:
    # r2's `&` takes a whitespace-separated word list, not a `,` list.
    assert run("&add pc") == [LINES[1]]
    assert run("&add mov") == []


def test_count_lines() -> None:
    assert run("?") == ["4"]


def test_count_chars() -> None:
    assert run("?.") == [str(sum(len(line) for line in LINES))]


def test_line_selection_is_a_line_index() -> None:
    # r2: `pd 4~:0` prints exactly one line.
    assert run(":0") == [LINES[0]]
    assert run(":2") == [LINES[2]]


def test_line_range() -> None:
    assert run(":1..3") == LINES[1:3]


def test_line_range_negative() -> None:
    # `:-N` is a single line, the Nth from the end (r2: `:-1` prints the last).
    assert run(":-1") == [LINES[-1]]
    assert run(":-2") == [LINES[-2]]


def test_line_range_open_end() -> None:
    assert run(":1..") == LINES[1:]


def test_column_zero_is_the_gutter() -> None:
    assert run("[0]") == ["│"] * 4


def test_column_one_is_the_address() -> None:
    assert run("[1]") == ["0x00015e50", "0x00015e54", "0x00015e58", "0x00015e5c"]


def test_column_range() -> None:
    assert run("[1-2]") == [
        "0x00015e50 b4379fe5",
        "0x00015e54 03308fe0",
        "0x00015e58 0310a0e1",
        "0x00015e5c 3ae2ffeb",
    ]


def test_column_from_end() -> None:
    # `[-1]` is the last column of each line, whatever its position.
    assert run("[-1]") == ["aav.0x000b36e0", "r3", "r3", "sym.imp.printf"]
    assert run("[-2]") == ["r3,", "pc,", "r1,", "bl"]


def test_column_list() -> None:
    assert run("[1,2]") == run("[1-2]")


def test_word_index() -> None:
    # Word 0 of each matching line is the gutter, as in r2.
    assert run("ldr[0]") == ["│"]
    assert run("ldr[3]") == ["ldr"]
    assert run("ldr[4]") == ["r3,"]


def test_sort_alphabetical() -> None:
    assert run("$", ["b", "c", "a"]) == ["a", "b", "c"]


def test_sort_reverse() -> None:
    assert run("$!", ["b", "c", "a"]) == ["c", "b", "a"]


def test_sort_uniq() -> None:
    assert run("$$", ["b", "a", "b"]) == ["a", "b"]


def test_reverse_lines() -> None:
    assert run("$!!", ["a", "b", "c"]) == ["c", "b", "a"]


def test_json_indent() -> None:
    import json

    payload = json.dumps({"a": 1, "b": [1, 2]})
    assert run("{}", [payload]) == [
        "{",
        '  "a": 1,',
        '  "b": [',
        "    1,",
        "    2",
        "  ]",
        "}",
    ]


def test_gron() -> None:
    import json

    assert run("{=}", [json.dumps({"a": 1, "b": {"c": 2}})]) == ["a=1", "b.c=2"]


def test_json_path() -> None:
    import json

    assert run("{b}", [json.dumps({"a": 1, "b": 2})]) == ["2"]


def test_json_modifier_reports_bad_input() -> None:
    out = run("{}", ["not json"])
    assert out and out[0].startswith("~ ERROR")


def test_zoom() -> None:
    assert run("<4", ["abcdefgh"]) == ["abcd"]


def test_grep_help_raises() -> None:
    with pytest.raises(grep._GrepHelp):
        grep.parse("??")


def test_empty_spec_is_a_no_op() -> None:
    parsed = grep.parse("")
    assert parsed.is_empty()
    assert parsed.apply(LINES) == LINES


@pytest.mark.parametrize("spec", ["[]", "[a]"])
def test_malformed_columns(spec: str) -> None:
    with pytest.raises(UsageError):
        grep.parse(spec)
