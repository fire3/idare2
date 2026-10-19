"""Command registry: longest-prefix matching and generated help."""

from __future__ import annotations

import pytest

from idare2 import cmd


@pytest.fixture(autouse=True)
def registered() -> None:
    cmd.load_all()


@pytest.mark.parametrize(
    ("token", "pattern"),
    [
        ("pd", "p[dDiI]"),
        ("pD", "p[dDiI]"),
        ("pdf", "p[dDiI]"),
        ("pdj", "p[dDiI]"),
        ("pi", "p[dDiI]"),
        ("px", "p[x8ruvscw]"),
        ("p8", "p[x8ruvscw]"),
        ("pwd", "p[x8ruvscw]"),
        ("s", "s"),
        ("s+", "s"),
        ("sf", "s"),
        ("afl", "a[fF]"),
        ("axt", "a[xX]"),
        ("iS", "i[SsEeiz]"),
        ("ij", "i"),
        ("f", "f"),
        ("q", "q"),
    ],
)
def test_lookup(token: str, pattern: str) -> None:
    found = cmd.lookup(token)
    assert found is not None
    assert found[0].pattern == pattern


def test_unknown_command() -> None:
    assert cmd.lookup("zzz") is None


def test_longest_match_wins() -> None:
    # `pwd` beats the `p[x8ruvscw]` family even though both match.
    found = cmd.lookup("pwd")
    assert found is not None
    assert found[0].pattern == "p[x8ruvscw]"
    assert found[1] == "d"


def test_pattern_matching() -> None:
    assert cmd.match_pattern("p[dD]", "pd") == 2
    assert cmd.match_pattern("p[dD]", "pD") == 2
    assert cmd.match_pattern("p[dD]", "px") is None
    assert cmd.match_pattern("i[SsEeiz]", "iS") == 2
    assert cmd.match_pattern("i[SsEeiz]", "ij") is None


def test_help_is_generated_from_the_pattern() -> None:
    found = cmd.lookup("pd")
    assert found is not None
    lines = cmd.help_for(found[0])
    assert lines[0].startswith("Usage: p[dDiI]")
    assert any("pdf" in line for line in lines)


def test_help_index_lists_families() -> None:
    lines = cmd.help_index()
    text = "\n".join(lines)
    for family in "paisfqeL":
        assert f"| {family}" in text


def test_duplicate_patterns_are_not_registered_twice() -> None:
    patterns = [command.pattern for command in cmd.all_commands()]
    # `pwd` is handled by the p-family, not a second command.
    assert patterns.count("pwd") == 0
