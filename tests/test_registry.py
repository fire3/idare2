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
        ("px", "p[x8hruvscw]"),
        ("pa", "pa"),
        ("p8", "p[x8hruvscw]"),
        ("pwd", "p[x8hruvscw]"),
        # `ph` was documented in `p?` and in the README but never registered.
        ("ph", "p[x8hruvscw]"),
        ("s", "s"),
        ("s+", "s"),
        ("sf", "s"),
        ("afl", "a[fF]"),
        ("axt", "a[xX]"),
        ("iS", "iS"),
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
    # `pwd` beats the `p[x8hruvscw]` family even though both match.
    found = cmd.lookup("pwd")
    assert found is not None
    assert found[0].pattern == "p[x8hruvscw]"
    assert found[1] == "d"


def test_pattern_matching() -> None:
    assert cmd.match_pattern("p[dD]", "pd") == 2
    assert cmd.match_pattern("p[dD]", "pD") == 2
    assert cmd.match_pattern("p[dD]", "px") is None
    assert cmd.match_pattern("i[SsEeizM]", "iS") == 2
    assert cmd.match_pattern("i[SsEeizM]", "ij") is None


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


def test_assembly_preview_is_read_only_but_wa_is_not() -> None:
    wa = cmd.lookup("wa")
    preview = cmd.lookup("wa*")
    assert wa is not None and wa[0].writes is True
    assert preview is not None and preview[0].writes is False


def test_registered_patterns_are_unique() -> None:
    patterns = [command.pattern for command in cmd.all_commands()]
    assert len(patterns) == len(set(patterns))


def test_duplicate_registration_fails_loudly() -> None:
    with pytest.raises(ValueError, match=r"duplicate command pattern 'p\[dDiI\]'"):
        cmd.command("p[dDiI]")(lambda session, statement: [])


def test_declared_suffix_sets_reject_unknown_leftovers() -> None:
    """A command that opts into registry validation cannot silently fall back."""
    declared = [command for command in cmd.all_commands() if command.suffixes is not None]
    assert declared, "expected at least the print and info families to opt in"
    for command in declared:
        assert command.suffix_help, f"{command.pattern} must point at its help"
        assert not command.accepts_remainder("ZZZ"), command.pattern
        assert command.accepts_remainder(""), command.pattern


def test_suffix_prefixes_cover_glued_blocksize_forms() -> None:
    found = cmd.lookup("b")
    assert found is not None
    command = found[0]
    assert command.accepts_remainder("+16")
    assert command.accepts_remainder("-16")
    assert command.accepts_remainder("=64")
    assert not command.accepts_remainder("z")


def test_print_suffix_set_covers_implemented_and_explicitly_unsupported() -> None:
    found = cmd.lookup("pd")
    assert found is not None
    command = found[0]
    for token in ("", "j", "f", "fj", "b", "r", "i", "d", "C", "J", ",", "s", "--"):
        assert command.accepts_remainder(token), token
    assert not command.accepts_remainder("zz")
