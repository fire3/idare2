"""Command-line parsing.

The precedence between modifiers is the part that is easy to get wrong, and it
was verified against r2 6.2.5 rather than inferred:

``>`` is peeled first, then ``|``, then ``~``, then ``@``.  That ordering is what
makes ``pd 3 @ main~add`` grep the disassembly *at main* instead of seeking to
``main~add``.
"""

from __future__ import annotations

import pytest

from idare2 import parser
from idare2.errors import UsageError


def parse_one(line: str) -> parser.Statement:
    statements = parser.parse(line)
    assert len(statements) == 1
    return statements[0]


def test_plain_command() -> None:
    stmt = parse_one("pd 10")
    assert (stmt.cmd, stmt.args) == ("pd", "10")


def test_statement_separator() -> None:
    assert [s.cmd for s in parser.parse("s main; pd 3; px 16")] == ["s", "pd", "px"]


def test_newline_is_a_separator() -> None:
    assert [s.cmd for s in parser.parse("s main\npd 3")] == ["s", "pd"]


def test_semicolon_inside_quotes_is_kept() -> None:
    stmt = parse_one('?e "a;b"')
    assert stmt.cmd == "?e"
    assert stmt.args == '"a;b"'


def test_temporary_seek() -> None:
    stmt = parse_one("pd 10 @ 0x1000")
    assert (stmt.cmd, stmt.args, stmt.tmpseek) == ("pd", "10", "0x1000")


def test_grep_is_peeled_before_seek() -> None:
    # r2: `pd 3 @ main~add` greps the disassembly at main.
    stmt = parse_one("pd 3 @ main~add")
    assert stmt.tmpseek == "main"
    assert stmt.filter == "add"


def test_grep_spec_swallows_later_seeks() -> None:
    # r2: `pd 3~add @ main` greps for the literal "add @ main".
    stmt = parse_one("pd 3~add @ main")
    assert stmt.tmpseek is None
    assert stmt.filter == "add @ main"


def test_pipe_and_redirect() -> None:
    # The redirect is peeled first, so it applies to the *piped* output:
    # pd -> grep -> shell pipe -> file.
    stmt = parse_one("pd 10 | head -3 > /tmp/out")
    assert stmt.pipe == "head -3"
    assert stmt.redirect == "/tmp/out"


def test_pipe_only() -> None:
    stmt = parse_one("pd 10|head -3")
    assert stmt.pipe == "head -3"
    assert stmt.redirect is None


def test_append_redirect() -> None:
    stmt = parse_one("afl >> /tmp/out")
    assert stmt.redirect == "/tmp/out"
    assert stmt.append is True


def test_repeat_prefix() -> None:
    stmt = parse_one("3pd 2")
    assert (stmt.cmd, stmt.args, stmt.repeat) == ("pd", "2", 3)


def test_bare_number_seeks() -> None:
    stmt = parse_one("0x1000")
    assert (stmt.cmd, stmt.args) == ("s", "0x1000")


def test_bare_decimal_seeks() -> None:
    stmt = parse_one("1000")
    assert (stmt.cmd, stmt.args) == ("s", "1000")


def test_help_suffix() -> None:
    stmt = parse_one("pd?")
    assert stmt.cmd == "pd"
    assert stmt.help is True


def test_double_question_is_its_own_command() -> None:
    stmt = parse_one("??")
    assert stmt.cmd == "?"
    assert stmt.args == "?"


def test_dot_prefix() -> None:
    stmt = parse_one(".afl")
    assert stmt.dot is True
    assert stmt.cmd == "afl"


def test_shell_prefix() -> None:
    stmt = parse_one("!ls -l")
    assert stmt.shell is True
    assert stmt.args == "ls -l"


def test_iterator() -> None:
    stmt = parse_one("pd 5 @@f")
    assert stmt.iterator == "f"
    assert stmt.cmd == "pd"


def test_iterator_with_sizes() -> None:
    stmt = parse_one("p8 4 @@@= 0x1000 16 0x2000 8")
    assert stmt.iterator_size == "= 0x1000 16 0x2000 8"


def test_seek_inside_brackets_is_not_stripped() -> None:
    stmt = parse_one("pd 3~[1]")
    assert stmt.tmpseek is None
    assert stmt.filter == "[1]"


def test_empty_redirect_is_rejected() -> None:
    with pytest.raises(UsageError):
        parser.parse_statement("pd 3 >")


def test_split_args_honours_quotes() -> None:
    assert parser.split_args('foo "bar baz" qux') == ["foo", "bar baz", "qux"]


def test_leading_quotes_keep_the_payload_literal() -> None:
    single = parse_one("'?e hello @ world")
    assert single.cmd == "'"
    assert single.args == "?e hello @ world"
    assert single.tmpseek is None

    double = parse_one('"?e x;y"')
    assert double.cmd == '"'
    assert double.args == '?e x;y"'
    assert [s.cmd for s in parser.parse('"?e x;y"')] == ['"']
