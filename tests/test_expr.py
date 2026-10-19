"""Expression evaluation -- r2's ``?`` grammar.

The contract these tests pin down was measured against r2 6.2.5, not guessed:

* bare digits are **decimal** (``s 1000`` seeks to 0x3e8);
* ``$$`` is the current seek;
* division truncates toward zero, matching r2 rather than Python's ``//``.
"""

from __future__ import annotations

import pytest

from idare2 import expr
from idare2.errors import UsageError


class Resolver:
    def __init__(self) -> None:
        self.names = {"main": 0x16BB4, "sym.foo": 0x2000}
        self.variables = {"": 0x1234, "b": 0x100, "s": 0x1000}
        self.memory = {0x4000: 0xDEADBEEF}

    def lookup_name(self, name: str) -> int | None:
        return self.names.get(name)

    def get_var(self, name: str) -> int | None:
        return self.variables.get(name)

    def deref(self, addr: int, size: int) -> int:
        return self.memory.get(addr, 0)


@pytest.fixture
def resolver() -> Resolver:
    return Resolver()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10+1", 11),
        ("0x10", 16),
        ("0b101", 5),
        ("0o17", 15),
        ("1000", 1000),  # bare digits are decimal, like r2
        ("1<<4", 16),
        ("100>>2", 25),
        ("2**10", 1024),
        ("10/3", 3),  # truncates toward zero, not Python's floor
        ("-10/3", -3),
        ("10%3", 1),
        ("-10%3", -1),
        ("0xff & 0x0f", 0x0F),
        ("0xf0 | 0x0f", 0xFF),
        ("0xff ^ 0x0f", 0xF0),
        ("~0", -1),
        ("!0", 1),
        ("!5", 0),
        ("-5", -5),
        ("(1+2)*3", 9),
        ("1 < 2", 1),
        ("2 <= 2", 1),
        ("3 > 4", 0),
        ("3 == 3", 1),
        ("3 != 3", 0),
    ],
)
def test_arithmetic(text: str, expected: int, resolver: Resolver) -> None:
    assert expr.evaluate(text, resolver) == expected


def test_names_and_variables(resolver: Resolver) -> None:
    assert expr.evaluate("main", resolver) == 0x16BB4
    assert expr.evaluate("main+8", resolver) == 0x16BBC
    assert expr.evaluate("$$", resolver) == 0x1234
    assert expr.evaluate("$$+4", resolver) == 0x1238
    assert expr.evaluate("$b*2", resolver) == 0x200


def test_ternary(resolver: Resolver) -> None:
    assert expr.evaluate("1 ? 10 : 20", resolver) == 10
    assert expr.evaluate("0 ? 10 : 20", resolver) == 20


def test_dereference(resolver: Resolver) -> None:
    assert expr.evaluate("[0x4000]", resolver) == 0xDEADBEEF


def test_unknown_names_and_variables(resolver: Resolver) -> None:
    with pytest.raises(UsageError, match="cannot resolve name"):
        expr.evaluate("nosuchthing", resolver)
    with pytest.raises(UsageError, match="unknown variable"):
        expr.evaluate("$nosuch", resolver)


def test_malformed(resolver: Resolver) -> None:
    for bad in ("", "1+", "(1", "1 2", "1+*2"):
        with pytest.raises(UsageError):
            expr.evaluate(bad, resolver)


def test_division_by_zero(resolver: Resolver) -> None:
    with pytest.raises(UsageError, match="division by zero"):
        expr.evaluate("1/0", resolver)
