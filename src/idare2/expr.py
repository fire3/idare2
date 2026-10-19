"""Expression evaluation, matching radare2's ``?`` number grammar.

Pure Python, no IDA and no session: everything the evaluator needs from the
outside world comes through a :class:`Resolver`.  That keeps the whole module
unit-testable and lets ``?``, ``@ addr``, ``s addr`` and flag arithmetic share
one implementation.

Number literals follow radare2 (verified against r2 6.2.5): **bare digits are
decimal**, so ``s 1000`` seeks to 0x3e8.  ``0x``/``0b``/``0o`` force hex, binary
and octal.
"""

from __future__ import annotations

import re
from typing import Protocol

from idare2.errors import UsageError


class Resolver(Protocol):
    """What the evaluator needs from the session.

    Every method returns ``None`` when the name is unknown, which is what turns
    a typo into a ``BAD_ARGS`` error instead of a silent zero.
    """

    def lookup_name(self, name: str) -> int | None:
        """Resolve a flag or IDA name to an address."""

    def get_var(self, name: str) -> int | None:
        """Resolve a ``$`` variable (``$$``, ``$b``, ...)."""

    def deref(self, addr: int, size: int) -> int:
        """Read ``size`` bytes at ``addr`` (``[addr]`` syntax)."""


# --------------------------------------------------------------------------
# tokenizer
# --------------------------------------------------------------------------

_NUMBER = re.compile(
    r"""
    (?P<hex>   0[xX][0-9a-fA-F]+)
  | (?P<bin>   0[bB][01]+)
  | (?P<oct>   0[oO][0-7]+)
  | (?P<dec>   [0-9]+)
    """,
    re.VERBOSE,
)

_NAME = re.compile(r"[A-Za-z_.][A-Za-z0-9_.$:]*")
_VAR = re.compile(r"\$[A-Za-z0-9_?.]*")

# Longest first: the tokenizer tries these in order.
_OPERATORS = (
    "**",
    "<<",
    ">>",
    "<=",
    ">=",
    "==",
    "!=",
    "&&",
    "||",
    "+",
    "-",
    "*",
    "/",
    "%",
    "&",
    "|",
    "^",
    "~",
    "!",
    "<",
    ">",
    "(",
    ")",
    "[",
    "]",
    "?",
    ":",
    ",",
)


class Token:
    __slots__ = ("kind", "value", "pos")

    def __init__(self, kind: str, value: object, pos: int) -> None:
        self.kind = kind
        self.value = value
        self.pos = pos

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Token({self.kind}, {self.value!r}@{self.pos})"


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "$":
            # `$$` is the current seek; the tokenizer gives it an empty name so
            # that get_var("") is the single place that answers for it.
            if text.startswith("$$", i):
                tokens.append(Token("var", "", i))
                i += 2
                continue
            m = _VAR.match(text, i)
            if m is None:  # a lone '$'
                raise UsageError(f"bad expression: dangling '$' at {i}")
            tokens.append(Token("var", m.group()[1:], i))
            i = m.end()
            continue
        if ch.isdigit():
            m = _NUMBER.match(text, i)
            assert m is not None  # ch is a digit, so the dec branch matches
            raw = m.group()
            if m.lastgroup == "hex":
                value = int(raw[2:], 16)
            elif m.lastgroup == "bin":
                value = int(raw[2:], 2)
            elif m.lastgroup == "oct":
                value = int(raw[2:], 8)
            else:
                value = int(raw, 10)
            tokens.append(Token("num", value, i))
            i = m.end()
            continue
        if ch.isalpha() or ch == "_":
            m = _NAME.match(text, i)
            assert m is not None
            tokens.append(Token("name", m.group(), i))
            i = m.end()
            continue
        for op in _OPERATORS:
            if text.startswith(op, i):
                tokens.append(Token("op", op, i))
                i += len(op)
                break
        else:
            raise UsageError(f"bad expression: unexpected {ch!r} at {i}")
    tokens.append(Token("eof", None, n))
    return tokens


# --------------------------------------------------------------------------
# parser / evaluator (precedence climbing)
# --------------------------------------------------------------------------

#: Binding power of each binary operator, lowest first.
_BINARY: dict[str, int] = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    "<=": 7,
    ">": 7,
    ">=": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
    "**": 11,
}

_RIGHT_ASSOC = frozenset({"**"})


class _Evaluator:
    def __init__(self, tokens: list[Token], resolver: Resolver, text: str) -> None:
        self.tokens = tokens
        self.pos = 0
        self.resolver = resolver
        self.text = text

    # -- token helpers -----------------------------------------------------

    @property
    def cur(self) -> Token:
        return self.tokens[self.pos]

    def peek_op(self) -> str | None:
        tok = self.cur
        return tok.value if tok.kind == "op" else None  # type: ignore[return-value]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, op: str) -> None:
        if self.peek_op() != op:
            raise UsageError(f"bad expression {self.text!r}: expected {op!r}")
        self.advance()

    # -- grammar -----------------------------------------------------------

    def parse(self) -> int:
        value = self.expression(0)
        if self.cur.kind != "eof":
            raise UsageError(f"bad expression {self.text!r}: trailing input")
        return value

    def expression(self, min_bp: int) -> int:
        lhs = self.unary()
        while True:
            op = self.peek_op()
            if op == "?" and min_bp <= 0:
                self.advance()
                then = self.expression(0)
                self.expect(":")
                other = self.expression(0)
                lhs = then if lhs else other
                continue
            if op is None or op not in _BINARY:
                return lhs
            bp = _BINARY[op]
            if bp < min_bp:
                return lhs
            self.advance()
            # Left-associative operators bind the right side one step tighter.
            rhs = self.expression(bp if op in _RIGHT_ASSOC else bp + 1)
            lhs = self.apply(op, lhs, rhs)

    def unary(self) -> int:
        op = self.peek_op()
        if op in ("-", "+", "~", "!"):
            self.advance()
            value = self.unary()
            if op == "-":
                return -value
            if op == "+":
                return value
            if op == "~":
                return ~value
            return 0 if value else 1
        return self.postfix()

    def postfix(self) -> int:
        value = self.atom()
        while self.peek_op() == "[":
            self.advance()
            size = self.expression(0)
            self.expect("]")
            if size not in (1, 2, 4, 8):
                raise UsageError(f"dereference size must be 1, 2, 4 or 8, not {size}")
            value = self.resolver.deref(value, size)
        return value

    def atom(self) -> int:
        tok = self.advance()
        if tok.kind == "num":
            return int(tok.value)  # type: ignore[arg-type]
        if tok.kind == "var":
            resolved = self.resolver.get_var(str(tok.value))
            if resolved is None:
                raise UsageError(f"unknown variable ${tok.value}")
            return resolved
        if tok.kind == "name":
            resolved = self.resolver.lookup_name(str(tok.value))
            if resolved is None:
                raise UsageError(f"cannot resolve name {tok.value!r}")
            return resolved
        if tok.kind == "op" and tok.value == "(":
            value = self.expression(0)
            self.expect(")")
            return value
        if tok.kind == "op" and tok.value == "[":
            # r2's `[expr]` dereferences with the target's pointer width.
            address = self.expression(0)
            self.expect("]")
            size = int(getattr(self.resolver, "pointer_size", 4))
            return self.resolver.deref(address, size)
        raise UsageError(f"bad expression {self.text!r}: unexpected {tok.value!r}")

    @staticmethod
    def apply(op: str, lhs: int, rhs: int) -> int:
        if op == "+":
            return lhs + rhs
        if op == "-":
            return lhs - rhs
        if op == "*":
            return lhs * rhs
        if op == "/":
            if rhs == 0:
                raise UsageError("division by zero")
            # r2 truncates toward zero; Python's // floors. Match r2.
            return int(lhs / rhs)
        if op == "%":
            if rhs == 0:
                raise UsageError("modulo by zero")
            return lhs - rhs * int(lhs / rhs)
        if op == "**":
            return lhs**rhs
        if op == "&":
            return lhs & rhs
        if op == "|":
            return lhs | rhs
        if op == "^":
            return lhs ^ rhs
        if op == "<<":
            return lhs << rhs
        if op == ">>":
            return lhs >> rhs
        if op == "==":
            return 1 if lhs == rhs else 0
        if op == "!=":
            return 1 if lhs != rhs else 0
        if op == "<":
            return 1 if lhs < rhs else 0
        if op == "<=":
            return 1 if lhs <= rhs else 0
        if op == ">":
            return 1 if lhs > rhs else 0
        if op == ">=":
            return 1 if lhs >= rhs else 0
        if op == "&&":
            return 1 if (lhs and rhs) else 0
        if op == "||":
            return 1 if (lhs or rhs) else 0
        raise UsageError(f"unsupported operator {op!r}")  # pragma: no cover


def evaluate(text: str, resolver: Resolver) -> int:
    """Evaluate ``text`` against ``resolver``.  Raises :class:`UsageError`."""
    stripped = text.strip()
    if not stripped:
        raise UsageError("empty expression")
    return _Evaluator(tokenize(stripped), resolver, stripped).parse()


def is_number_literal(text: str) -> bool:
    """Whether ``text`` is a plain number (no names, no operators)."""
    return bool(_NUMBER.fullmatch(text.strip()))
