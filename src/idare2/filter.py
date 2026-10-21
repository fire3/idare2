"""The ``~`` internal grep, matching radare2's semantics.

Authoritative source: ``libr/cons/grep.c`` (``help_detail_tilde``) in the
radare2 source tree, cross-checked against r2 6.2.5 behaviour.

Grammar::

    [command]~[modifier][word,word][endmodifier][[column]][:line]

Three things verified against r2 6.2.5 that are easy to get wrong:

* ``~:N`` selects **lines**, not columns -- ``pd 4~:0`` prints one line.
  The line range uses r2's half-open ``grep_parse_range`` arithmetic, so
  ``:0`` means ``[0, 1)`` and ``:-2`` means "the last two lines".
* ``~[n]`` selects **columns** and is **0-based over whitespace-split fields**.
  The ``|``/``│`` gutter that ``pd`` prints inside a function counts as column
  0, so ``pd~[1]`` is the address.
* ``~word[n]`` takes the n-th word of each *matching* line, also 0-based.

Everything here is a pure function over a list of lines, which is what makes it
testable without IDA or a session.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from idare2.errors import UsageError

#: Modifier characters that may open a spec.
_MODIFIER_CHARS = "&$+!?^,"

# `~:))` is an explicit request for C-like syntax highlighting, so it always
# emits colour (r2 does the same even with `scr.color=0`).  The palette is the
# radare2 6.2.5 default for the keys used by `r_cons_codecolors()`.
_ANSI_RESET = "\x1b[0m"
_ANSI_STRING = "\x1b[38;2;193;156;0m"  # pal.ai.ascii
_ANSI_CPP = "\x1b[38;2;58;150;221m"  # pal.label
_ANSI_COMMENT = "\x1b[38;2;197;15;31m"  # pal.comment
_ANSI_NUMBER = "\x1b[38;2;19;161;14m"  # pal.num
_ANSI_KEYWORD = "\x1b[38;2;136;23;152m"  # pal.push
_ANSI_TYPES = _ANSI_COMMENT


@dataclass
class Column:
    """One ``[..]`` column selection."""

    first: int
    last: int | None = None  # None means "single column" when from_end is False
    from_end: bool = False

    def pick(self, fields: list[str]) -> list[str]:
        n = len(fields)
        if self.from_end:
            index = n - self.first
            return [fields[index]] if 0 <= index < n else []
        if self.last is None:
            return [fields[self.first]] if 0 <= self.first < n else []
        last = self.last if self.last >= 0 else n + self.last
        first = max(self.first, 0)
        return fields[first : last + 1]


@dataclass
class Filter:
    """A parsed ``~`` specification."""

    words: list[str] = field(default_factory=list)
    ignore_case: bool = False
    negate: bool = False
    require_all: bool = False
    anchor_start: bool = False
    anchor_end: bool = False
    count: bool = False
    count_chars: bool = False
    #: ``None`` | ``alpha`` | ``alpha-desc`` | ``uniq`` | ``reverse``
    sort: str | None = None
    sort_column: int | None = None
    columns: list[Column] | None = None
    lines: tuple[int, int] | None = None
    #: ``json`` | ``gron`` | ``xml``
    indent: str | None = None
    json_path: str | None = None
    zoom: int | None = None
    #: ``~:}`` -- indent C-like code honouring braces.
    code_indent: bool = False
    #: ``~<>`` -- XML indentation.
    xml: bool = False
    #: ``~{:`` -- human-friendly JSON indentation.
    human: bool = False
    #: ``~?ea`` -- seven-segment ASCII art.
    seven_segment: bool = False
    #: ``~:)`` -- tokenise C-like decompiler output.
    c_parse: bool = False
    #: ``~:))`` -- C-like syntax highlighting.
    c_highlight: bool = False
    #: ``less`` | ``hud`` | ``hud-one-line``; non-interactive fallback.
    pager: str | None = None
    #: Modifiers we recognised but do not implement, for a one-line warning.
    unimplemented: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            (
                self.words,
                self.count,
                self.count_chars,
                self.sort,
                self.columns,
                self.lines,
                self.indent,
                self.json_path,
                self.zoom is not None,
                self.code_indent,
                self.xml,
                self.human,
                self.seven_segment,
                self.c_parse,
                self.c_highlight,
                self.pager,
            )
        )

    # -- pipeline ----------------------------------------------------------

    def apply(self, lines: list[str]) -> list[str]:
        """Run the full filter pipeline over ``lines``."""
        # These modifiers consume the buffer and return immediately in r2's
        # `r_cons_grepbuf`, before the plain grep/sort/column stages.
        if self.code_indent:
            return _code_indent(lines)
        if self.c_highlight:
            return _code_highlight(lines)
        if self.c_parse:
            return _c_parse(lines)
        if self.seven_segment:
            return _seven_segment(lines)
        if self.zoom is not None:
            return _scale(lines, self.zoom)
        if self.xml:
            return _xml_indent(lines)
        if self.human:
            return _json_human(lines)
        if self.indent is not None or self.json_path is not None:
            lines = self._reformat(lines)
            if lines and lines[0].startswith("~ ERROR"):
                return lines
        if self.pager is not None:
            # idare2 has no interactive pager; keep the (possibly reformatted)
            # output and let the session print a one-line warning.
            return lines
        if self.words:
            lines = self._grep(lines)
        if self.lines is not None:
            lines = self._slice(lines)
        if self.sort is not None:
            lines = self._sort(lines)
        if self.columns is not None:
            lines = self._columns(lines)
        if self.count_chars:
            return [str(sum(len(line) for line in lines))]
        if self.count:
            return [str(len(lines))]
        return lines

    # -- stages ------------------------------------------------------------

    def _grep(self, lines: list[str]) -> list[str]:
        needles = [w.lower() for w in self.words] if self.ignore_case else self.words
        kept: list[str] = []
        for line in lines:
            hay = line.lower() if self.ignore_case else line
            if self.require_all:
                hit = all(needle in hay for needle in needles)
            else:
                hit = any(needle in hay for needle in needles)
            if hit and self.anchor_start:
                hit = any(hay.startswith(needle) for needle in needles)
            if hit and self.anchor_end:
                hit = any(hay.endswith(needle) for needle in needles)
            # `~!word` keeps the lines that do *not* match.
            if hit != self.negate:
                kept.append(line)
        return kept

    def _slice(self, lines: list[str]) -> list[str]:
        first, last = self.lines  # type: ignore[misc]
        n = len(lines)
        begin = first + n if first < 0 else first
        end = last + n if last <= 0 else last
        return lines[max(begin, 0) : max(end, 0)]

    def _sort(self, lines: list[str]) -> list[str]:
        if self.sort == "reverse":
            return list(reversed(lines))
        if self.sort == "uniq":
            return sorted(set(lines))
        if self.sort == "alpha-desc":
            return sorted(lines, reverse=True)
        if self.sort == "alpha":
            if self.sort_column is None:
                return sorted(lines)
            return sorted(lines, key=self._column_key)
        return lines  # pragma: no cover - parser never produces this

    def _column_key(self, line: str) -> tuple[int, object]:
        fields = line.split()
        index = self.sort_column or 0
        if index >= len(fields):
            return (1, "")
        value = fields[index]
        try:
            return (0, int(value, 0))
        except ValueError:
            return (1, value)

    def _columns(self, lines: list[str]) -> list[str]:
        assert self.columns is not None
        out = []
        for line in lines:
            fields = line.split()
            picked: list[str] = []
            for column in self.columns:
                picked.extend(column.pick(fields))
            out.append(" ".join(picked))
        return out

    def _reformat(self, lines: list[str]) -> list[str]:
        if self.json_path is not None:
            return self._json_path(lines)
        try:
            data = json.loads("\n".join(lines))
        except (ValueError, TypeError):
            return [f"~ ERROR: output is not valid JSON, cannot apply ~{self.indent}"]
        if self.indent == "json":
            return json.dumps(data, indent=2).splitlines()
        if self.indent == "gron":
            return _gron(data)
        if self.indent == "xml":
            return ["~ ERROR: xml indentation is not implemented"]
        return lines  # pragma: no cover

    def _json_path(self, lines: list[str]) -> list[str]:
        try:
            data = json.loads("\n".join(lines))
        except (ValueError, TypeError):
            return ["~ ERROR: output is not valid JSON, cannot apply a json path"]
        for part in (self.json_path or "").split("."):
            if not part:
                continue
            if isinstance(data, dict):
                if part not in data:
                    return []
                data = data[part]
            elif isinstance(data, list):
                try:
                    data = data[int(part)]
                except (ValueError, IndexError):
                    return []
            else:
                return []
        if isinstance(data, (dict, list)):
            return json.dumps(data, indent=2).splitlines()
        return [str(data)]


def _gron(data: object, prefix: str = "") -> list[str]:
    """Flatten JSON into ``key=value`` lines (``{=}`` modifier)."""
    out: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            out.extend(_gron(value, f"{prefix}.{key}" if prefix else key))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            out.extend(_gron(value, f"{prefix}[{index}]"))
    else:
        out.append(f"{prefix}={json.dumps(data)}")
    return out


# --------------------------------------------------------------------------
# buffer-shaped modifiers
# --------------------------------------------------------------------------

def _buffer(lines: list[str]) -> str:
    """Reconstruct the newline-terminated buffer r2 would have seen."""
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def _scale(lines: list[str], zoom: int) -> list[str]:
    """Port of ``r_str_scale`` used by ``~<N``.

    r2 calls ``r_str_scale(buffer, N * 2, N)``: the output is ``N`` rows and
    each row is ``2 * N`` columns.  This is a real nearest-neighbour zoom, not
    a truncation (``?e aaa~<2`` prints ``aaaa``).
    """
    if zoom <= 0:
        return lines
    text = _buffer(lines)
    rows = text.split("\n")
    width = zoom * 2
    out: list[str] = []
    current = -1
    for i in range(zoom):
        source = int(i * (len(rows) / zoom))
        row = rows[source] if 0 <= source < len(rows) else ""
        if row:
            line = "".join(row[int(j * (len(row) / width))] for j in range(width))
        else:
            line = " " * width
        if current != source:
            out.append(line)
            current = source
    return out


_SEVEN_SEGMENTS: dict[str, tuple[str, str, str]] = {
    "0": (" __ ", "|  |", "|__|"),
    "1": ("    ", "  | ", "  | "),
    "2": (" __ ", " __|", "|__ "),
    "3": (" __ ", " __|", " __|"),
    "4": ("    ", "|__|", "   |"),
    "5": (" __ ", "|__ ", " __|"),
    "6": (" __ ", "|__ ", "|__|"),
    "7": (" __ ", "   |", "   |"),
    "8": (" __ ", "|__|", "|__|"),
    "9": (" __ ", "|__|", " __|"),
    "$": (" __ ", "||_ ", " _||"),
    "_": ("    ", "    ", " __ "),
    ".": ("    ", "    ", "  _ "),
    ",": ("    ", "    ", " _  "),
    "/": ("    ", "  / ", " /  "),
    "%": ("    ", " O/ ", " /O "),
    "=": ("    ", " __ ", " __ "),
    '"': (" __ ", "    ", "    "),
    "?": (" __ ", "  _|", " _\\ "),
    "+": ("    ", " _|_", "  | "),
    "-": ("    ", " __ ", "    "),
    "*": ("    ", "_\\/_", " /\\ "),
    "(": (" _  ", "|   ", "|_  "),
    ")": ("  _ ", "   |", "  _|"),
    "[": (" _  ", "|   ", "|_  "),
    "]": ("  _ ", "   |", "  _|"),
    ">": ("    ", "  \\ ", "  / "),
    " ": ("    ", "    ", "    "),
    "a": (" __ ", "|__|", "|  |"),
    "b": ("    ", "|__ ", "|__|"),
    "c": ("    ", " __ ", "|__ "),
    "d": ("    ", " __|", "|__|"),
    "e": (" __ ", "|_  ", "|__ "),
    "f": (" __ ", "|_  ", "|   "),
    "g": (" __ ", "| _ ", "|__|"),
    "h": ("    ", "|__|", "|  |"),
    "i": (" ___", "  | ", " _|_"),
    "j": (" __ ", "  | ", "|_| "),
    "k": ("    ", "|_/ ", "| \\ "),
    "l": ("    ", "|   ", "|__ "),
    "m": ("    ", "|\\/|", "|  |"),
    "n": ("    ", "|\\ |", "| \\|"),
    "o": (" __ ", "|  |", "|__|"),
    "p": (" __ ", "|__|", "|   "),
    "q": (" __ ", "|__|", "  \\ "),
    "r": (" __ ", "|__|", "| \\ "),
    "s": (" __ ", "|__ ", " __\\"),
    "t": ("    ", "_|_ ", " |_ "),
    "u": ("    ", "    ", "|__|"),
    "v": ("    ", "|  |", " \\/ "),
    "w": ("    ", "|  |", "|/\\|"),
    "x": ("    ", " \\/ ", " /\\ "),
    "y": ("    ", "|__|", " __|"),
    "z": (" __ ", "  / ", " /_ "),
    "&": ("    ", "    ", " &  "),
    "@": ("    ", "    ", " @  "),
}


def _seven_segment(lines: list[str]) -> list[str]:
    """Port of ``r_str_ss(buffer, NULL, 0)`` used by ``~?ea``."""
    out: list[str] = []
    for line in _buffer(lines).split("\n"):
        for row in range(3):
            out.append("".join(_SEVEN_SEGMENTS.get(ch, ("", "", ""))[row] for ch in line.lower()))
        out.append("")
    return out


def _xml_indent(lines: list[str]) -> list[str]:
    """Port of ``r_xml_indent`` used by ``~<>``."""
    text = _buffer(lines)
    out: list[str] = []
    level = -1
    open_tag = False
    closing = False
    finish = False
    start = 0
    i = 0
    n = len(text)
    while i < n:
        if open_tag:
            if text[i] == ">":
                open_tag = False
                finish = True
                level += 1
        elif text[i] == "<":
            if i + 1 < n and text[i + 1] == "/":
                closing = True
                level -= 1
            open_tag = True
            out.append(text[start:i])
            out.append("\n")
            start = i
        i += 1
        while i < n and text[i] in " \t\r\n":
            i += 1
        if finish:
            out.append("  " * max(level, 0))
            out.append(text[start:i])
            out.append("\n")
            if closing:
                closing = False
                level -= 1
            out.append("  " * max(level, 0))
            start = i
            finish = False
    return "".join(out).splitlines()


def _json_human(lines: list[str]) -> list[str]:
    """Port of ``r_print_json_human`` used by ``~{:``.

    The C implementation intentionally drops braces, brackets and quotes while
    re-flowing the document; keeping that quirk is what makes the output match
    r2 byte for byte.
    """
    text = _buffer(lines)
    out: list[str] = []
    indent = 0
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if ch == '"':
                in_string = False
            elif ch == "\\" and i + 1 < n and text[i + 1] == '"':
                out.append(ch)
                i += 1
                ch = text[i]
            if ch != '"':
                out.append(ch)
            i += 1
            continue
        if indent <= 0 and ch not in "{[":
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_string = True
        if ch in "\n\r\t ":
            i += 1
            continue
        if ch == ":":
            out.append(": ")
        elif ch == ",":
            out.append("\n")
            out.append("  " * max(indent - 1, 0))
        elif ch in "{[":
            if indent > 0:
                out.append("\n")
            indent += 1
            out.append("  " * max(indent - 1, 0))
        elif ch in "}]":
            indent -= 1
            out.append("  " * max(indent - 1, 0))
        elif not in_string:
            out.append(ch)
        i += 1
    return "".join(out).splitlines()


def _code_indent(lines: list[str]) -> list[str]:
    """Port of ``r_print_code_indent`` used by ``~:}``."""
    text = _buffer(lines)
    out: list[str] = []
    indent = 0
    in_string = False
    in_char = False
    in_comment = False
    p = 0
    n = len(text)
    while p < n:
        nl = text.find("\n", p)
        if nl < 0:
            nl = n
        line = text[p:nl]
        trimmed = line.lstrip(" \t")
        opens = 0
        closes = 0
        line_comment = False
        j = 0
        while j < len(trimmed):
            ch = trimmed[j]
            nxt = trimmed[j + 1] if j + 1 < len(trimmed) else ""
            if line_comment:
                break
            if in_comment:
                if ch == "*" and nxt == "/":
                    in_comment = False
                    j += 1
                j += 1
                continue
            if in_string:
                if ch == "\\":
                    j += 1
                elif ch == '"':
                    in_string = False
                j += 1
                continue
            if in_char:
                if ch == "\\":
                    j += 1
                elif ch == "'":
                    in_char = False
                j += 1
                continue
            if ch == "/" and nxt == "/":
                line_comment = True
                break
            if ch == "/" and nxt == "*":
                in_comment = True
                j += 2
                continue
            if ch == '"':
                in_string = True
            elif ch == "'":
                in_char = True
            elif ch == "{":
                opens += 1
            elif ch == "}":
                if opens > 0:
                    opens -= 1
                else:
                    closes += 1
            j += 1
        indent = max(indent - closes, 0)
        out.append("  " * indent + trimmed)
        indent += opens
        if nl >= n:
            break
        p = nl + 1
    return out


_C_KEYWORDS = frozenset(
    [
        "if", "else", "while", "for", "switch", "case", "break", "continue",
        "return", "goto", "do", "sizeof", "typedef", "struct", "union", "enum",
        "volatile", "static", "inline", "extern", "NULL", "null", "true",
        "false", "class", "public", "private", "protected", "new", "delete",
        "try", "catch", "throw", "finally", "import", "from", "export",
        "function", "let", "var", "async", "await", "def", "elif", "in", "is",
        "not", "and", "or", "None", "True", "False", "lambda", "fn", "pub",
        "impl", "trait", "match", "mut", "use", "mod", "func", "package",
        "defer", "go", "range", "select", "chan",
    ]
)

_C_TYPES = frozenset(
    [
        "const", "int", "char", "short", "long", "void", "float", "double",
        "bool", "boolean", "string", "signed", "unsigned", "ut8", "uint8_t",
        "ut64", "uint64_t",
    ]
)

_C_PREPROCESSOR = frozenset({"R_API"})


def _is_identifier_char(ch: str) -> bool:
    return ch == "_" or ch.isalnum() or ord(ch) >= 0x80


def _code_highlight(lines: list[str]) -> list[str]:
    """Port of ``r_print_code_tocolor`` used by ``~:))``."""
    text = _buffer(lines)
    out: list[str] = []
    p = 0
    n = len(text)
    in_string = False
    in_char = False
    in_comment = False
    in_line_comment = False
    in_preproc = False
    while p < n:
        ch = text[p]
        nxt = text[p + 1] if p + 1 < n else ""
        if (in_string or in_char) and ch == "\\" and p + 1 < n:
            out.append(text[p : p + 2])
            p += 2
            continue
        if not in_string and not in_char and not in_comment and ch == "#" and (p == 0 or text[p - 1] == "\n"):
            in_preproc = True
            out.append(_ANSI_CPP + ch)
            p += 1
            continue
        if in_preproc:
            if ch == "\n":
                in_preproc = False
                out.append(_ANSI_RESET)
            out.append(ch)
            p += 1
            continue
        if not in_string and not in_char and not in_line_comment and not in_comment and ch == "/" and nxt == "/":
            in_line_comment = True
            out.append(_ANSI_COMMENT + "//")
            p += 2
            continue
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(_ANSI_RESET)
            out.append(ch)
            p += 1
            continue
        if not in_string and not in_char and not in_comment and ch == "/" and nxt == "*":
            in_comment = True
            out.append(_ANSI_COMMENT + "/*")
            p += 2
            continue
        if in_comment:
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append("/")
                p += 2
                in_comment = False
                out.append(_ANSI_RESET)
            else:
                p += 1
            continue
        if not in_char and ch == '"':
            in_string = not in_string
            out.append(_ANSI_STRING + ch)
            p += 1
            if not in_string:
                out.append(_ANSI_RESET)
            continue
        if not in_string and ch == "'":
            in_char = not in_char
            out.append(_ANSI_STRING + ch)
            p += 1
            if not in_char:
                out.append(_ANSI_RESET)
            continue
        if in_string or in_char:
            out.append(ch)
            p += 1
            continue
        if ch.isdigit():
            out.append(_ANSI_NUMBER)
            while p < n and (text[p].isdigit() or text[p] == "x" or text[p] in "abcdefABCDEF"):
                out.append(text[p])
                p += 1
            out.append(_ANSI_RESET)
            continue
        if _is_identifier_char(ch):
            start = p
            while p < n and _is_identifier_char(text[p]):
                p += 1
            word = text[start:p]
            if word in _C_KEYWORDS:
                out.append(_ANSI_KEYWORD + word + _ANSI_RESET)
            elif word in _C_PREPROCESSOR:
                out.append(_ANSI_CPP + word + _ANSI_RESET)
            elif word in _C_TYPES:
                out.append(_ANSI_TYPES + word + _ANSI_RESET)
            else:
                out.append(word)
            continue
        out.append(ch)
        p += 1
    return "".join(out).splitlines()


def _c_parse(lines: list[str]) -> list[str]:
    return [
        "~ ERROR: ~:) (C tokenizer) is not implemented by idare2; "
        "use ~:)) for syntax highlighting"
    ]


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

_WHOLE_SPECS = {
    "?": "count",
    "?.": "count_chars",
    "??": "help",
    "..": "less",
    "...": "hud",
    "....": "hud-one-line",
    "?ea": "seven-segment",
    ":)": "c-parse",
    ":))": "c-highlight",
    ":}": "c-indent",
    "<>": "xml",
    "{:": "human",
    "{:..": "human-less",
    "{:...": "human-hud",
    "{}": "json",
    "{}..": "json-less",
    "{}...": "json-hud",
}


def parse(spec: str) -> Filter:
    """Parse the text after ``~``.  Raises :class:`UsageError` on bad syntax."""
    result = Filter()
    text = spec

    if text in _WHOLE_SPECS:
        kind = _WHOLE_SPECS[text]
        if kind == "count":
            result.count = True
            return result
        if kind == "count_chars":
            result.count_chars = True
            return result
        if kind == "help":
            raise _GrepHelp()
        if kind == "seven-segment":
            result.seven_segment = True
        elif kind == "c-parse":
            result.c_parse = True
        elif kind == "c-highlight":
            result.c_highlight = True
        elif kind == "c-indent":
            result.code_indent = True
        elif kind == "xml":
            result.xml = True
        elif kind.startswith("json"):
            result.indent = "json"
            result.pager = {"json-less": "less", "json-hud": "hud"}.get(kind)
        elif kind.startswith("human"):
            result.indent = "json"
            result.human = True
            result.pager = {"human-less": "less", "human-hud": "hud"}.get(kind)
        else:
            result.pager = kind if kind in ("less", "hud", "hud-one-line") else None
        return result

    # -- leading modifiers -------------------------------------------------
    while text:
        if text.startswith("$!!"):
            result.sort, text = "reverse", text[3:]
        elif text.startswith("$$"):
            result.sort, text = "uniq", text[2:]
        elif text.startswith("$!"):
            result.sort, text = "alpha-desc", text[2:]
        elif text.startswith("$"):
            result.sort = "alpha"
            text = text[1:]
            if text.startswith("["):
                end = text.find("]")
                if end < 0:
                    raise UsageError("unterminated column selector in ~$[n]")
                result.sort_column = _int(text[1:end], "sort column")
                text = text[end + 1 :]
        elif text[0] == "&":
            # r2 requires every whitespace-separated word after `&` to match:
            # `~&foo bar` is AND, `~foo,bar` is OR (verified against 6.2.5).
            result.require_all, text = True, text[1:]
        elif text[0] == "+":
            result.ignore_case, text = True, text[1:]
        elif text[0] == "!":
            result.negate, text = True, text[1:]
        elif text[0] == "^":
            result.anchor_start, text = True, text[1:]
        elif text[0] == "?":
            result.count, text = True, text[1:]
        elif text[0] == ",":
            # Separator between keywords; the split below handles it.
            break
        else:
            break

    # -- json / xml reformatting ------------------------------------------
    if text.startswith("{"):
        end = text.find("}")
        if end < 0:
            raise UsageError("unterminated {..} in ~ spec")
        inner = text[1:end]
        tail = text[end + 1 :]
        if tail == "..":
            result.pager = "less"
        elif tail == "...":
            result.pager = "hud"
        if inner == "":
            result.indent = "json"
        elif inner == "=":
            result.indent = "gron"
        else:
            result.json_path = inner
        text = ""

    if text.startswith("<"):
        digits = text[1:].strip()
        result.zoom = _int(digits, "zoom width")
        text = ""

    # -- endmodifier, columns, line range ---------------------------------
    # These come after the word, so peel them off the right first.
    if ":" in text and not text.startswith(":"):
        head, _, tail = text.rpartition(":")
        if _is_range(tail):
            result.lines = _parse_range(tail)
            text = head
    elif text.startswith(":"):
        tail = text[1:]
        if _is_range(tail):
            result.lines = _parse_range(tail)
            text = ""

    if text.endswith("]") and "[" in text:
        start = text.rindex("[")
        inner = text[start + 1 : -1]
        result.columns = _parse_columns(inner)
        text = text[:start]

    if text.endswith("$"):
        result.anchor_end = True
        text = text[:-1]

    if text:
        result.words = text.split() if result.require_all else text.split(",")

    return result


class _GrepHelp(Exception):
    """Raised for ``~??`` so the caller can print the help table."""


def _is_range(text: str) -> bool:
    if not text:
        return False
    body = text[1:] if text.startswith("-") else text
    if ".." in body:
        return True
    return body.isdigit()


def _int(text: str, what: str) -> int:
    try:
        return int(text, 10)
    except ValueError:
        raise UsageError(f"~ {what} must be a decimal number, not {text!r}") from None


def _parse_range(text: str) -> tuple[int, int]:
    """Reproduce ``grep_parse_range`` from ``libr/cons/grep.c``.

    The range is half-open ``[first, last)`` once resolved by
    :meth:`Filter._slice`, and negatives count from the end.  ``:0`` selects
    line 0; ``:-1`` selects the last line; ``:-2`` selects the second-to-last.
    """
    if ".." in text:
        head, _, tail = text.partition("..")
        first = _int(head, "line") if head else 0
        last = _int(tail, "line") if tail else 0
    else:
        first = _int(text, "line")
        last = first + 1
    return first, last


def _parse_columns(inner: str) -> list[Column]:
    columns: list[Column] = []
    for part in inner.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("-") and part[1:].isdigit():
            columns.append(Column(int(part[1:]), from_end=True))
            continue
        if ".." in part:
            head, _, tail = part.partition("..")
            first = _int(head, "column") if head else 0
            last = _int(tail, "column") if tail else -1
            columns.append(Column(first, last=last))
            continue
        if "-" in part[1:]:
            head, _, tail = part.partition("-")
            first = _int(head, "column")
            last = _int(tail, "column") if tail else -1
            columns.append(Column(first, last=last))
            continue
        columns.append(Column(_int(part, "column")))
    if not columns:
        raise UsageError("empty column selector in ~ spec")
    return columns


def apply_spec(lines: list[str], spec: str) -> list[str]:
    """Convenience wrapper: parse ``spec`` and filter ``lines``."""
    return parse(spec).apply(lines)


GREP_HELP = """\
Usage: [command]~[modifier][word,word][endmodifier][[column]][:line]
modifier:
|  &            all words must match to grep the line
|  $[n]         sort numerically / alphabetically the Nth column
|  $            sort in alphabetic order
|  $$           sort + uniq
|  $!           inverse alphabetical sort
|  $!!          reverse the lines (like the `tac` tool)
|  ,            token to define another keyword
|  +            case insensitive grep (grep -i)
|  ^            words must be placed at the beginning of line
|  !            negate grep
|  ?            count number of matching lines
|  ?.           count number chars
|  ??           show this help message
|  ?ea          convert text into seven segment style ascii art
|  :s..e        show lines s-e
|  ..           internal 'less' (warning when not interactive)
|  ...          internal 'hud' (warning when not interactive)
|  ....         internal 'hud' in one line (warning when not interactive)
|  :)           parse C-like output from decompiler (not implemented)
|  :))          code syntax highlight
|  :}           indent C code honoring braces
|  <50          perform zoom to the given text width on the buffer
|  <>           xml indentation
|  {:           human friendly indentation (yes, it's a smiley)
|  {:..         less the output of {:
|  {:...        hud the output of {:
|  {}           json indentation
|  {}..         less json indentation
|  {}...        hud json indentation
|  {=}          gron-like output (key=value)
|  {path}       json path grep
endmodifier:
|  $            words must be placed at the end of line
column:
|  [n]          show only column n
|  [-n]         show only column n from the end
|  [n-m]        show column n to m
|  [n-]         show all columns starting from column n
|  [i,j,k]      show the columns i, j and k
"""
