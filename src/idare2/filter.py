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
            )
        )

    # -- pipeline ----------------------------------------------------------

    def apply(self, lines: list[str]) -> list[str]:
        """Run the full filter pipeline over ``lines``."""
        if self.zoom is not None:
            lines = [line[: self.zoom] for line in lines]
        if self.indent is not None or self.json_path is not None:
            lines = self._reformat(lines)
            if lines and lines[0].startswith("~ ERROR"):
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
    "{:": "brace",
    "{:..": "brace-less",
    "{:...": "brace-hud",
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
        result.unimplemented.append(text)
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
        if tail in ("..", "..."):
            result.unimplemented.append(tail)
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
|  :s..e        show lines s-e
|  <50          perform zoom to the given text width on the buffer
|  {}           json indentation
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
