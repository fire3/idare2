"""ANSI colouring, gated by ``scr.color``.

Colour is off for non-tty output and when ``NO_COLOR`` is set, which is what
makes ``idare2 -qc 'pd 10' file | grep foo`` produce clean text.
"""

from __future__ import annotations

import os
import sys
from typing import Any

RESET = "\x1b[0m"

#: r2's ``scr.color`` levels map onto these.
_GREY = "\x1b[90m"
_RED = "\x1b[31m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_BLUE = "\x1b[34m"
_MAGENTA = "\x1b[35m"
_CYAN = "\x1b[36m"


def default_color_mode(stream: Any = None) -> int:
    """1 when writing to a terminal, 0 otherwise."""
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return 0
    return 1 if getattr(stream, "isatty", lambda: False)() else 0


class Colors:
    def __init__(self, mode: int = 0) -> None:
        self.mode = mode

    @property
    def enabled(self) -> bool:
        return self.mode > 0

    def wrap(self, text: str, code: str) -> str:
        if not self.enabled or not text:
            return text
        return f"{code}{text}{RESET}"

    def addr(self, text: str) -> str:
        return self.wrap(text, _CYAN)

    def mnemonic(self, text: str) -> str:
        return self.wrap(text, _GREEN)

    def register(self, text: str) -> str:
        return self.wrap(text, _YELLOW)

    def number(self, text: str) -> str:
        return self.wrap(text, _MAGENTA)

    def comment(self, text: str) -> str:
        return self.wrap(text, _GREY)

    def error(self, text: str) -> str:
        return self.wrap(text, _RED)

    def warn(self, text: str) -> str:
        return self.wrap(text, _YELLOW)

    def disasm(self, text: str, record: dict[str, Any]) -> str:
        """Colour a disassembly line the way r2 does at ``scr.color=1``."""
        if not self.enabled:
            return text
        parts = text.split(None, 1)
        if not parts:
            return text
        head = self.mnemonic(parts[0])
        return head if len(parts) == 1 else f"{head} {parts[1]}"
