"""Tab completion: client-side names, config keys, and remote caching."""

from __future__ import annotations

from idare2 import cmd
from idare2.complete import Completer, command_names
from idare2.config import Config
from idare2.flags import FlagStore


class FakeRemote:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def call_with_meta(self, operation: str, **arguments):
        self.calls.append((operation, arguments))
        if operation == "symbols":
            return [
                {"ea": 0x1000, "name": "main"},
                {"ea": 0x2000, "name": "malloc"},
            ], None
        if operation == "functions":
            return [
                {"ea": 0x1000, "name": "main"},
                {"ea": 0x3000, "name": "helper"},
            ], None
        raise AssertionError(f"unexpected remote operation {operation}")


class FakeSession:
    def __init__(self) -> None:
        self.config = Config()
        self.remote = FakeRemote()
        self.flags = FlagStore()
        self.vars = {"foo": 1}
        self.aliases = {"bar": "0x1000"}


def _completer() -> tuple[Completer, FakeSession]:
    cmd.load_all()
    session = FakeSession()
    return Completer(session), session


def test_command_names_expand_patterns_and_have_no_brackets() -> None:
    names = command_names()
    assert "pd" in names
    assert "pdf" in names
    assert "afl" in names
    assert "agfd" in names
    assert all("[" not in name and "]" not in name for name in names)


def test_complete_commands_at_the_start_of_a_statement() -> None:
    completer, _session = _completer()
    candidates = completer.candidates("pd; a", 4, 5)
    assert "afl" in candidates
    assert "agf" in candidates
    assert all(candidate.startswith("a") for candidate in candidates)


def test_complete_config_keys() -> None:
    completer, _session = _completer()
    assert "scr.color" in completer.candidates("e scr.co", 2, 8)
    # Values after `=` are not keys; do not offer misleading completions.
    assert completer.candidates("e scr.color=1", 2, 13) == []


def test_complete_flags_and_functions_once_then_cache() -> None:
    completer, session = _completer()
    assert "main" in completer.candidates("s ma", 2, 4)
    assert "helper" in completer.candidates("s hel", 2, 5)
    assert [name for name, _args in session.remote.calls] == ["symbols", "functions"]

    completer.invalidate()
    assert "main" in completer.candidates("s ma", 2, 4)
    assert [name for name, _args in session.remote.calls] == [
        "symbols",
        "functions",
        "symbols",
        "functions",
    ]


def test_complete_at_prefixed_names_and_variables() -> None:
    completer, _session = _completer()
    assert "@main" in completer.candidates("pd @ma", 3, 6)
    assert completer.candidates("pd @ ", 4, 4)
    assert "$foo" in completer.candidates("pd $f", 3, 5)
    assert "$bar" in completer.candidates("pd $b", 3, 5)


def test_non_name_arguments_do_not_produce_remote_queries() -> None:
    completer, session = _completer()
    assert completer.candidates("pd -n 1", 6, 7) == []
    assert completer.candidates("pd 0x10", 3, 7) == []
    assert session.remote.calls == []


def test_readline_callback_reuses_candidates_for_one_word(monkeypatch) -> None:
    import readline

    completer, session = _completer()
    monkeypatch.setattr(readline, "get_line_buffer", lambda: "s ma")
    monkeypatch.setattr(readline, "get_begidx", lambda: 2)
    monkeypatch.setattr(readline, "get_endidx", lambda: 4)

    assert completer.complete("ma", 0) == "main"
    assert completer.complete("ma", 1) == "malloc"
    assert completer.complete("ma", 2) is None
    assert [name for name, _args in session.remote.calls] == ["symbols", "functions"]
