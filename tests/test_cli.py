"""Startup files: rc discovery/loading and readline history."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from idare2 import argv, cli
from idare2.errors import QuitRequested, UsageError


class _Session:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def run(self, line: str, emit=None) -> list[str]:
        self.lines.append(line)
        return []


class _Readline:
    def __init__(self) -> None:
        self.history_length: int | None = None
        self.loaded: str | None = None
        self.saved: str | None = None
        self.missing = True

    def set_history_length(self, size: int) -> None:
        self.history_length = size

    def read_history_file(self, path: str) -> None:
        if self.missing:
            raise FileNotFoundError(path)
        self.loaded = path

    def write_history_file(self, path: str) -> None:
        self.saved = path
        Path(path).write_text("s main\n", encoding="utf-8")


def _options(*arguments: str) -> argv.Options:
    return argv.parse(list(arguments))


def test_rc_paths_follow_xdg_precedence(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = tmp_path / "config"
    work = tmp_path / "work" / "nested"
    work.mkdir(parents=True)
    home.mkdir()
    (home / ".idare2rc").write_text("", encoding="utf-8")
    (config / "idare2").mkdir(parents=True)
    (config / "idare2" / "rc").write_text("", encoding="utf-8")
    rc_d = config / "idare2" / "rc.d"
    rc_d.mkdir()
    for name in ("20-last", "10-first"):
        (rc_d / name).write_text("", encoding="utf-8")
    project_rc = tmp_path / "work" / ".idare2rc"
    project_rc.write_text("", encoding="utf-8")

    monkeypatch.delenv("IDARE2_RCFILE", raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.chdir(work)

    assert cli._rc_paths() == [
        home / ".idare2rc",
        config / "idare2" / "rc",
        rc_d / "10-first",
        rc_d / "20-last",
        project_rc,
    ]


def test_rc_paths_env_override_is_exclusive(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    configured = tmp_path / "custom.rc"

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("IDARE2_RCFILE", str(configured))
    assert cli._rc_paths() == [configured]


def test_relative_xdg_home_is_ignored(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/path")
    assert cli._xdg_home("XDG_CONFIG_HOME", home / ".config") == home / ".config"


def test_project_rc_finds_the_nearest_ancestor(tmp_path: Path) -> None:
    top = tmp_path / "project"
    nested = top / "src" / "deep"
    nested.mkdir(parents=True)
    expected = top / ".idare2rc"
    expected.write_text("e scr.color=0\n", encoding="utf-8")

    assert cli._find_project_rc(nested) == expected


def test_load_rc_runs_files_in_order(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = tmp_path / "config"
    work = tmp_path / "work"
    work.mkdir()
    home.mkdir()
    (home / ".idare2rc").write_text("e first=1\n", encoding="utf-8")
    (config / "idare2" / "rc.d").mkdir(parents=True)
    (config / "idare2" / "rc").write_text("e second=2\n", encoding="utf-8")
    (config / "idare2" / "rc.d" / "10-third").write_text("e third=3\n", encoding="utf-8")

    monkeypatch.delenv("IDARE2_RCFILE", raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.chdir(work)

    session = _Session()
    cli._load_rc(session, _options())
    assert session.lines == ["e first=1", "e second=2", "e third=3"]


def test_load_rc_reports_an_explicit_missing_file(monkeypatch, tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.rc"
    monkeypatch.setenv("IDARE2_RCFILE", str(missing))

    session = _Session()
    cli._load_rc(session, _options())

    assert session.lines == []
    assert f"WARN: cannot read rc file {missing}: no such file" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["-N", "-NN"])
def test_load_rc_can_be_disabled(monkeypatch, tmp_path: Path, flag: str) -> None:
    rcfile = tmp_path / "rc"
    rcfile.write_text("e scr.color=0\n", encoding="utf-8")
    monkeypatch.setenv("IDARE2_RCFILE", str(rcfile))

    session = _Session()
    cli._load_rc(session, _options(flag))
    assert session.lines == []


def test_load_rc_warns_when_a_script_cannot_be_read(monkeypatch, tmp_path: Path, capsys) -> None:
    rcfile = tmp_path / "rc"
    rcfile.mkdir()
    monkeypatch.setenv("IDARE2_RCFILE", str(rcfile))

    cli._load_rc(_Session(), _options())
    assert f"WARN: cannot read rc file {rcfile}: not a regular file" in capsys.readouterr().err


def test_scripts_run_before_commands(tmp_path: Path) -> None:
    pre = tmp_path / "pre.r2"
    post = tmp_path / "post.r2"
    pre.write_text("e pre=1\n", encoding="utf-8")
    post.write_text("e post=1\n", encoding="utf-8")

    session = _Session()
    options = _options("-I", str(pre), "-i", str(post), "-c", "pd 1", "-c", "px 4")
    cli._run_scripts(session, options)
    assert session.lines == ["e pre=1", "e post=1", "pd 1", "px 4"]


def test_missing_script_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="cannot read script"):
        cli._run_file(_Session(), str(tmp_path / "missing.r2"))


def test_history_path_uses_xdg_state_home(monkeypatch, tmp_path: Path) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    assert cli._history_path() == state / "idare2" / "history"


def test_history_is_loaded_and_saved_privately(monkeypatch, tmp_path: Path) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    readline = _Readline()

    cli._load_history(readline)
    assert readline.history_length == cli.HISTORY_SIZE

    cli._save_history(readline)
    path = state / "idare2" / "history"
    assert readline.saved == str(path)
    assert path.read_text(encoding="utf-8") == "s main\n"
    assert path.stat().st_mode & 0o777 == 0o600

    readline.missing = False
    cli._load_history(readline)
    assert readline.loaded == str(path)


def test_history_save_failure_is_reported(monkeypatch, tmp_path: Path, capsys) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))

    class Broken(_Readline):
        def write_history_file(self, path: str) -> None:
            raise OSError("disk full")

    cli._save_history(Broken())
    assert "WARN: cannot save history" in capsys.readouterr().err


def test_repl_saves_history_when_quitting(monkeypatch, tmp_path: Path) -> None:
    readline = _Readline()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(cli, "_import_readline", lambda: readline)
    monkeypatch.setattr(cli, "_install_completion", lambda session, module: None)
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")

    def run(line: str, emit=None) -> list[str]:
        raise QuitRequested(0)

    session = SimpleNamespace(
        config=SimpleNamespace(get_bool=lambda name: False),
        prompt=lambda: "",
        run=run,
    )
    assert cli._repl(session, _options()) == 0
    assert readline.saved == str(cli._history_path())


def test_history_without_readline_is_a_noop(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_import_readline", lambda: None)

    session = SimpleNamespace(
        config=SimpleNamespace(get_bool=lambda name: False),
        prompt=lambda: "",
        run=lambda line, emit=None: [],
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": (_ for _ in ()).throw(EOFError()))
    assert cli._repl(session, _options()) == 0
