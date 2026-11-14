"""The Nexus lease wrapper: what it may and may not turn into a TransportError.

`connect` wraps unexpected failures so the user sees one actionable line, but
it sits around the whole `with` body -- so anything the body raises deliberately
has to come back out unchanged.
"""

from __future__ import annotations

import pytest

from idare2.errors import QuitRequested, TransportError, UsageError
from idare2.nexus import Target, connect, open_handle, resolve


class _Handle:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


@pytest.fixture()
def stubbed_nexus(monkeypatch):
    import idare2.nexus as nexus

    handle = _Handle()
    monkeypatch.setattr(nexus, "resolve", lambda target: object())
    monkeypatch.setattr(
        nexus, "_open_with_retry", lambda selection, target, **kw: handle
    )
    monkeypatch.setattr(nexus, "await_analysis", lambda *a, **kw: None)
    return handle


def _target() -> Target:
    return Target(path="/nonexistent-on-purpose")


def test_quit_requested_passes_through_unchanged(stubbed_nexus) -> None:
    """Regression: it was wrapped into TransportError("QuitRequested: ...").

    That made `idare2 -qc 'q'` print `ERROR: QuitRequested: quit with 0` and
    exit 4 (EXIT_TRANSPORT) instead of exiting 0.
    """
    with (
        pytest.raises(QuitRequested) as caught,
        connect(_target(), timeout=1, linger=3600),
    ):
        raise QuitRequested(0)
    assert caught.value.code == 0


def test_quit_keeps_a_nonzero_exit_code(stubbed_nexus) -> None:
    with (
        pytest.raises(QuitRequested) as caught,
        connect(_target(), timeout=1, linger=3600),
    ):
        raise QuitRequested(3)
    assert caught.value.code == 3


def test_idare2_errors_pass_through_with_their_exit_code(stubbed_nexus) -> None:
    with (
        pytest.raises(UsageError) as caught,
        connect(_target(), timeout=1, linger=3600),
    ):
        raise UsageError("bad argument")
    assert caught.value.exit_code == 2


def test_unexpected_failures_are_still_wrapped(stubbed_nexus) -> None:
    with (
        pytest.raises(TransportError) as caught,
        connect(_target(), timeout=1, linger=3600),
    ):
        raise ValueError("socket closed")
    assert "ValueError: socket closed" in str(caught.value)


def test_the_handle_is_closed_on_the_way_out(stubbed_nexus) -> None:
    with connect(_target(), timeout=1, linger=3600):
        pass
    assert stubbed_nexus.closed


def test_processor_hint_selects_the_arm_subtype() -> None:
    from idare2.nexus import _processor_hint

    assert _processor_hint("arm", 32) == "arm:ARMv7"
    assert _processor_hint("arm", 64) == "arm:ARMv8"
    assert _processor_hint("arm", None) == "arm"
    assert _processor_hint("arm:ARMv7", 64) == "arm:ARMv7"


def test_connect_applies_import_hints_before_analysis(stubbed_nexus, monkeypatch) -> None:
    import idare2.nexus as nexus

    seen = []
    monkeypatch.setattr(
        nexus, "_apply_import_hints", lambda handle, target: seen.append((handle, target))
    )
    target = Target(path="/nonexistent-on-purpose", processor="arm", bits=32)
    with connect(target, timeout=1, linger=3600):
        pass
    assert seen == [(stubbed_nexus, target)]


def test_hints_are_not_requested_for_an_attached_record() -> None:
    import idare2.nexus as nexus

    target = Target(record_id="1234-abcd", processor="arm", bits=32)
    assert not nexus._import_hints_requested(target)


def test_endian_alone_requests_import_hints() -> None:
    """A raw binary can need only the byte order; analysis must still wait."""
    import idare2.nexus as nexus

    target = Target(path="/nonexistent-on-purpose", endian="big")
    assert nexus._import_hints_requested(target)
    assert not nexus._import_hints_requested(Target(path="/nonexistent-on-purpose"))


def test_apply_import_hints_forwards_the_byte_order(monkeypatch) -> None:
    import idare2.nexus as nexus
    import idare2.rpc as rpc

    calls = []

    class _Remote:
        def __init__(self, handle, timeout):
            pass

        def call(self, name, **kwargs):
            calls.append((name, kwargs))

    monkeypatch.setattr(rpc, "Remote", _Remote)
    nexus._apply_import_hints(
        object(), Target(path="/nonexistent-on-purpose", bits=32, endian="big")
    )
    assert calls == [
        ("apply_import_hints", {"bits": 32, "entry": None, "big_endian": True})
    ]

    calls.clear()
    nexus._apply_import_hints(
        object(), Target(path="/nonexistent-on-purpose", endian="little")
    )
    assert calls == [
        ("apply_import_hints", {"bits": None, "entry": None, "big_endian": False})
    ]


# ---------------------------------------------------------------------------
# close-time saving: only a writable session that asked for it
# ---------------------------------------------------------------------------


def _shutdown_calls(monkeypatch) -> list:
    import idare2.nexus as nexus

    calls: list[tuple[object, bool]] = []
    monkeypatch.setattr(nexus, "shutdown_if_ours", lambda handle, *, save: calls.append(save) or True)
    return calls


def test_readonly_session_never_saves_on_close(stubbed_nexus, monkeypatch) -> None:
    calls = _shutdown_calls(monkeypatch)
    with connect(Target(path="/nonexistent-on-purpose"), timeout=1, linger=0):
        pass
    assert calls == [False]


def test_writable_session_without_save_on_close_discards(stubbed_nexus, monkeypatch) -> None:
    """`-w` alone must not persist: the patch survived a `--no-save-on-close`
    run because connect() only looked at `readonly`."""
    calls = _shutdown_calls(monkeypatch)
    with connect(Target(path="/nonexistent-on-purpose", readonly=False), timeout=1, linger=0):
        pass
    assert calls == [False]


def test_writable_session_with_save_on_close_saves(stubbed_nexus, monkeypatch) -> None:
    calls = _shutdown_calls(monkeypatch)
    target = Target(path="/nonexistent-on-purpose", readonly=False, save_on_close=True)
    with connect(target, timeout=1, linger=0):
        pass
    assert calls == [True]


def test_save_on_close_is_ignored_for_readonly_sessions(stubbed_nexus, monkeypatch) -> None:
    calls = _shutdown_calls(monkeypatch)
    target = Target(path="/nonexistent-on-purpose", readonly=True, save_on_close=True)
    with connect(target, timeout=1, linger=0):
        pass
    assert calls == [False]


# ---------------------------------------------------------------------------
# preflight: directories are not databases
# ---------------------------------------------------------------------------


def test_a_directory_is_rejected_with_an_actionable_error(tmp_path) -> None:
    from idare2.errors import NoDatabaseError

    with pytest.raises(NoDatabaseError) as caught:
        resolve(Target(path=str(tmp_path)))
    assert "directory" in str(caught.value)


def test_a_missing_file_is_still_no_such_file() -> None:
    from idare2.errors import NoDatabaseError

    with pytest.raises(NoDatabaseError, match="no such file"):
        resolve(Target(path="/nonexistent-on-purpose/missing"))


# ---------------------------------------------------------------------------
# --backend constrains how a path is opened
# ---------------------------------------------------------------------------


def test_backend_idalib_forces_idalib_for_path_opens(monkeypatch, tmp_path) -> None:
    """`--backend idalib` used to be ignored for path opens; Nexus picks idat
    unless IDA_NEXUS_IDALIB_ONLY is set."""
    import idare2.nexus as nexus

    monkeypatch.delenv("IDA_NEXUS_IDALIB_ONLY", raising=False)
    opened: list[str] = []

    class _Options:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class _Handle:
        def __init__(self, path, options=None):
            opened.append(path)

        def __getattr__(self, name):
            return lambda *a, **kw: None

    monkeypatch.setattr("ida_nexus.DatabaseHandle.open", lambda path, options=None: _Handle(path, options))
    target = Target(path=str(tmp_path / "sample"), backend="idalib")
    handle = nexus.open_handle(str(tmp_path / "sample"), target, timeout=1, linger=0)
    assert opened == [str(tmp_path / "sample")]
    import os

    assert os.environ.get("IDA_NEXUS_IDALIB_ONLY") == "1"
    monkeypatch.delenv("IDA_NEXUS_IDALIB_ONLY", raising=False)
    assert handle is not None


def test_backend_gui_cannot_open_a_path(tmp_path) -> None:
    from idare2.errors import NoDatabaseError

    target = Target(path=str(tmp_path / "sample"), backend="gui")
    with pytest.raises(NoDatabaseError, match="--backend gui"):
        open_handle(str(tmp_path / "sample"), target, timeout=1, linger=0)


def test_shutdown_discards_even_without_take_snapshot() -> None:
    """Regression: `handle.take_snapshot()` does not exist in ida-nexus 0.14.2,
    so the old guard aborted before `shutdown_database(save=...)` ever ran --
    the worker then saved on its own shutdown, which is how `--no-save-on-close`
    silently persisted every writable batch."""
    from idare2.nexus import shutdown_if_ours

    class _Handle:
        def __init__(self):
            self.calls = []

        def shutdown_database(self, *, save):
            self.calls.append(save)
            return {"shutting_down": True, "save": save}

    handle = _Handle()
    assert shutdown_if_ours(handle, save=False) is True
    assert handle.calls == [False]


def test_shutdown_reports_a_refused_worker() -> None:
    from idare2.nexus import shutdown_if_ours

    class _Handle:
        def shutdown_database(self, *, save):
            raise RuntimeError("another lease is attached")

    assert shutdown_if_ours(_Handle(), save=False) is False


def test_shutdown_honours_take_snapshot_when_it_exists() -> None:
    """Older ida-nexus: a failed snapshot (another lease attached) still means
    hands off."""
    from idare2.nexus import shutdown_if_ours

    class _Handle:
        def __init__(self):
            self.shut_down = False

        def take_snapshot(self):
            raise RuntimeError("busy")

        def shutdown_database(self, *, save):  # pragma: no cover
            self.shut_down = True

    handle = _Handle()
    assert shutdown_if_ours(handle, save=False) is False
    assert handle.shut_down is False
