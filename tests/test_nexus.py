"""The Nexus lease wrapper: what it may and may not turn into a TransportError.

`connect` wraps unexpected failures so the user sees one actionable line, but
it sits around the whole `with` body -- so anything the body raises deliberately
has to come back out unchanged.
"""

from __future__ import annotations

import pytest

from idare2.errors import QuitRequested, TransportError, UsageError
from idare2.nexus import Target, connect


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
