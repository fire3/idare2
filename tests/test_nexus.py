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
