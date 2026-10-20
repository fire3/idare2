"""Remote operation handlers, driven through the dispatcher with a fake db.

These run without IDA: ``idare2.remote.dispatch.invoke`` only needs an object
whose shape matches what the handler reads, which is enough to catch the class
of bug where the **client and the handler disagree on the signature** -- the
dispatcher's ``signature.bind`` rejects the call before the handler body runs,
so a plain unit test of the handler would never see it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from idare2 import protocol
from idare2.remote import dispatch
from idare2.remote.ops import load_all


@pytest.fixture(autouse=True)
def registered() -> None:
    load_all()


class FakeDb:
    """The slice of ``ida_domain.Database`` the ``i`` listings touch."""

    def __init__(self) -> None:
        self.imports = SimpleNamespace(get_all_imports=self._imports)
        self.names = SimpleNamespace(get_all=self._names)
        self.entries = SimpleNamespace(get_all=self._entries)

    @staticmethod
    def _imports():
        for ea, name, module, ordinal in (
            (0xE740, "pthread_detach", "libc.so", 3),
            (0xE74C, "printf", "libc.so", 5),
            (0xE758, "cgi_ucloud_destory", "", 7),
            (0xE764, "hal_set_led_blink", "", 8),
        ):
            yield SimpleNamespace(address=ea, name=name, module_name=module, ordinal=ordinal)

    @staticmethod
    def _names():
        yield from ((0x1000, "main"), (0x2000, "helper"), (0x3000, "other"))

    @staticmethod
    def _entries():
        yield SimpleNamespace(address=0x4000, name="start", ordinal=1, forwarder_name=None)


def _rows(envelope: dict) -> list:
    assert protocol.is_ok(envelope), envelope
    return envelope["result"]


def test_dispatcher_rejects_unknown_keyword() -> None:
    """The guard that made ``ii`` fail: a mismatched signature is a BAD_ARGS."""
    envelope = dispatch.invoke(FakeDb(), "imports", {"offset": 0, "extraneous": 1})
    assert not protocol.is_ok(envelope)
    assert envelope["error"]["code"] == protocol.BAD_ARGS
    assert "unexpected keyword argument" in envelope["error"]["message"]


def test_imports_accepts_the_client_offset_and_count() -> None:
    """``ii`` passes offset/count; the handler must take them (was TypeError)."""
    envelope = dispatch.invoke(
        FakeDb(), "imports", {"pattern": None, "offset": 0, "count": 2}
    )
    rows = _rows(envelope)
    assert [row["name"] for row in rows] == ["pthread_detach", "printf"]
    assert envelope["meta"]["truncated"] is True
    assert envelope["meta"]["next_offset"] == 2


def test_imports_resumes_at_the_offset() -> None:
    envelope = dispatch.invoke(
        FakeDb(), "imports", {"pattern": None, "offset": 2, "count": 10}
    )
    rows = _rows(envelope)
    assert [row["name"] for row in rows] == ["cgi_ucloud_destory", "hal_set_led_blink"]
    assert "meta" not in envelope or envelope.get("meta") is None


def test_imports_filters_by_pattern() -> None:
    envelope = dispatch.invoke(FakeDb(), "imports", {"pattern": "printf"})
    rows = _rows(envelope)
    assert [row["name"] for row in rows] == ["printf"]
    assert rows[0]["ea"] == 0xE74C


def test_imports_row_shape_matches_the_formatter() -> None:
    """``format_imports`` indexes ordinal/ea/module/name -- all four must exist."""
    rows = _rows(dispatch.invoke(FakeDb(), "imports", {"pattern": None, "offset": 0}))
    assert set(rows[0]) == {"ea", "name", "module", "ordinal"}
    assert isinstance(rows[0]["ordinal"], int)


def test_listing_ops_accept_the_client_paging_arguments() -> None:
    """``ii``/``is``/``iz`` all pass offset/count; every handler must take them.

    Signature-only on purpose: ``strings`` needs ``ida_loader`` for its segment
    index, so it cannot be *invoked* offline -- but a missing parameter is
    exactly the failure mode that broke ``ii``, and that is visible here.
    """
    import inspect

    for name in ("imports", "symbols", "strings"):
        params = inspect.signature(dispatch.HANDLERS[name]).parameters
        assert "offset" in params, f"{name} takes no offset"
        assert "count" in params, f"{name} takes no count"


def test_symbols_pages_like_imports() -> None:
    envelope = dispatch.invoke(FakeDb(), "symbols", {"offset": 1, "count": 1})
    assert protocol.is_ok(envelope), envelope
    assert [row["name"] for row in envelope["result"]] == ["helper"]
    assert envelope["meta"]["next_offset"] == 2


# ---------------------------------------------------------------------------
# enum.Flag values (afi / sf / sF / Cd.)
# ---------------------------------------------------------------------------


class _Func:
    start_ea = 0x15E10
    end_ea = 0x16604


class FlagFunctions:
    """The ``db.functions`` surface ``function_info`` touches."""

    def __init__(self, flags) -> None:
        self._flags = flags

    def get_at(self, ea: int):
        return _Func()

    def get_flowchart(self, func):
        return [_Func(), _Func()]

    def get_instructions(self, func):
        return range(75)

    def get_callers(self, func):
        return range(19)

    def get_callees(self, func):
        return range(64)

    def get_name(self, func) -> str:
        return "main"

    def is_far(self, func) -> bool:
        return False

    def does_return(self, func) -> bool:
        return True

    def get_flags(self, func):
        return self._flags


class FlagBytes:
    def __init__(self, flags) -> None:
        self._flags = flags

    def get_flags_at(self, ea: int):
        return self._flags


def test_flag_value_reads_enum_flag() -> None:
    """``enum.Flag`` has no ``__int__``; ``.value`` does."""
    import enum

    from idare2.remote.helpers import flag_value

    class Bits(enum.Flag):
        NONE = 0
        FRAME = 1
        THUNK = 2

    assert flag_value(Bits.FRAME | Bits.THUNK) == 3
    assert flag_value(Bits.NONE) == 0
    assert flag_value(None) == 0
    assert flag_value(42) == 42
    # Anything unconvertible degrades to 0 instead of raising.
    assert flag_value(object()) == 0


def test_function_info_survives_a_flag_enum() -> None:
    """Regression: ``int(FunctionFlags)`` raised TypeError and killed afi/sf/sF."""
    import enum

    from idare2.remote.helpers import flag_value  # noqa: F401  (documented pairing)

    class FunctionFlags(enum.Flag):
        FRAME = 1
        THUNK = 2

    db = SimpleNamespace(functions=FlagFunctions(FunctionFlags.FRAME))
    envelope = dispatch.invoke(db, "function_info", {"ea": 0x15E10})
    assert protocol.is_ok(envelope), envelope
    payload = envelope["result"]
    assert payload["flags"] == 1
    assert payload["ea"] == 0x15E10
    assert payload["size"] == 0x16604 - 0x15E10
    assert payload["nbbs"] == 2
    assert payload["noreturn"] is False


def test_function_info_reports_a_zero_flag_set() -> None:
    import enum

    class FunctionFlags(enum.Flag):
        FRAME = 1

    db = SimpleNamespace(functions=FlagFunctions(FunctionFlags(0)))
    envelope = dispatch.invoke(db, "function_info", {"ea": 0x15E10})
    assert protocol.is_ok(envelope), envelope
    assert envelope["result"]["flags"] == 0


def test_item_flags_no_longer_collapses_to_zero() -> None:
    """``item_flags`` used to swallow the TypeError and report 0 for every ea."""
    import enum

    from idare2.remote import helpers

    class ByteFlags(enum.Flag):
        CODE = 1
        WORD = 2

    db = SimpleNamespace(bytes=FlagBytes(ByteFlags.CODE | ByteFlags.WORD))
    assert helpers.item_flags(db, 0x1000) == 3
