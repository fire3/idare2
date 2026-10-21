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


def test_dispatcher_preserves_handler_error_codes(monkeypatch) -> None:
    from idare2.remote import helpers

    def failing(db):
        helpers.fail(protocol.NOT_FOUND, "missing thing", {"ea": 0x1234})

    monkeypatch.setitem(dispatch.HANDLERS, "test_failing_op", failing)
    envelope = dispatch.invoke(SimpleNamespace(), "test_failing_op", {})
    assert not protocol.is_ok(envelope)
    assert envelope["error"] == {
        "code": protocol.NOT_FOUND,
        "message": "missing thing",
        "data": {"ea": 0x1234},
    }


def test_duplicate_remote_operation_fails_loudly() -> None:
    with pytest.raises(ValueError, match="duplicate remote operation 'imports'"):
        dispatch.op("imports")(lambda db: None)


def test_apply_import_hints_uses_encoded_segment_addressing(monkeypatch) -> None:
    import sys

    calls = []
    ida_ida = SimpleNamespace(
        inf_set_app_bitness=lambda bits: calls.append(("bits", bits)),
        inf_set_start_ip=lambda ea: calls.append(("entry", ea)) or True,
    )
    ida_segment = SimpleNamespace(
        set_segment_addressing=lambda ea, mode: calls.append(("segment", ea, mode)) or True
    )
    ida_auto = SimpleNamespace(
        AU_CODE=1, auto_mark=lambda ea, kind: calls.append(("mark", ea, kind))
    )
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_segment", ida_segment)
    monkeypatch.setitem(sys.modules, "ida_auto", ida_auto)
    db = SimpleNamespace(
        format="Binary file",
        segments=SimpleNamespace(get_all=lambda: [SimpleNamespace(start_ea=0x1000)]),
    )

    envelope = dispatch.invoke(
        db, "apply_import_hints", {"bits": 32, "entry": 0x1000}
    )
    assert protocol.is_ok(envelope), envelope
    assert envelope["result"] == {"applied": True, "bits": 32, "start_ip": 0x1000}
    assert calls == [
        ("bits", 32),
        ("segment", 0x1000, 1),
        ("entry", 0x1000),
        ("mark", 0x1000, 1),
    ]


def test_assemble_returns_idautils_bytes(monkeypatch) -> None:
    import sys

    calls = []

    def assemble(ea: int, text: str):
        calls.append((ea, text))
        return True, b"\x90"

    monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(Assemble=assemble))
    envelope = dispatch.invoke(
        SimpleNamespace(), "assemble", {"ea": 0x1000, "text": "nop"}
    )

    assert protocol.is_ok(envelope), envelope
    assert envelope["result"] == {"ea": 0x1000, "size": 1, "data": b"\x90"}
    assert calls == [(0x1000, "nop")]


def test_assemble_splits_instructions_and_concatenates_the_result(monkeypatch) -> None:
    import sys

    calls = []

    def assemble(ea: int, lines: list[str]):
        calls.append((ea, lines))
        return True, [b"\x90", b"\x90"]

    monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(Assemble=assemble))
    envelope = dispatch.invoke(
        SimpleNamespace(), "assemble", {"ea": 0x1000, "text": "nop; nop"}
    )

    assert protocol.is_ok(envelope), envelope
    assert envelope["result"] == {"ea": 0x1000, "size": 2, "data": b"\x90\x90"}
    assert calls == [(0x1000, ["nop", "nop"])]


def test_assemble_reports_processor_without_assembler(monkeypatch) -> None:
    import sys

    monkeypatch.setitem(
        sys.modules,
        "idautils",
        SimpleNamespace(Assemble=lambda ea, text: (False, "Assembler failed: nop")),
    )
    envelope = dispatch.invoke(
        SimpleNamespace(), "assemble", {"ea": 0x1000, "text": "nop"}
    )

    assert not protocol.is_ok(envelope)
    assert envelope["error"]["code"] == protocol.IDA_ERROR
    assert "processor module may not provide an assembler" in envelope["error"]["message"]
    assert "Assembler failed: nop" in envelope["error"]["message"]


def test_assemble_rejects_blank_input(monkeypatch) -> None:
    import sys

    monkeypatch.setitem(
        sys.modules,
        "idautils",
        SimpleNamespace(Assemble=lambda ea, text: pytest.fail("must not run")),
    )
    envelope = dispatch.invoke(
        SimpleNamespace(), "assemble", {"ea": 0x1000, "text": " ; \n"}
    )

    assert not protocol.is_ok(envelope)
    assert envelope["error"]["code"] == protocol.BAD_ARGS


def test_function_info_skips_hexrays_when_unavailable(monkeypatch) -> None:
    import sys

    from idare2.remote.ops.analysis import _local_count

    monkeypatch.setitem(
        sys.modules, "ida_hexrays", SimpleNamespace(init_hexrays_plugin=lambda: False)
    )
    db = SimpleNamespace(
        functions=SimpleNamespace(
            get_local_variables=lambda func: pytest.fail("decompiler must not run")
        )
    )
    assert _local_count(db, object()) == 0


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


# ---------------------------------------------------------------------------
# iz: one odd string must not take the listing down
# ---------------------------------------------------------------------------


class OddString:
    """A literal whose type code ida-domain's ``StringType`` IntEnum rejects.

    Reproduces ``ValueError: 16 is not a valid StringType``, which Hex-Rays can
    leave behind after ``pdc`` and which used to abort the whole ``iz`` walk.
    """

    address = 0xC8C48
    length = 20
    internal_type = 16
    contents = b"still readable"

    @property
    def type(self):
        raise ValueError("16 is not a valid StringType")

    @property
    def encoding(self):
        raise ValueError("16 is not a valid StringType")


class PlainString:
    address = 0xC8C48
    length = 6
    internal_type = 0
    contents = b"abc"
    type = "0"
    encoding = "ascii"


RODATA = [(0xC8000, 0xF0000, ".rodata", 0xC0C48)]


def test_string_type_falls_back_on_an_unknown_enum_value() -> None:
    from idare2.remote.ops.info import _string_type

    assert _string_type(OddString()) == "0x10"
    assert _string_type(PlainString()) == "0"


def test_string_encoding_falls_back_on_an_unknown_enum_value() -> None:
    from idare2.remote.ops.info import _string_encoding

    assert _string_encoding(OddString()) == ""
    assert _string_encoding(PlainString()) == "ascii"


def test_string_row_survives_a_string_ida_domain_cannot_classify() -> None:
    """Regression: this ValueError aborted `iz` for the whole database."""
    from idare2.remote.ops.info import _string_row

    row = _string_row(OddString(), RODATA)
    assert row is not None
    assert row["text"] == "still readable"
    assert row["ea"] == 0xC8C48
    assert row["section"] == ".rodata"
    assert row["paddr"] == 0xC0C48 + (0xC8C48 - 0xC8000)
    assert row["type"] == "0x10"


def test_string_row_keeps_the_normal_path_intact() -> None:
    from idare2.remote.ops.info import _string_row

    row = _string_row(PlainString(), RODATA)
    assert row == {
        "ea": 0xC8C48,
        "paddr": 0xC0C48 + (0xC8C48 - 0xC8000),
        "section": ".rodata",
        "length": 3,
        "size": 6,
        "type": "0",
        "encoding": "ascii",
        "text": "abc",
    }


def test_string_row_skips_an_unrenderable_literal() -> None:
    from idare2.remote.ops.info import _string_row

    class NoContents(PlainString):
        contents = None

    assert _string_row(NoContents(), RODATA) is None
