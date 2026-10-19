"""The client-side RPC adapter and the wire envelope."""

from __future__ import annotations

import base64
import json

import pytest

from idare2 import __version__, protocol, rpc
from idare2.errors import (
    CommandError,
    NotFoundError,
    ReadOnlyError,
    TransportError,
    UsageError,
    from_remote,
)


def test_bytes_round_trip() -> None:
    payload = {"lines": [{"bytes": b"\x10\x48\x2d\xe9"}], "n": 1}
    encoded = protocol.encode_bytes(payload)
    assert encoded["lines"][0]["bytes"] == {
        protocol.BYTES_TAG: base64.b64encode(b"\x10\x48\x2d\xe9").decode()
    }
    assert protocol.decode_bytes(encoded) == payload


def test_encode_is_copy_on_write_for_byte_free_values() -> None:
    payload = {"a": 1, "b": [1, 2, 3]}
    assert protocol.encode_bytes(payload) is payload


def test_decode_ignores_lookalike_dicts() -> None:
    payload = {protocol.BYTES_TAG: "AAAA", "extra": 1}
    assert protocol.decode_bytes(payload) == payload


def test_envelope_shapes() -> None:
    ok = protocol.build_ok({"x": 1}, {"total": 3})
    assert protocol.is_ok(ok)
    assert ok["meta"] == {"total": 3}
    err = protocol.build_error(protocol.BAD_ADDRESS, "nope")
    assert not protocol.is_ok(err)
    assert err["error"]["code"] == protocol.BAD_ADDRESS


def test_remote_codes_map_to_local_exceptions() -> None:
    assert isinstance(from_remote(protocol.READONLY, "x"), ReadOnlyError)
    assert isinstance(from_remote(protocol.BAD_ARGS, "x"), UsageError)
    assert isinstance(from_remote(protocol.NOT_FOUND, "x"), NotFoundError)
    # Unknown codes fall back to a generic command error rather than blowing up.
    assert isinstance(from_remote("SOMETHING_NEW", "x"), CommandError)


def test_build_code_publishes_the_package_path_and_checks_the_version() -> None:
    code = rpc.build_code("disasm", {"ea": 0x1000})
    assert rpc._PACKAGE_PARENT in code
    assert "__version__" in code
    assert __version__ in code
    assert "_ire2_execute(db, **_ire2_req)" in code
    # It must be valid Python.
    compile(code, "<remote>", "exec")


def test_build_code_embeds_the_operation_and_arguments() -> None:
    code = rpc.build_code("read_bytes", {"ea": 16, "count": 4})
    encoded = code.split("base64.b64decode(")[1].split(")")[0].strip("'")
    assert json.loads(base64.b64decode(encoded)) == {
        "op": "read_bytes",
        "args": {"ea": 16, "count": 4},
    }


class FakeHandle:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def execute_python(self, code, *, timeout=None, operation_label=None):
        self.calls.append((code, timeout, operation_label))
        return self.reply


def test_remote_returns_the_result() -> None:
    handle = FakeHandle({"result": protocol.build_ok({"ea": 1}), "stdout": "", "stderr": ""})
    remote = rpc.Remote(handle, timeout=5)
    assert remote.call("disasm", ea=1) == {"ea": 1}
    assert handle.calls[0][1] == 5
    assert handle.calls[0][2] == "idare2: disasm"


def test_remote_raises_the_mapped_error() -> None:
    handle = FakeHandle(
        {
            "result": protocol.build_error(protocol.NOT_FOUND, "no function"),
            "stdout": "",
            "stderr": "",
        }
    )
    remote = rpc.Remote(handle)
    with pytest.raises(NotFoundError, match="no function"):
        remote.call("function_info", ea=0)


def test_remote_rejects_a_bad_envelope() -> None:
    handle = FakeHandle({"result": {"nonsense": True}, "stdout": "", "stderr": ""})
    remote = rpc.Remote(handle)
    with pytest.raises(TransportError):
        remote.call("x")
