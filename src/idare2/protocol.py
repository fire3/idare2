"""The result envelope shared by the CLI and the IDA-side handlers.

IDA Nexus owns transport framing and authentication, but its wire accepts only
JSON-compatible values.  ``encode_bytes``/``decode_bytes`` bridge that gap by
tagging binary payloads as ``{"$idare2.b64": "..."}`` dicts.

This module must stay importable inside IDA: no ``ida_nexus``, no ``ida_*``.
"""

from __future__ import annotations

import base64
from typing import Any

BYTES_TAG = "$idare2.b64"

# -- error codes -----------------------------------------------------------

BAD_ARGS = "BAD_ARGS"
BAD_ADDRESS = "BAD_ADDRESS"
NOT_FOUND = "NOT_FOUND"
NOT_FUNC = "NOT_FUNC"
NO_HEXRAYS = "NO_HEXRAYS"
READONLY = "READONLY"
IDA_ERROR = "IDA_ERROR"
NOT_READY = "NOT_READY"
TIMEOUT = "TIMEOUT"
INTERNAL = "INTERNAL"
UNKNOWN_OP = "UNKNOWN_OP"


def build_ok(result: Any = None, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"ok": True, "result": result}
    if meta:
        message["meta"] = meta
    return message


def build_error(
    code: str, message: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"ok": False, "error": error}


def is_ok(reply: Any) -> bool:
    return isinstance(reply, dict) and reply.get("ok") is True


def encode_bytes(value: Any) -> Any:
    """JSON-safe copy of ``value`` with every bytes payload tagged.

    Copy-on-write: a subtree with no bytes is returned unchanged, so the common
    byte-free envelope allocates nothing.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {BYTES_TAG: base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        changed = None
        for key, item in value.items():
            encoded = encode_bytes(item)
            if encoded is not item:
                if changed is None:
                    changed = dict(value)
                changed[key] = encoded
        return value if changed is None else changed
    if isinstance(value, (list, tuple)):
        changed = None
        for index, item in enumerate(value):
            encoded = encode_bytes(item)
            if encoded is not item:
                if changed is None:
                    changed = list(value)
                changed[index] = encoded
        return value if changed is None else changed
    return value


def decode_bytes(value: Any) -> Any:
    """Invert :func:`encode_bytes`.

    Only an exact ``{"$idare2.b64": str}`` dict decodes; the key is reserved and
    handlers must not emit it themselves.  Copy-on-write, like ``encode_bytes``.
    """
    if isinstance(value, dict):
        if len(value) == 1 and isinstance(value.get(BYTES_TAG), str):
            return base64.b64decode(value[BYTES_TAG])
        changed = None
        for key, item in value.items():
            decoded = decode_bytes(item)
            if decoded is not item:
                if changed is None:
                    changed = dict(value)
                changed[key] = decoded
        return value if changed is None else changed
    if isinstance(value, list):
        changed = None
        for index, item in enumerate(value):
            decoded = decode_bytes(item)
            if decoded is not item:
                if changed is None:
                    changed = list(value)
                changed[index] = decoded
        return value if changed is None else changed
    return value
