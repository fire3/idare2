"""IDA-side entry point, invoked through Nexus's ``execute_python`` RPC.

The CLI injects its package parent onto the remote ``sys.path`` and calls
:func:`execute`.  Handlers register themselves on first use and stay in
``sys.modules`` for the life of the IDA process.
"""

from __future__ import annotations

from typing import Any

_INITIALIZED = False


def _load() -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return
    from idare2.remote.ops import load_all

    load_all()
    _INITIALIZED = True


def execute(db: Any, op: str | None = None, args: dict[str, Any] | None = None) -> Any:
    """Run one operation and return its bytes-encoded RPC envelope."""
    _load()

    from idare2 import protocol
    from idare2.remote.dispatch import invoke

    if not op:
        return protocol.encode_bytes(
            protocol.build_error(protocol.BAD_ARGS, "request is missing an op name")
        )
    return protocol.encode_bytes(invoke(db, op, args or {}))
