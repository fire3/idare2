"""Operation registry and in-process invocation (runs inside IDA).

Nexus owns authentication, framing, request limits and serialized main-thread
execution.  The dispatcher only validates arguments, creates an undo point for
mutations, and returns the compact result envelope.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from idare2 import protocol

#: op name -> function
HANDLERS: dict[str, Callable[..., Any]] = {}


def op(name: str, *, writes: bool = False):
    """Register one operation.

    ``writes=True`` makes the dispatcher create an IDA undo point before the
    handler runs, so a GUI analyst can undo anything idare2 changed.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        function._ire2_writes = writes  # type: ignore[attr-defined]
        HANDLERS[name] = function
        return function

    return decorate


def _create_undo_point(name: str) -> None:
    try:
        import ida_undo

        ida_undo.create_undo_point("idare2", name)
    except Exception:
        # Undo points are best-effort: some IDA builds refuse them outside a
        # GUI, and a missing undo point must never fail the operation itself.
        pass


def _translate(exc: BaseException) -> dict[str, Any]:
    """Map an ida-domain / IDAPython exception onto an envelope error."""
    name = type(exc).__name__
    message = f"{name}: {exc}"
    if name == "InvalidEAError":
        return protocol.build_error(protocol.BAD_ADDRESS, message)
    if name == "InvalidParameterError":
        return protocol.build_error(protocol.BAD_ARGS, message)
    if name in ("DatabaseNotLoadedError", "DatabaseError"):
        return protocol.build_error(protocol.NOT_READY, message)
    if name == "DecompilerError":
        return protocol.build_error(protocol.NO_HEXRAYS, message)
    if name in ("NoValueError", "UnsupportedValueError", "SerializationError"):
        return protocol.build_error(protocol.IDA_ERROR, message)
    if isinstance(exc, ValueError):
        return protocol.build_error(protocol.BAD_ARGS, message)
    return protocol.build_error(protocol.INTERNAL, message)


def invoke(db: Any, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Invoke one registered operation and return an unencoded envelope.

    Every handler takes the live ``ida_domain.Database`` as its first parameter;
    it is injected here rather than reached through a module global so that
    handlers stay ordinary testable functions.
    """
    function = HANDLERS.get(name)
    if function is None:
        return protocol.build_error(protocol.UNKNOWN_OP, f"unknown operation: {name!r}")

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        return protocol.build_error(protocol.BAD_ARGS, "arguments must be a map")

    signature = inspect.signature(function)
    parameters = list(signature.parameters)
    if not parameters or parameters[0] != "db":
        return protocol.build_error(
            protocol.INTERNAL, f"{name}: handler must declare `db` as its first parameter"
        )

    try:
        signature.bind(db, **arguments)
    except TypeError as exc:
        return protocol.build_error(protocol.BAD_ARGS, f"{name}: {exc}")

    if getattr(function, "_ire2_writes", False):
        _create_undo_point(name)

    try:
        output = function(db, **arguments)
    except Exception as exc:  # noqa: BLE001 - translated below
        return _translate(exc)

    if isinstance(output, tuple) and len(output) == 2:
        result, meta = output
    else:
        result, meta = output, None
    return protocol.build_ok(result, meta)
