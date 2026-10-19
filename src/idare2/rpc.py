"""Client-side adapter that runs operations inside the IDA process.

Nexus executes Python in IDA's interpreter.  Both ends run on the same host, so
we publish this installation's package parent on the remote ``sys.path`` and
call a small IDA-side entry point.  That keeps the Nexus plugin generic and lets
GUI databases and managed idalib workers share one handler implementation.

The version check in the preamble exists because ``sys.modules`` pins the
first-imported ``idare2`` for the life of the IDA process: after an upgrade the
remote copy is stale, and a stale handler set fails in confusing ways.  We turn
that into one actionable error instead.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from idare2 import __version__, protocol
from idare2.errors import Idare2Error, TransportError, from_remote

#: The directory to publish on the remote sys.path -- ``src/`` in a checkout,
#: ``site-packages/`` in an installed environment.  Either way ``import idare2``
#: resolves to this same package.
_PACKAGE_PARENT = str(Path(__file__).resolve().parent.parent)

DEFAULT_TIMEOUT = 30.0


def _preamble(payload: dict[str, Any]) -> str:
    encoded = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return (
        "import base64, json, sys\n"
        f"_ire2_path = {_PACKAGE_PARENT!r}\n"
        "if _ire2_path not in sys.path:\n"
        "    sys.path.insert(0, _ire2_path)\n"
        "import idare2 as _ire2_pkg\n"
        "_ire2_seen = getattr(_ire2_pkg, '__version__', '?')\n"
        f"_ire2_want = {__version__!r}\n"
        "if _ire2_seen != _ire2_want:\n"
        "    raise RuntimeError(\n"
        "        'IDA holds stale idare2 modules (remote %s, CLI %s); restart IDA or '\n"
        "        'close the idalib worker (idare2 .idaclose) to reload'\n"
        "        % (_ire2_seen, _ire2_want)\n"
        "    )\n"
        f"_ire2_req = json.loads(base64.b64decode({encoded!r}).decode('utf-8'))\n"
    )


def build_code(operation: str, arguments: dict[str, Any]) -> str:
    """The remote Python for one operation."""
    return _preamble({"op": operation, "args": arguments}) + (
        "from idare2.remote.entry import execute as _ire2_execute\n"
        "_ire2_execute(db, **_ire2_req)\n"
    )


def _envelope(execution: Any) -> dict[str, Any]:
    if not isinstance(execution, dict):
        raise TransportError("Nexus returned no execution result")
    envelope = protocol.decode_bytes(execution.get("result"))
    if not isinstance(envelope, dict) or not isinstance(envelope.get("ok"), bool):
        raise TransportError("Nexus returned an invalid idare2 envelope")
    return envelope


class Remote:
    """Bound to one :class:`~ida_nexus.DatabaseHandle`."""

    def __init__(self, handle: Any, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.handle = handle
        self.timeout = timeout

    def call(self, operation: str, **arguments: Any) -> Any:
        """Run an operation and return its result."""
        result, _ = self.call_with_meta(operation, **arguments)
        return result

    def call_with_meta(
        self, operation: str, **arguments: Any
    ) -> tuple[Any, dict[str, Any] | None]:
        """Run an operation and return ``(result, meta)``."""
        envelope = self._invoke(operation, arguments)
        if not envelope.get("ok"):
            error = envelope.get("error") or {}
            raise from_remote(
                str(error.get("code", protocol.IDA_ERROR)),
                str(error.get("message", "remote operation failed")),
                error.get("data"),
            )
        return envelope.get("result"), envelope.get("meta")

    def _invoke(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        code = build_code(operation, arguments)
        try:
            execution = self.handle.execute_python(
                code,
                timeout=self.timeout,
                operation_label=f"idare2: {operation}",
            )
        except Idare2Error:
            raise
        except Exception as exc:
            raise _transport_error(exc) from exc
        return _envelope(execution)


def _transport_error(exc: Exception) -> Idare2Error:
    message = f"{type(exc).__name__}: {exc}"
    # ida_nexus.RemoteError carries the remote traceback and captured output of
    # a failed execute_python.  Without it a handler crash inside IDA is
    # undiagnosable from the CLI.
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        for key in ("traceback", "stdout", "stderr"):
            text = details.get(key)
            if text:
                message += f"\n--- remote {key} ---\n{str(text).rstrip()}"
    return TransportError(message)
