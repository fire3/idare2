"""Error taxonomy and exit codes.

Exit codes follow radare2 where it matters (0 = ok, 1 = the command failed) and
extend it where a script benefits from the distinction (usage error vs no
database vs transport failure).  ``if idare2 -qc ...; then`` keeps working.
"""

from __future__ import annotations

from typing import Any

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_NO_DB = 3
EXIT_TRANSPORT = 4

# Remote error codes, mirrored from idare2.remote.envelope.  Kept as plain
# strings so this module stays importable inside IDA.
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

#: Remote code -> local exception class, populated at the bottom of this module.
_BY_CODE: dict[str, type[Idare2Error]] = {}


class Idare2Error(Exception):
    """Base class for every error idare2 reports to the user."""

    code = INTERNAL
    exit_code = EXIT_FAIL

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        exit_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if exit_code is not None:
            self.exit_code = exit_code
        self.details = details or {}

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class UsageError(Idare2Error):
    code = BAD_ARGS
    exit_code = EXIT_USAGE


class NoDatabaseError(Idare2Error):
    code = "NO_SESSION"
    exit_code = EXIT_NO_DB


class NotReadyError(Idare2Error):
    code = NOT_READY
    exit_code = EXIT_NO_DB


class TransportError(Idare2Error):
    code = "TRANSPORT"
    exit_code = EXIT_TRANSPORT


class RemoteTimeout(Idare2Error):
    code = TIMEOUT
    exit_code = EXIT_TRANSPORT


class CommandError(Idare2Error):
    """A remote operation ran and failed (bad address, IDA error, ...)."""

    code = IDA_ERROR
    exit_code = EXIT_FAIL


class ReadOnlyError(Idare2Error):
    code = READONLY
    exit_code = EXIT_FAIL


class NotFoundError(Idare2Error):
    code = NOT_FOUND
    exit_code = EXIT_FAIL


class BadAddressError(Idare2Error):
    code = BAD_ADDRESS
    exit_code = EXIT_FAIL


class NoHexRaysError(Idare2Error):
    code = NO_HEXRAYS
    exit_code = EXIT_FAIL


class UnknownCommand(Idare2Error):
    """No handler matched the command token.

    radare2 exits 1 on an unknown command (verified against r2 6.2.5), and so
    do we -- including for commands r2 has but idare2 does not implement.
    """

    code = "UNKNOWN_CMD"
    exit_code = EXIT_FAIL


class NotSupported(UnknownCommand):
    """A known radare2 command that idare2 deliberately does not implement."""

    code = "NOT_SUPPORTED"


class QuitRequested(Exception):
    """Raised by ``q`` to unwind out of the command pipeline."""

    def __init__(self, code: int = 0) -> None:
        super().__init__(f"quit with {code}")
        self.code = int(code)


_BY_CODE.update(
    {
        BAD_ARGS: UsageError,
        BAD_ADDRESS: BadAddressError,
        NOT_FOUND: NotFoundError,
        NOT_FUNC: NotFoundError,
        NO_HEXRAYS: NoHexRaysError,
        READONLY: ReadOnlyError,
        IDA_ERROR: CommandError,
        NOT_READY: NotReadyError,
        TIMEOUT: RemoteTimeout,
        INTERNAL: CommandError,
        UNKNOWN_OP: UnknownCommand,
    }
)


def from_remote(code: str, message: str, details: dict[str, Any] | None = None) -> Idare2Error:
    """Build the local exception for a remote error envelope."""
    cls = _BY_CODE.get(code, CommandError)
    return cls(message, details=details)
