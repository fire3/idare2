"""Database selection and lifecycle over IDA Nexus.

Nexus already does the hard part: it discovers IDA GUI databases and managed
idalib workers through a filesystem registry, and hands out authenticated
leases.  This module is only the policy layer -- which database the user meant,
how long the worker should outlive us, and whether to wait for analysis.

``ida_nexus`` is imported lazily so ``idare2 -h`` and ``idare2 -v`` work even on
a machine where the IDA stack is not configured.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from idare2.errors import (
    Idare2Error,
    NoDatabaseError,
    NotReadyError,
    QuitRequested,
    TransportError,
)

#: Keep a spawned worker alive this long after our last lease closes, so that a
#: sequence of CLI invocations reuses one loaded IDB (and IDA's in-memory undo
#: history survives between them).  Nexus caps this at one hour.
WORKER_LINGER = 3600.0

#: Deadline for opening or spawning a database when the user gives no ``-t``.
#: A cold idalib import plus autoanalysis of a large firmware image is minutes.
OPEN_TIMEOUT = 600.0


@dataclass
class Target:
    """How the user asked for a database."""

    path: str | None = None
    record_id: str | None = None
    spawn: bool = True
    backend: str = "any"
    #: Import hints, applied only when Nexus has to create the database.
    processor: str | None = None
    bits: int | None = None
    image_base: int | None = None
    auto_analysis: bool = True
    save_on_close: bool = False
    #: Whether the session may change the database.  Read-only sessions are
    #: never saved, so attaching cannot rewrite somebody's IDB.
    readonly: bool = True


@dataclass
class DatabaseRow:
    """One discovery row, shaped for both selection and display."""

    record_id: str
    status: str
    backend: str
    pid: int
    path: str
    idb_path: str | None
    error: str | None
    instance: Any = None

    @property
    def ready(self) -> bool:
        return self.status == "ready"


def list_databases() -> list[DatabaseRow]:
    """Every registered Nexus instance, ready ones first."""
    from ida_nexus import discover_databases, reachable_path

    rows: list[DatabaseRow] = []
    for discovered in discover_databases():
        entry = discovered.instance
        try:
            path = reachable_path(entry) or entry.idb_path or ""
        except Exception:
            path = entry.idb_path or ""
        rows.append(
            DatabaseRow(
                record_id=entry.record_id,
                status=discovered.state.value,
                backend=entry.backend,
                pid=entry.pid,
                path=path,
                idb_path=entry.idb_path,
                error=discovered.detail,
                instance=entry,
            )
        )
    rows.sort(key=lambda row: (not row.ready, row.path))
    return rows


def _matches_backend(row: DatabaseRow, backend: str) -> bool:
    return backend == "any" or row.backend == backend


def resolve(target: Target) -> Any:
    """Resolve a :class:`Target` to a live ``DatabaseInstance`` or a path.

    Returning a ``str`` means "Nexus should open this", which may spawn a
    worker.  Returning a ``DatabaseInstance`` means "attach to exactly this
    instance" -- no path re-resolution, no chance of spawning a lookalike.
    """
    if target.record_id:
        for row in list_databases():
            if row.record_id == target.record_id:
                if not row.ready:
                    raise NotReadyError(
                        f"instance {row.record_id} is {row.status}"
                        + (f" ({row.error})" if row.error else "")
                    )
                return row.instance
        raise NoDatabaseError(f"no registered Nexus instance {target.record_id!r}")

    if target.path:
        candidate = Path(target.path).expanduser()
        if not candidate.exists():
            raise NoDatabaseError(f"no such file: {target.path}")
        return str(candidate.resolve())

    rows = [row for row in list_databases() if _matches_backend(row, target.backend)]
    ready = [row for row in rows if row.ready]
    if not ready:
        if rows:
            detail = "; ".join(
                f"{row.record_id} is {row.status}" + (f" ({row.error})" if row.error else "")
                for row in rows
            )
            raise NotReadyError(f"no usable Nexus database: {detail}")
        raise NoDatabaseError(
            "no registered Nexus database; open one in IDA or pass a path to create one"
        )
    if len(ready) > 1:
        listing = ", ".join(f"{row.record_id} ({row.path})" for row in ready)
        raise NoDatabaseError(
            f"{len(ready)} registered databases; pick one with --attach or --idb: {listing}"
        )
    return ready[0].instance


def open_handle(selection: Any, target: Target, *, timeout: float, linger: float):
    """Open one handle.  The caller owns it and must close it."""
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, NexusConnectionError

    if isinstance(selection, str):
        hints = _import_hints_requested(target)
        return DatabaseHandle.open(
            selection,
            options=DatabaseOpenOptions(
                startup_timeout=timeout,
                keepalive=linger,
                spawn=target.spawn,
                # Import hints must be applied before analysis.  The worker
                # starts quiet, idare2 applies the raw-binary bitness/entry,
                # and connect() drains analysis afterwards.
                auto_analysis=target.auto_analysis and not hints,
                processor=_processor_hint(target.processor, target.bits),
                image_base=target.image_base,
            ),
        )
    try:
        return DatabaseHandle.attach(selection, keepalive=linger)
    except NexusConnectionError as exc:
        raise NotReadyError(
            f"instance {selection.record_id} refused a lease (it may have just exited): {exc}"
        ) from exc


def await_analysis(handle: Any, timeout: float, mode: str = "wait") -> None:
    """Bring the database to a state where queries return final answers.

    A headless worker is ours, so we may drain its analysis.  A GUI database is
    somebody's live session: forcing autoanalysis on would freeze their main
    thread, so we only *poll* and report that it is still busy.
    """
    if mode == "skip":
        return
    backend = getattr(handle.instance, "backend", "idalib")
    if backend != "gui":
        handle.wait_autoanalysis(timeout)
        return
    status = handle.poll_autoanalysis()
    if not status.get("complete"):
        raise NotReadyError(
            f"GUI instance {handle.instance.record_id} is still auto-analyzing; "
            "wait for it to finish or use -n to skip"
        )


@contextmanager
def shutdown_if_ours(handle: Any, *, save: bool) -> bool:
    """Shut down our managed worker, or leave it for other clients.

    Nexus saves the database when a **managed idalib worker** shuts down,
    regardless of ``db.save_on_close`` (verified in ``ida_nexus/cli/worker.py``:
    it calls ``Database.close(save=...)`` from ``server.save_on_shutdown``,
    which defaults to true).  So for a read-only session the only way to keep
    "opening a database must not rewrite it" true is to discard the changes at
    shutdown.

    ``take_snapshot()`` is Nexus's exclusivity check: it fails while any other
    lease is attached, which is exactly when we must *not* shut the worker down.
    """
    try:
        handle.take_snapshot()
    except Exception:
        return False
    try:
        handle.shutdown_database(save=save)
    except Exception:
        return False
    return True


def _open_with_retry(selection: Any, target: Target, *, timeout: float, linger: float) -> Any:
    """Open a handle, tolerating a worker that is mid-shutdown.

    With ``--linger 0`` the previous invocation closes the worker as it exits;
    a command started immediately afterwards can land in the window where the
    registry still lists it but the service is draining.  Nexus retries its own
    spawn race; the same courtesy is worth extending to ours.
    """
    import time

    from idare2.errors import NoDatabaseError, NotReadyError

    attempts = 3
    last: Exception | None = None
    for attempt in range(attempts):
        current = selection
        if attempt:
            current = resolve(target)
            time.sleep(0.25 * attempt)
        try:
            return open_handle(current, target, timeout=timeout, linger=linger)
        except (NotReadyError, NoDatabaseError) as exc:
            last = exc
        except Exception as exc:  # noqa: BLE001 - a draining worker says many things
            last = exc
    assert last is not None
    raise last


@contextmanager
def connect(target: Target, *, timeout: float, linger: float, wait: str = "wait") -> Iterator[Any]:
    """Own a handle's whole lifecycle: resolve, open, await analysis, close.

    With ``linger=0`` -- the batch/test policy -- the worker is shut down on the
    way out and the database is discarded unless the session was writable.
    With the default hour-long linger nothing is shut down, so nothing is
    written either; a read-only session therefore never rewrites the IDB.
    """
    handle = None
    try:
        selection = resolve(target)
        handle = _open_with_retry(selection, target, timeout=timeout, linger=linger)
        _apply_import_hints(handle, target)
        await_analysis(handle, timeout, wait)
        yield handle
    except (Idare2Error, QuitRequested):
        # Deliberate control flow raised by the `with` body.  An idare2 error
        # already carries its own exit code, and `q` raises QuitRequested to
        # unwind all the way to the CLI -- wrapping either here turned
        # `idare2 -qc 'q'` into `ERROR: QuitRequested: quit with 0` with exit
        # code 4 (EXIT_TRANSPORT) instead of a clean 0.
        raise
    except Exception as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        if handle is not None:
            if linger <= 0:
                shutdown_if_ours(handle, save=not target.readonly)
            handle.close()


def _import_hints_requested(target: Target) -> bool:
    return bool(
        not target.record_id
        and (target.processor or target.bits is not None or target.image_base is not None)
    )


def _processor_hint(processor: str | None, bits: int | None) -> str | None:
    """Choose the processor subtype that matches a requested bitness."""
    if not processor or bits is None or ":" in processor:
        return processor
    if processor.lower() == "arm":
        if bits == 32:
            return f"{processor}:ARMv7"
        if bits == 64:
            return f"{processor}:ARMv8"
    return processor


def _apply_import_hints(handle: Any, target: Target) -> None:
    if not _import_hints_requested(target):
        return
    from idare2.rpc import Remote

    Remote(handle, timeout=60).call(
        "apply_import_hints", bits=target.bits, entry=target.image_base
    )
